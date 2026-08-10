//! The shared dataplane regions and the buffer-ownership protocol common to the
//! protection domains.
//!
//! Faces the byzantine neighbour protection domain: this crate *is*
//! the inter-PD protocol, so it defines what one domain must withstand from
//! another.
//!
//! It carries no seL4/Microkit dependency on purpose: region layout and
//! ownership protocol are pure logic, so both are exercised in full on the
//! host, and the protection-domain binaries stay thin adapters that map a
//! region, hand its address here, and drive the protocol from notifications.
//!
//! # One pipeline is three regions, because a region is the unit of grant
//!
//! A pipeline joins three domains into `rx driver -> forwarder -> tx driver`
//! over one buffer pool. One pool is what makes forwarding zero-copy end to
//! end: the receiving NIC DMAs a frame into a pool buffer, the transmitting NIC
//! DMAs it back out of that very buffer, and only the descriptor moves.
//!
//! Microkit grants memory a region at a time, so what a domain can reach is
//! decided by where the region boundaries fall and never by which fields its
//! code touches. The pipeline is therefore cut three ways — [`Pool`],
//! [`ForwardRings`], [`ReturnRing`] — which lets the forwarder hold the pool
//! whose L2/L3 headers it rewrites and the two rings it moves descriptors
//! between, while holding neither pipeline's return ring. The cut costs one
//! mapping page over a single region holding all four, and that page is what
//! buys the separation: the ring on which a forged return would put a live DMA
//! target back onto an owner's free stack is not addressable from the forwarder
//! at all. A [`Pool`] goes to the forwarder and the transmitting driver, and to
//! the receiving one as a physical address with no mapping at all.
//!
//! # Handles are taken once, at attach
//!
//! A handle holds its side's ring position, so a second one restarts at slot
//! zero and redelivers descriptors the first already handed over. Every role
//! type here therefore borrows its region for its lifetime and takes each
//! handle in its `attach` constructor — but nothing stops a domain calling two
//! `attach`es over one ring end, and this crate's own tests take extra handles
//! deliberately. Closing it needs the once-only claim `queue`'s header
//! describes, threaded through every role's `attach` across this crate and
//! `nic-driver-core`.
//!
//! # A stage owns neither the chain nor the table it decides through
//!
//! [`RouteStage`] takes both the [`Pipeline`] and the [`Configuration`] as
//! parameters of [`RouteStage::poll`] and keeps neither. For the table, holding
//! one made a second configuration unrepresentable — the borrow lasted as long
//! as the stage — and passing it per call also settles *when* a commit takes
//! effect without a lock: a Microkit protection domain runs one `notified` to
//! completion at a time, so the caller cannot run while a poll holds what it
//! was lent. For the chain, a stage of it may hold state spanning both
//! directions, which a per-direction owner would split in half.
//!
//! # What a hostile peer cannot cause, and what enforces it
//!
//! * **No out-of-bounds slot access and no redelivery of a descriptor already
//!   handed over** — `queue`, whose positions live in memory the peer cannot
//!   map and whose only shared read is masked into range.
//! * **No out-of-bounds dereference of a forged descriptor** —
//!   [`descriptor_in_bounds`] on the consuming side before the span is touched,
//!   backstopped unconditionally by `packet_buffer`'s own span checks.
//! * **No double-owned buffer through a forged or duplicated return** —
//!   [`PoolOwner::reclaim`], in two layers: `packet_buffer`'s ledger for the
//!   index itself, and this crate's *lent* set for what the ledger cannot see.
//! * **No unbounded work** — [`DRAIN_LIMIT`], derived from this crate's own
//!   constants and never from a peer-influenced estimate.
//! * **No panic** — every rejection above is a counted drop ([`PoolCounters`],
//!   [`RouteCounters`]). Peer-supplied values are input and are rejected
//!   safely; only a violated invariant of this domain's own private state fails
//!   visibly.
//!
//! # The accepted, tracked residue
//!
//! * **Buffer loss.** A peer stalling its side of a ring can leave
//!   [`RouteStage::poll`] unable to place a descriptor it already dequeued.
//!   A dequeue cannot be undone and this domain does not produce onto that
//!   ring, so the buffer is lost to its owner's ledger for good. The pool
//!   shrinks; nothing is double-owned and nothing crashes.
//! * **A verdict rests on a snapshot, not on the frame.** [`RouteStage`] routes
//!   a copy taken into its own memory, because a decision made on pool bytes a
//!   peer may rewrite under it is no decision at all. The peer keeps the bytes:
//!   it may rewrite them after the snapshot and before the transmitting NIC
//!   reads them, so what leaves the port can differ from what was decided on,
//!   in every field the rewrite does not overwrite. Nothing here closes that —
//!   an IOMMU or a per-buffer cross-domain ownership epoch would; neither exists yet.
//! * **Frame loss and reordering**, by forging a cursor.
//! * **Writing pool bytes at any time.** The two drivers share a pool, and no
//!   Rust type stops one of them scribbling a buffer it does not own. That is
//!   contained by the pool never handing out a safe reference to those bytes,
//!   and it is why an IOMMU — still an open item — is what finally confines a NIC's DMA
//!   rather than anything here.

#![cfg_attr(not(test), no_std)]

use core::mem::{align_of, offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

use net_headers::{
    ETHERNET_HEADER_LEN, Frame, IPV4_HEADER_LEN, MacAddress, ParseCounters, TtlExpired,
};
use packet_buffer::{BufferPool, CopyOutError, FreeList, ReturnError, WriteOutsideBuffer};
use pipeline::{DropCounters, DropReason, Inspection, Pipeline};
use queue::SpscRing;
use routing::PortId;
use wire::{TapDecision, TapDirection};

pub use packet_buffer::{BUFFER_SIZE, OwnedBuffer};
pub use queue::{RingConsumer, RingProducer};
pub use wire::{Descriptor, Verdict};

/// Re-exported rather than restated: one number, one declaration. What this
/// crate adds is that a [`Pool`] is the whole of its region, so a region base's
/// alignment is every buffer's DMA alignment.
pub use wire::MAPPING_ALIGN;

pub const POOL_BUFFERS: usize = 64;

/// Bytes a published frame leaves free in front of itself, for the transmitting
/// driver to write the device's own header into. The pipeline's constant rather
/// than a driver's: a domain that *originates* a frame must leave the room and
/// holds no virtio type to ask. `nic_driver_core` const-asserts it equal.
pub const DEVICE_HEADER_LEN: u32 = 12;

/// Power of two; usable capacity is one less. Sized above [`POOL_BUFFERS`] so no
/// ring fills before the pool is exhausted, making hand-offs along a correctly
/// accounted chain infallible.
pub const RING_SLOTS: usize = 128;

/// The most descriptors any single drain of a peer-fed ring will process.
///
/// A peer that keeps advancing its published cursor keeps a dequeue returning
/// descriptors forever, and a domain stuck in that loop stops servicing its own
/// device. One full ring's worth bounds it — no legitimate backlog exceeds
/// `RING_SLOTS - 1` descriptors or [`POOL_BUFFERS`] buffers — and it comes from
/// this crate's constants, not a ring's peer-influenced `len()`.
pub const DRAIN_LIMIT: usize = RING_SLOTS;

pub type Ring = SpscRing<RING_SLOTS>;

/// Both NICs' DMA target, and the whole of one memory region: pool buffer `i`
/// sits at the region's physical base plus `i * BUFFER_SIZE`, no offset to add.
pub type Pool = BufferPool<POOL_BUFFERS>;

/// Bytes the system description reserves for each region, derived rather than
/// chosen: the fewest [`MAPPING_ALIGN`] pages that hold the region's type. As a
/// literal it drifted to 1.93x its type, mapping bytes no field names into three
/// domains. `xtask::sysdesc` holds every `size=` to the constant here, proved by
/// `a_short_region_is_reported_against_the_constant_it_must_equal`.
pub const POOL_REGION_SIZE: usize = size_of::<Pool>().next_multiple_of(MAPPING_ALIGN);

/// As [`POOL_REGION_SIZE`], for the forwarder's region.
pub const FORWARD_REGION_SIZE: usize = size_of::<ForwardRings>().next_multiple_of(MAPPING_ALIGN);

/// As [`POOL_REGION_SIZE`], for the return region.
pub const RETURN_REGION_SIZE: usize = size_of::<ReturnRing>().next_multiple_of(MAPPING_ALIGN);

/// As [`POOL_REGION_SIZE`], for the connection table — and by some distance the
/// largest region in the system, at sixty-eight mebibytes and a page.
///
/// The rounding costs a whole page for 256 bytes, which is the ordinary price of
/// a grant being whole pages. What decides the number is
/// [`lfw_flow::FLOW_CAPACITY`], and that is a knob nothing else here turns:
/// halving it halves this region and halves how many connections the appliance
/// can carry at once, which is a decision about the product rather than about
/// the layout.
pub const FLOW_TABLE_REGION_SIZE: usize = FLOW_TABLE_BYTES.next_multiple_of(MAPPING_ALIGN);

/// A connection table small enough for a host test to hold, used by the tests in
/// this crate alone: the appliance's own is far too large to put on a stack.
#[cfg(test)]
pub(crate) type ApplianceTestFlows = lfw_flow::FlowTable<16>;

// The re-decision sizes a wakeup's share of itself against the frames a wakeup
// may drain, and it restates that bound rather than importing it: `pipeline` may
// not depend on this crate. A number moved on one side alone would let a commit's
// pass spend more than a full drain costs — or less, and take longer than it need.
const _: () = assert!(pipeline::WAKEUP_FRAME_BUDGET == DRAIN_LIMIT);

/// Whether a peer's descriptor names a span within one pool buffer; a failing one is rejected.
#[must_use]
pub fn descriptor_in_bounds(descriptor: &Descriptor) -> bool {
    (descriptor.buffer as usize) < POOL_BUFFERS
        && (descriptor.offset as usize)
            .checked_add(descriptor.len as usize)
            .is_some_and(|end| end <= BUFFER_SIZE)
}

/// Saturating rather than wrapping: the rate is attacker-controlled, and a
/// wrapped counter turns a sustained flood back into a small number.
pub(crate) fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The forwarder's region: the two rings a descriptor crosses between drivers.
///
/// The ring the buffers come back on is a separate region the forwarder never
/// maps; the [`Pool`] those descriptors index is a third, and *is* mapped,
/// because the routed frame's headers are rewritten in place.
///
/// A zeroed region is the valid empty state, so no domain constructs one; each
/// attaches to the mapped frames with [`attach_region!`].
#[repr(C)]
pub struct ForwardRings {
    pub rx: Ring,
    pub tx: Ring,
}

/// The return region: transmitted buffers, tx driver back to the pool owner.
///
/// Its own region rather than a third field beside [`ForwardRings`], which is
/// what denies the forwarder the ability to forge a return — the one move that
/// would put a live buffer back on an owner's free stack.
#[repr(C)]
pub struct ReturnRing {
    pub free: Ring,
}

// A peer domain reads these bytes at these offsets, so pin every field offset
// and not merely the component sizes: a reorder keeps the sizes identical while
// silently making one domain's `rx` another's `tx`. Offsets and total size
// together also prove each layout carries no padding.
const _: () = {
    assert!(size_of::<Ring>() == 8 + RING_SLOTS * size_of::<Descriptor>());
    assert!(size_of::<Ring>() == 2056);
    assert!(size_of::<Pool>() == POOL_BUFFERS * BUFFER_SIZE);
    assert!(size_of::<Pool>() == 0x20000);
    assert!(offset_of!(ForwardRings, rx) == 0);
    assert!(offset_of!(ForwardRings, tx) == size_of::<Ring>());
    assert!(size_of::<ForwardRings>() == 2 * size_of::<Ring>());
    assert!(size_of::<ForwardRings>() == 4112);
    assert!(offset_of!(ReturnRing, free) == 0);
    assert!(size_of::<ReturnRing>() == size_of::<Ring>());
    // Exactly four, not merely "within a page": the rings' `AtomicU32`s are the
    // only alignment in either region, and an upper-bound check can never fail,
    // so it could never catch the reorder or field-type change it exists to
    // catch. A `Pool` is byte-aligned as a type, which is why its buffers' DMA
    // alignment comes from its region base instead.
    assert!(align_of::<ForwardRings>() == 4);
    assert!(align_of::<ReturnRing>() == 4);
};

// The three grants, pinned as tightly as the fields: each region exceeds its
// type by less than one page, so no unaddressed slack can return unnoticed.
const _: () = {
    assert!(POOL_REGION_SIZE == 0x20000);
    assert!(FORWARD_REGION_SIZE == 0x2000);
    assert!(RETURN_REGION_SIZE == 0x1000);
    assert!(POOL_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(FORWARD_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(RETURN_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    // The pool region is its type exactly, with no rounding remainder at all.
    assert!(POOL_REGION_SIZE == size_of::<Pool>());
    assert!(FORWARD_REGION_SIZE - size_of::<ForwardRings>() < MAPPING_ALIGN);
    assert!(RETURN_REGION_SIZE - size_of::<ReturnRing>() < MAPPING_ALIGN);
    // What the split costs, stated here rather than left to a report nobody
    // diffed: one mapping page. It was nothing while a descriptor was 12 bytes;
    // a 16-byte one pushes `ForwardRings` past a page. The page is what buys
    // the grant separation, and a cut that cost *more* fails here.
    assert!(
        POOL_REGION_SIZE + FORWARD_REGION_SIZE + RETURN_REGION_SIZE
            == (size_of::<Pool>() + 3 * size_of::<Ring>()).next_multiple_of(MAPPING_ALIGN)
                + MAPPING_ALIGN
    );
};

// The DMA-alignment obligation `packet_buffer` names this crate as the owner
// of: buffer `i` sits at `pool_paddr + i * BUFFER_SIZE`, and a pool is the whole
// of its region, so a region base at the mapping granularity makes every buffer
// `BUFFER_SIZE`-aligned with no offset in the chain to get wrong.
const _: () = assert!(MAPPING_ALIGN.is_multiple_of(BUFFER_SIZE));

impl ForwardRings {
    /// For host use; a mapped region is already zeroed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx: Ring::new(),
            tx: Ring::new(),
        }
    }
}

impl Default for ForwardRings {
    fn default() -> Self {
        Self::new()
    }
}

impl ReturnRing {
    /// For host use; see [`ForwardRings::new`].
    #[must_use]
    pub const fn new() -> Self {
        Self { free: Ring::new() }
    }
}

impl Default for ReturnRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Physical address of pool buffer `index`, where `pool_paddr` is the [`Pool`]
/// region's own physical base — the address a Microkit `setvar region_paddr`
/// patches into the driver that hands it to its NIC.
///
/// # Panics
/// If `index >= POOL_BUFFERS`, in every build profile — a `debug_assert!` would
/// be absent from every image that boots, and the release build ships. The result would
/// otherwise address *outside* the region, and a driver posts it to a NIC as a
/// DMA target: with no IOMMU, an arbitrary physical write.
///
/// A first-party invariant break rather than untrusted input, because `index`
/// is bounded before every call by one of two enforcers:
///
/// * an `OwnedBuffer<POOL_BUFFERS>` index, which the token's own type bounds
///   below `POOL_BUFFERS`;
/// * a peer-supplied [`Descriptor`]`::buffer` past an unconditional
///   [`descriptor_in_bounds`] rejection — proven by
///   `descriptor_in_bounds_matches_a_widened_reference`.
///
/// A hostile peer or device therefore reaches a rejection, never this
/// assertion; reaching it means an enforcer broke, which is surfaced visibly
/// rather than counted as traffic.
#[must_use]
pub const fn buffer_paddr(pool_paddr: u64, index: u32) -> u64 {
    assert!(
        (index as usize) < POOL_BUFFERS,
        "buffer_paddr would address outside the pool"
    );
    pool_paddr + index as u64 * BUFFER_SIZE as u64
}

/// Attach to a mapped region and borrow it for the domain's lifetime.
/// Protection domains call this through [`attach_region!`], which states the
/// aliasing invariant once for every call site.
///
/// # Panics
/// If `ptr` is not aligned for `T`, in every build profile: a bound absent from
/// the shipped image is not a bound, and it costs one compare.
///
/// # Safety
/// `ptr` must be aligned to `align_of::<T>()`, point to a live mapping of at
/// least `size_of::<T>()` bytes that is either zeroed or already a valid value,
/// and outlive `'a`. The mapping may be shared read-write with peer protection
/// domains and used as a device DMA target, so `T` must expose no safe path to
/// its own bytes — a peer's writes are then a protocol concern rather than a
/// soundness one — and the caller must never create a `&mut T` to it.
#[must_use]
pub unsafe fn attach_region<'a, T: Sync>(ptr: *mut T) -> &'a T {
    assert!(ptr.is_aligned(), "region is misaligned");
    // SAFETY: the caller guarantees an aligned, live, correctly sized,
    // correctly initialised mapping outliving `'a`, and the assertion above
    // re-checks the alignment unconditionally. Aliasing with the peer domains
    // and with NIC DMA is sound because the caller also guarantees `T` exposes
    // no safe path to its bytes, so no safe code can hold a reference to a byte
    // a peer may concurrently write.
    unsafe { &*ptr }
}

/// Attach this protection domain to the region a Microkit `setvar_vaddr` symbol
/// names, yielding a `&'static` borrow of `$region`.
///
/// Every domain attaches through this macro so the aliasing invariant that
/// makes the `&'static` share sound is written once instead of re-derived at
/// every call site, where one copy drifted and understated the aliasing set.
///
/// A [`ForwardRings`] region is mapped read-write into three protection domains
/// at once and a [`ReturnRing`] into two; a [`Pool`] is mapped into the
/// transmitting driver alone and is additionally a DMA target of both NICs; the
/// two configuration regions are mapped into two domains, each writable in one
/// of them. Sharing any of them as a `&` is sound in the face of that because
/// none exposes a safe path to those bytes; whether the peers behave is the
/// protocol question the crate header answers, not a soundness one.
///
/// The calling crate must depend on `sel4-microkit`; this crate deliberately
/// does not, so the protocol stays host-testable.
#[macro_export]
macro_rules! attach_region {
    ($vaddr_symbol:ident : $region:ty) => {{
        // SAFETY: `attach_region`'s preconditions come from four different
        // components, and only the first is the Microkit tool's.
        //
        // * Address, page alignment, lifetime — the Microkit tool, which
        //   patches `$vaddr_symbol` from the matching `<map ... setvar_vaddr>`
        //   in `systems/qemu-x86_64/librefirewall.system`, maps at page
        //   granularity (far beyond any region type's 4 bytes), and makes the
        //   mapping static, so it outlives the protection domain.
        // * Zero-initialisation — the seL4 kernel, which zeroes a frame
        //   retyped from a general-purpose untyped but not one retyped from a
        //   device untyped. Which it is follows from the region's `phys_addr`
        //   lying inside RAM, and that from QEMU's `-m 1G`
        //   (`tools/xtask/src/qemu.rs`). This is the one precondition here that
        //   no build step checks; a region outside RAM surfaces as unbacked
        //   reads at run time rather than as a build or boot error.
        // * Minimum size — the `size=` attribute on that region, which
        //   `xtask::sysdesc`'s `REGIONS` table names a rule for and
        //   `check_region_size` holds *equal* to the constant the domains map
        //   it as: `POOL_REGION_SIZE`, `FORWARD_REGION_SIZE`,
        //   `RETURN_REGION_SIZE`, `CONFIG_REGION_SIZE`, `CONFIG_ACK_REGION_SIZE`,
        //   `STATS_REGION_SIZE`.
        //   The log regions alone are sized by agreement, that table naming no
        //   rule for one. Both checks run in the gate and before image assembly.
        // * No safe path to the bytes — the region types, whose fields are
        //   atomics (`Ring`, `wire`'s configuration regions) or an `UnsafeCell`
        //   reachable only through an `unsafe` accessor (`Pool`).
        //
        // No `&mut` is created here or by `attach_region`.
        unsafe {
            $crate::attach_region::<$region>(
                ::sel4_microkit::memory_region_symbol!($vaddr_symbol: *mut $region).as_ptr(),
            )
        }
    }};
}

/// Whether the connection table's exclusive borrow has been taken.
///
/// What makes "once per protection domain" a *check* rather than a claim in a
/// safety comment. A second `&mut` to those bytes would be undefined behaviour,
/// and the only thing standing between the system and one is that
/// [`attach_flow_table`] is expanded once — which nothing about the macro
/// enforces. So it is enforced here, and a second call faults instead.
static FLOW_TABLE_TAKEN: AtomicBool = AtomicBool::new(false);

/// Attach to the connection table's region and borrow it **mutably** for the
/// domain's lifetime.
///
/// This is the one region in the system a domain owns outright, and the one
/// borrowed `&mut`. Everything else here is shared with a peer or with a device
/// and is therefore a `&` over a type with no safe path to its own bytes; an
/// [`ApplianceFlowTable`] is an ordinary Rust value with public methods taking
/// `&mut self`, so it may be reached that way only where no other domain and no
/// device can reach it at all.
///
/// Concrete rather than generic over the region type, because the argument for
/// the exclusive borrow is about *this* region — one mapper, no physical
/// address, zero-filled — and a generic helper would offer that argument to a
/// region nobody had made it for.
///
/// # Panics
/// If called twice, in every build profile: the second call would produce a
/// second `&mut` to the same bytes, and a bound absent from the shipped image is
/// not a bound. Unreachable from first-party code — the forwarder's `init` is the
/// one caller and `init` runs once — which is why reaching it is a fault rather
/// than a counted refusal.
///
/// # Safety
/// `ptr` must be aligned to `align_of::<ApplianceFlowTable>()`, point to a live
/// mapping of at least `size_of::<ApplianceFlowTable>()` bytes that outlives
/// `'a`, and that mapping must be **zero-filled** and reachable by **no other
/// protection domain and no device**. Zeroing is a stronger requirement than
/// [`attach_region`]'s: a table holds `FlowState`, a `#[repr(u8)]` enum, so
/// *forming* the reference over bytes that are not a valid table is undefined
/// before any method runs.
#[must_use]
pub unsafe fn attach_flow_table_region<'a>(
    ptr: *mut ApplianceFlowTable,
) -> &'a mut ApplianceFlowTable {
    assert!(ptr.is_aligned(), "region is misaligned");
    assert!(
        !FLOW_TABLE_TAKEN.swap(true, Ordering::SeqCst),
        "the connection table's exclusive borrow was taken twice"
    );
    // SAFETY: the caller guarantees an aligned, live, correctly sized, zeroed
    // mapping outliving `'a` that no other domain and no device can reach; the
    // two assertions above re-check the alignment and establish, unconditionally
    // and in every profile, that this is the first and only borrow. Together
    // those make this the only reference to those bytes that exists.
    unsafe { &mut *ptr }
}

/// Attach this protection domain to the connection table the Microkit
/// `setvar_vaddr` symbol names, yielding a `&'static mut ApplianceFlowTable`.
///
/// Separate from [`attach_region!`] because the borrow is exclusive and the
/// argument for it is a different one: not "no safe path to the bytes" but "no
/// other holder of the bytes".
#[macro_export]
macro_rules! attach_flow_table {
    ($vaddr_symbol:ident) => {{
        // SAFETY: `attach_flow_table_region`'s preconditions, each named against
        // the component that guarantees it.
        //
        // * Address, page alignment, lifetime — the Microkit tool, which
        //   patches `$vaddr_symbol` from the matching
        //   `<map mr="flow_table" ... setvar_vaddr="flow_table_vaddr">` in
        //   systems/qemu-x86_64/librefirewall.system and makes the mapping
        //   static, so it outlives the protection domain. An `ApplianceFlowTable`
        //   is 64-byte aligned and a page is 4096, so page granularity satisfies
        //   it.
        // * Minimum size — the `size=` attribute on that region, which
        //   `xtask::sysdesc`'s `REGIONS` table holds EQUAL to
        //   `pd_runtime::FLOW_TABLE_REGION_SIZE`, itself `lfw_flow`'s
        //   `FLOW_TABLE_BYTES` rounded up to the mapping granularity. The check
        //   runs in the gate and before image assembly.
        // * Zero-initialisation — the seL4 kernel, which zeroes a frame retyped
        //   from a general-purpose untyped. This region names no `phys_addr`, so
        //   Microkit allocates it from general-purpose untyped memory and that
        //   retyping is the one seL4 zeroes; the region does not rest on the
        //   RAM-membership argument the DMA regions do. Zeroing is what makes
        //   forming the reference defined at all, `FlowState::Vacant` being
        //   discriminant zero.
        // * No other holder — the same `REGIONS` rule, whose `grants` name
        //   exactly one mapper, `read_write("forwarder")`, and whose `withheld`
        //   claim states what every other domain's absence buys. No driver maps
        //   it, so no device can DMA into it either: a device reaches only what
        //   a driver hands it the physical address of, and this region has no
        //   `region_paddr` for anyone to hand over.
        //
        // The remaining clause — that this is the only borrow ever taken — is
        // not delegated anywhere: `attach_flow_table_region` establishes it
        // itself, and a second call faults.
        unsafe {
            $crate::attach_flow_table_region(
                ::sel4_microkit::memory_region_symbol!(
                    $vaddr_symbol: *mut $crate::ApplianceFlowTable
                )
                .as_ptr(),
            )
        }
    }};
}

pub mod clock;
pub mod configuration;
pub mod download;
pub mod endpoint;
pub mod handover;
pub mod owner;
pub mod reconnect;
pub mod relay;
pub mod stats;
pub mod tap;

pub use clock::{PdClock, TICK_PERIOD, TICKS_PER_SECOND, read_timestamp_counter};
pub use configuration::{CONFIG_TARGET, Configurations, MAX_ANSWER_LEN, Submissions};
pub use download::{CAPTURE_TARGET, DownloadCounters, Downloads, LOG_TARGET, Stream, sink_for};
pub use endpoint::{
    CalibrationRefused, ConfigRefused, DIAL_LIMIT, EndpointRegions, EndpointStage,
    EndpointStageCounters, MAX_REPLY_LEN, ONBOARD_LIMIT, OUTPUT_LIMIT, TIMER_LIMIT,
    calibration_from,
};
// The two types a domain needs to name the channel it dials: the address it
// dials and the outcome it reports, reached through this facade rather than
// through a second dependency on the crates that own them.
pub use handover::{
    Committed, CommittedReader, ConfigCounters, ConfigPublisher, ConfigurationSwitch, Offer,
    StaleOffer, endpoint_from, interfaces_from, router_from, rules_from,
};
/// Re-exported rather than restated: a protection domain reaches its whole
/// dataplane vocabulary through this crate, and the tables a poll decides under
/// are part of it.
pub use lfw_flow::{ApplianceFlowTable, FLOW_TABLE_BYTES};
pub use lfw_ip_endpoint::IsnSecret;
pub use lfw_ip_endpoint::onboard::{
    Ended as OnboardEnded, INBOUND_CAPACITY as ONBOARD_INBOUND_CAPACITY, ONBOARDING_PORT,
    OUTBOUND_CAPACITY as ONBOARD_OUTBOUND_CAPACITY, StreamCounters as OnboardCounters,
};
pub use lfw_ip_endpoint::outbound::{
    DialFacts, Ended, OpenError, RECEIVE_CAPACITY as DIAL_RECEIVE_CAPACITY, Resolutions,
    SEND_CAPACITY as DIAL_SEND_CAPACITY,
};
pub use lfw_ip_endpoint::route::{Hop, RouteRefusal, Via};
pub use net_headers::Ipv4Address;
pub use owner::{OwnershipChange, OwnershipWatch};
pub use pipeline::{Configuration, Ownership, PolicySweep, Tracking};
pub use reconnect::{INITIAL_BACKOFF, MAX_BACKOFF, Reconnect, Wait};
pub use relay::{
    ANSWER_TIMEOUT as RELAY_ANSWER_TIMEOUT, Answered, ChannelStream,
    DEMANDS_PER_WAKEUP as RELAY_DEMANDS_PER_WAKEUP, Half, Relay, RelayFailure, RelayPass,
    RelayReport, RelaySession, Relayed, SHIPPED_RING_BYTES, TerminatedSession, Terminating,
    TerminatingPass, Terminator, Upstream,
};
pub use stats::{
    BlockCounters, ForwarderCounters, StatsRegions, StoreIdentity, StoreSigning,
    SubmissionCounters, config_sample, flow_sample, forwarder_sample, log_sample,
    management_sample, pipeline_sample, policy_sample, policy_sweep_sample, recorder_sample,
    store_sample,
};
pub use tap::{
    Observation, Revocation, Tap, TapCounters, tap_classification, tap_decision, tap_drop_reason,
    tap_flow, tap_flow_state, tap_outcome, tap_revoked_flow,
};
pub use wire::{
    ApplianceOwnership, CLOCK_CALIBRATION_REGION_SIZE, CONFIG_REPLY_REGION_SIZE,
    CONFIG_REQUEST_REGION_SIZE, CalibrationImage, ClockCalibration, ConfigAck, ConfigHandover,
    ConfigImage, ConfigReply, ConfigRequest, MAX_DOCUMENT_BYTES, MAX_INTERFACES, MAX_NEIGHBOURS,
    OWNERSHIP_REGION_SIZE,
};

/// Counts of the pool owner's untrusted-input rejections, which are otherwise
/// invisible: a byzantine peer's activity looks exactly like an idle link.
///
/// Monotonic for the domain's life and saturating; there is no reset, because
/// the appliance's metrics endpoint differences successive scrapes and a reset
/// would forge a negative rate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PoolCounters {
    /// Returns naming an index this domain never lent: forged, out of range, a
    /// duplicate of a return already accepted, or — the reason the lent set
    /// exists — a real buffer still posted to this domain's own NIC.
    pub reclaim_not_lent: u64,
    /// Returns of a lent index that `packet_buffer`'s ledger nevertheless
    /// refused. Unreachable while the lent set and the ledger agree, a lent
    /// index being outstanding by construction; counted rather than asserted so
    /// a divergence surfaces as a lost buffer with a number attached.
    pub reclaim_refused: u64,
}

/// The pool-owning side of a pipeline: it owns every buffer, lends them out as
/// bare indices, and takes them back off the [`ReturnRing`].
///
/// Ownership is a move-only [`OwnedBuffer`] for as long as the buffer stays
/// inside this domain, so a local double-release is not expressible. The token
/// dissolves to a bare index at [`lend`](Self::lend) alone, that being where
/// the buffer leaves Rust's ownership tracking for the ring protocol.
///
/// It borrows the return ring and **not** the [`Pool`]: an owner accounts for
/// buffers by index and never reads or writes their bytes, which is what lets
/// the receiving driver take its pool's physical address without mapping it.
pub struct PoolOwner<'ring> {
    ledger: FreeList<POOL_BUFFERS>,
    /// Which indices were dissolved onto a ring and may therefore legitimately
    /// come back. The ledger cannot answer this: a buffer posted to this
    /// domain's own NIC is "outstanding" exactly as a lent one is, and a peer
    /// naming it would otherwise have a live DMA target handed back to the free
    /// stack and re-issued to a second owner.
    lent: [bool; POOL_BUFFERS],
    free: RingConsumer<'ring, RING_SLOTS>,
    counters: PoolCounters,
}

impl<'ring> PoolOwner<'ring> {
    /// Take ownership of this domain's pool and of `returns`' consumer handle —
    /// once per protection domain per pipeline; see the crate header.
    #[must_use]
    pub fn attach(returns: &'ring ReturnRing) -> Self {
        Self {
            ledger: FreeList::full(),
            lent: [false; POOL_BUFFERS],
            free: returns.free.consumer(),
            counters: PoolCounters::default(),
        }
    }

    /// Take exclusive ownership of a free buffer, e.g. to hand to a device for
    /// it to fill. `None` when the pool is momentarily exhausted.
    pub fn alloc(&mut self) -> Option<OwnedBuffer<POOL_BUFFERS>> {
        self.ledger.pop()
    }

    /// Return a buffer this domain still holds, without publishing it — the
    /// path taken when a hand-off could not proceed.
    ///
    /// # Panics
    /// If the ledger refuses the token: a violation of *this domain's own*
    /// invariant rather than untrusted input, so it fails visibly. Holding the
    /// token means the index is outstanding, and the only route by which a peer
    /// could have had it freed underneath us is [`reclaim`](Self::reclaim),
    /// which accepts an index only if it is in the lent set — which a held
    /// token's index never is. Proven by this crate's
    /// `a_return_of_a_buffer_still_held_by_this_domain_is_refused`.
    pub fn release(&mut self, buffer: OwnedBuffer<POOL_BUFFERS>) {
        self.ledger
            .push(buffer)
            .expect("a held token names an outstanding, unlent buffer");
    }

    /// Publish `len` bytes at `offset` of an already-filled buffer on `ring`
    /// under `verdict`, handing it to the next domain without copying.
    ///
    /// The token is consumed and only a bare index crosses onto the shared
    /// ring, a move-only token being unable to cross a protection-domain
    /// boundary. The index is recorded as lent, which is what later lets
    /// [`reclaim`](Self::reclaim) tell a legitimate return from a peer naming a
    /// buffer it was never given.
    ///
    /// # Errors
    /// Returns the token unchanged when the ring is momentarily full, so the
    /// caller still owns the buffer and can [`release`](Self::release) it. The
    /// buffer is not marked lent in that case: nothing was handed over.
    pub fn lend(
        &mut self,
        ring: &mut RingProducer<'_, RING_SLOTS>,
        buffer: OwnedBuffer<POOL_BUFFERS>,
        offset: u32,
        len: u32,
        verdict: Verdict,
    ) -> Result<(), OwnedBuffer<POOL_BUFFERS>> {
        let index = buffer.index();
        if ring
            .try_enqueue(Descriptor::new(index, offset, len, verdict))
            .is_err()
        {
            return Err(buffer);
        }
        self.lent[index as usize] = true;
        Ok(())
    }

    /// Take back the buffers the transmitting domain has returned, until the
    /// `free` ring is observed empty or [`DRAIN_LIMIT`] descriptors have been
    /// processed. Returns how many buffers were reclaimed.
    ///
    /// Every index here is peer-supplied, so a return is accepted only if the
    /// index is in this domain's lent set *and* `packet_buffer`'s ledger
    /// accepts it. A rejected return changes nothing and is counted in
    /// [`counters`](Self::counters), so the buffer it named keeps whatever
    /// state it really had and its rightful holder can still return it.
    ///
    /// The count is what a driver acts on; *which* indices were accepted is
    /// [`lent`](Self::lent) differenced across the call, an accepted return being
    /// exactly a lent flag this cleared and nothing here setting one.
    pub fn reclaim(&mut self) -> usize {
        let Self {
            ledger,
            lent,
            free,
            counters,
        } = self;
        let mut reclaimed = 0;
        for descriptor in free.drain(DRAIN_LIMIT) {
            let index = descriptor.buffer;
            // `get` rather than an index: `index` is a peer value, so an
            // out-of-range one must be a rejection and never a panic.
            if lent.get(index as usize) != Some(&true) {
                bump(&mut counters.reclaim_not_lent);
                continue;
            }
            match ledger.reclaim(index) {
                Ok(()) => {
                    lent[index as usize] = false;
                    reclaimed += 1;
                }
                Err(ReturnError::OutOfRange(_))
                | Err(ReturnError::NotOutstanding(_))
                | Err(ReturnError::ListFull(_)) => bump(&mut counters.reclaim_refused),
            }
        }
        reclaimed
    }

    /// How many buffers the owner currently holds free.
    #[must_use]
    pub fn owned(&self) -> usize {
        self.ledger.len()
    }

    /// Which indices this domain currently counts as lent to a peer, one flag
    /// per pool index.
    ///
    /// The record [`reclaim`](Self::reclaim) decides against, exposed because its
    /// count cannot say *which* returns it accepted: differencing this across a
    /// `reclaim` names exactly the indices that came back. A caller tracking
    /// ownership of its own cannot reconstruct that from a number, and it is also
    /// what tells a return the peer routed out of band from a forged one.
    #[must_use]
    pub fn lent(&self) -> [bool; POOL_BUFFERS] {
        self.lent
    }

    #[must_use]
    pub fn counters(&self) -> PoolCounters {
        self.counters
    }
}

/// The bytes a forwarding rewrite can touch, and so the whole of what
/// [`RouteStage`] puts back into the pool: the Ethernet header and the IPv4
/// header, never a payload byte.
///
/// The IPv4 header sits at [`ETHERNET_HEADER_LEN`] with nothing in between,
/// because a frame that reaches a rewrite is never 802.1Q-tagged: `Router`
/// answers a tagged frame with `DropReason::VlanTagged` before it resolves
/// anything, proved by `routing`'s
/// `a_tagged_frame_is_dropped_for_want_of_a_sub_interface`. A tag would move
/// the L3 header four bytes along and this window would then write the wrong
/// bytes back over the right ones.
const REWRITTEN_HEADER_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;

// What makes the fixed-range write-back slice of `scratch` unable to leave it:
// a build error rather than a bounds check on the per-frame path.
const _: () = assert!(REWRITTEN_HEADER_LEN <= BUFFER_SIZE);

/// Monotonic and saturating for the reasons given on [`PoolCounters`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RouteCounters {
    /// The generation the most recent poll decided under. The counts below span
    /// the domain's life and no commit resets them, so this is what tells two
    /// scrapes apart: a pair naming one generation differences to a rate under
    /// one configuration.
    pub generation: u32,
    /// Frames rewritten for their next hop and handed to the transmitting
    /// driver.
    pub forwarded: u64,
    /// Descriptors the destination ring would not take. Each loses its buffer
    /// to the pool for good — see the crate header — so a rising count is a
    /// shrinking pool.
    pub egress_full: u64,
    /// Descriptors naming a span outside the pool. Such a descriptor names no
    /// buffer the transmitting driver could return, so handing it on would be
    /// inventing a return rather than granting one; it is dropped instead.
    pub malformed_descriptor: u64,
    /// Spans the pool refused to snapshot, leaving nothing to route on.
    pub snapshot_failed: u64,
    /// Frames that are not the IPv4-over-Ethernet packet they would have to be to
    /// be routed, one counter per [`net_headers::ParseFailure`]: four classes,
    /// because each is a different thing for an operator to do about it, and four
    /// rather than one per error variant because the values that make a rejection
    /// diagnosable belong in a record rather than in a label.
    pub unparsable: ParseCounters,
    /// Frames the pipeline would forward out of a port this stage is not wired
    /// to. A stage is a fixed cross-connect between one ingress and one egress
    /// port, so such a decision cannot be carried out here at all.
    pub misrouted: u64,
    /// Rewritten headers the pool refused to take back. The buffer then still
    /// holds the frame as it arrived, so it is discarded rather than
    /// transmitted with its original MACs and TTL — which would loop it.
    pub writeback_failed: u64,
    /// Why the pipeline refused a frame, one counter per reason.
    pub drops: DropCounters,
}

/// One direction of the routed dataplane: it snapshots each frame a pipeline's
/// `rx` ring names, decides on it, rewrites the headers of the ones it
/// forwards, and hands every descriptor on under the verdict the transmitting
/// driver acts on.
///
/// A discarded frame's descriptor travels onward exactly as a forwarded one's
/// does. This domain maps no `free` ring — that is what denies it the ability
/// to forge a return — so the transmitting driver is the only domain that can
/// give the buffer back, and the verdict is how it is told to.
///
/// # What an attached [`Tap`] records, and what it does not
///
/// One observation per frame the *pipeline* decided on, taken from the snapshot
/// before the forwarding rewrite, so a recording holds the frame as it arrived.
/// Three classes of frame are therefore absent from a recording and present in
/// the counters, which is the honest split rather than an omission:
///
/// * a frame no decision was reached about — a descriptor outside the pool, a
///   snapshot the pool refused, or bytes that are not the IPv4-over-Ethernet
///   packet a router can read — has no verdict to record;
/// * a frame routed out of a port this stage is not wired to, which
///   `wire::TapDropReason` has no encoding for: it mirrors
///   `pipeline::DropReason` exactly, and recording one under a neighbouring
///   reason would put a false claim in an artifact that is evidence;
/// * a frame recorded as forwarded that a later refusal still lost — the pool
///   declining the rewritten header, the destination ring declining the
///   descriptor, or `rewrite_for_forwarding` refusing a TTL the pipeline had
///   already accepted. Each has its own exposed counter series.
pub struct RouteStage<'ring> {
    ingress: PortId,
    egress: PortId,
    from: RingConsumer<'ring, RING_SLOTS>,
    to: RingProducer<'ring, RING_SLOTS>,
    pool: &'ring Pool,
    /// Private storage the frame is snapshotted into. A field rather than a
    /// `poll` local because the protection domain's stack is 16 KiB and this is
    /// 2 KiB per stage.
    scratch: [u8; BUFFER_SIZE],
    counters: RouteCounters,
}

impl<'ring> RouteStage<'ring> {
    /// Take `rings`' `rx` consumer and `tx` producer handles — once per
    /// protection domain per pipeline; see the crate header — and borrow the
    /// pool those descriptors index.
    #[must_use]
    pub fn attach(
        rings: &'ring ForwardRings,
        pool: &'ring Pool,
        ingress: PortId,
        egress: PortId,
    ) -> Self {
        Self {
            ingress,
            egress,
            from: rings.rx.consumer(),
            to: rings.tx.producer(),
            pool,
            scratch: [0; BUFFER_SIZE],
            counters: RouteCounters::default(),
        }
    }

    /// Put every descriptor the source ring names through `pipeline` under
    /// `configuration`, until the source ring is observed empty, the
    /// destination refuses one, or [`DRAIN_LIMIT`] have been handled. Returns
    /// how many reached the destination ring under either verdict — the number
    /// of buffers on their way back to their owner, and so the quantity a
    /// caller can act on; how many were forwarded is
    /// [`RouteCounters::forwarded`].
    ///
    /// The rings are sized above the pool, so along a correctly accounted chain
    /// the destination can always take what the source held. A refusal means
    /// accounting has already broken — a byzantine peer over-filling the source
    /// while the destination stalls — and the response is to count the drop and
    /// stop draining rather than fault, the descriptor being peer input.
    /// Stopping on the first refusal is deliberate: every further dequeue into
    /// a full destination would lose another buffer.
    ///
    /// The descriptors the refusal leaves behind stay on the source ring, owned
    /// by whoever lent them, so the stop costs the one already dequeued and
    /// leaks nothing. There is no self-wakeup — this call cannot schedule
    /// another — so the bound on when they are looked at again is the next
    /// notification the domain receives. Two things make that a real bound: a
    /// driver polls in a busy loop rather than waiting to be asked, so a
    /// momentarily full destination drains within one of its passes; and every
    /// frame either driver receives afterwards wakes this domain, which
    /// re-drains the backlog ahead of it. Only a total traffic stop is unbounded,
    /// and then the backlog is stationary rather than growing.
    pub fn poll<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize, const FLOWS: usize>(
        &mut self,
        pipeline: &mut Pipeline,
        configuration: Configuration<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
        tracking: &mut Tracking<'_, FLOWS>,
        ownership: Ownership,
        mut tap: Option<&mut Tap<'_>>,
    ) -> usize {
        let Self {
            ingress,
            egress,
            from,
            to,
            pool,
            scratch,
            counters,
        } = self;
        counters.generation = configuration.generation();
        let deciding = Deciding {
            configuration,
            ownership,
        };
        let mut handed_on = 0;
        for descriptor in from.drain(DRAIN_LIMIT) {
            // Unconditionally, and before the buffer is touched: the descriptor
            // is peer input, and this is the span the two pool accessors below
            // are argued from.
            if !descriptor_in_bounds(&descriptor) {
                bump(&mut counters.malformed_descriptor);
                continue;
            }
            let (routed, frame_len) = match snapshot(pool, &descriptor, scratch) {
                Ok(frame_bytes) => {
                    let len = frame_bytes.len();
                    (
                        decide(
                            pipeline,
                            &deciding,
                            tracking,
                            *ingress,
                            *egress,
                            frame_bytes,
                            counters,
                        ),
                        len,
                    )
                }
                Err(_) => {
                    bump(&mut counters.snapshot_failed);
                    (Routed::Discarded, 0)
                }
            };
            // Before the rewrite below, which is what makes the recorded bytes
            // the frame as it arrived rather than as it leaves.
            if let Some(tap) = tap.as_deref_mut()
                && let Some(decision) = routed.observed()
            {
                tap.observe(Observation {
                    timestamp: read_timestamp_counter().0,
                    interface_id: ingress.0,
                    decision,
                    // The snapshot's own length, so the slice is the frame; the
                    // fallback records nothing rather than branching on a span
                    // `snapshot` cannot produce.
                    frame: scratch.get(..frame_len).unwrap_or_default(),
                });
            }
            let verdict = match routed {
                Routed::Forward {
                    source,
                    destination,
                    ..
                } => forward(
                    pool,
                    &descriptor,
                    scratch,
                    frame_len,
                    source,
                    destination,
                    counters,
                ),
                Routed::Dropped(_) | Routed::Discarded => Verdict::Discard,
            };
            if to
                .try_enqueue(Descriptor {
                    verdict: verdict.to_bits(),
                    ..descriptor
                })
                .is_err()
            {
                bump(&mut counters.egress_full);
                break;
            }
            handed_on += 1;
            if verdict == Verdict::Transmit {
                bump(&mut counters.forwarded);
            }
        }
        handed_on
    }

    #[must_use]
    pub fn counters(&self) -> RouteCounters {
        self.counters
    }

    /// The same, borrowed: what a caller assembling a shard out of both stages
    /// needs, and copying a struct of this many counters would be one copy per
    /// wakeup for nothing.
    #[must_use]
    pub const fn counters_ref(&self) -> &RouteCounters {
        &self.counters
    }
}

/// Snapshot the frame `descriptor` names into `scratch`, yielding the exactly
/// `len`-byte prefix that holds it.
///
/// The copy is what makes a decision defensible at all: bytes left in the pool
/// are free to change under the decision that inspected them
/// (`packet_buffer`'s crate header), so what is parsed and rewritten is this
/// domain's own memory, and only the finished header goes back.
///
/// # Errors
/// [`CopyOutError`], carrying the span that was refused: `scratch` shorter than
/// the frame, or a span that leaves its buffer.
fn snapshot<'scratch>(
    pool: &Pool,
    descriptor: &Descriptor,
    scratch: &'scratch mut [u8],
) -> Result<&'scratch mut [u8], CopyOutError> {
    let len = descriptor.len as usize;
    let capacity = scratch.len();
    let Some(frame_bytes) = scratch.get_mut(..len) else {
        return Err(CopyOutError::DestinationTooSmall { len, capacity });
    };
    // SAFETY: `copy_out`'s one clause is that the caller currently owns the
    // index, and this domain does not: it holds a descriptor in transit, not a
    // buffer. That clause has no enforcer anywhere in the system and is not
    // claimed here; `packet_buffer`'s own header states what violating it
    // yields — "a snapshot of bytes another domain was writing, which the
    // caller already treats as untrusted, and never a dangling or aliased
    // reference" — and the crate header above records it as accepted residue.
    // What makes the call sound is guaranteed: the mapping is the
    // `<map mr="pool0"/"pool1" perms="rw" cached="true">` grant to the
    // forwarder in systems/qemu-x86_64/librefirewall.system, taken through
    // `attach_region!`; the span is bounded by `descriptor_in_bounds` in
    // `RouteStage::poll` and again, unconditionally, by the pool's own span
    // check, which answers in the return value rather than faulting; and
    // `frame_bytes` is the caller's own storage, which cannot alias a pool it
    // holds no reference into.
    unsafe {
        pool.copy_out(
            descriptor.buffer as usize,
            descriptor.offset as usize,
            descriptor.len,
            frame_bytes,
        )
    }?;
    Ok(frame_bytes)
}

/// What the stage resolved about one snapshotted frame, before a byte of it is
/// rewritten.
///
/// The decision is separated from the rewrite so an attached [`Tap`] can record
/// the frame as it arrived. That costs a second [`Frame::parse`] on the
/// forwarding path — the first borrow must end before the bytes can be read —
/// and buys the property that makes a recording usable as evidence: what is on
/// the medium is what the wire carried.
enum Routed {
    Forward {
        source: MacAddress,
        destination: MacAddress,
        decision: TapDecision,
    },
    Dropped(TapDecision),
    /// Discarded for something `routing` does not name; see [`RouteStage`] on
    /// why no tap records it.
    Discarded,
}

impl Routed {
    /// What the tap records about this resolution, or `None` where the ABI has no
    /// honest encoding for it.
    ///
    /// The decision is composed in [`decide`] rather than here, because it is
    /// built out of the facts the chain attached to an [`Inspection`] and that
    /// value cannot outlive the borrow of the frame it inspected.
    const fn observed(&self) -> Option<TapDecision> {
        match self {
            Self::Forward { decision, .. } | Self::Dropped(decision) => Some(*decision),
            Self::Discarded => None,
        }
    }
}

/// What one wakeup decides under: the two facts other domains publish and this
/// one is held to.
///
/// One value because they arrive together and are read together, and two fields
/// rather than one because they come from different writers and mean different
/// things — the tables the configuration domain committed, and whether the
/// domain holding the identity says this appliance has an owner. Folding
/// ownership into [`Configuration`] would make it something the domain that
/// parses an attacker's document composes, which is exactly what it must not be.
#[derive(Clone, Copy)]
struct Deciding<'table, const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize> {
    configuration: Configuration<'table, MAX_INTERFACES, MAX_NEIGHBOURS>,
    ownership: Ownership,
}

/// Parse one snapshotted frame and put it through the pipeline, untouched.
fn decide<const MAX_INTERFACES: usize, const MAX_NEIGHBOURS: usize, const FLOWS: usize>(
    pipeline: &mut Pipeline,
    deciding: &Deciding<'_, MAX_INTERFACES, MAX_NEIGHBOURS>,
    tracking: &mut Tracking<'_, FLOWS>,
    ingress: PortId,
    egress: PortId,
    frame_bytes: &mut [u8],
    counters: &mut RouteCounters,
) -> Routed {
    let frame = match Frame::parse(frame_bytes) {
        Ok(frame) => frame,
        Err(error) => {
            counters.unparsable.record(error);
            return Routed::Discarded;
        }
    };
    let mut inspection = Inspection::new(ingress, frame);
    let verdict = pipeline.evaluate(
        &mut inspection,
        &deciding.configuration,
        tracking,
        deciding.ownership,
    );
    // Composed while the inspection still exists, which is the whole reason the
    // decision travels out on [`Routed`]: the facts the chain attached — the
    // flow, the rule, the tracker's refusal — are gone the moment the borrow of
    // the frame ends, and the tap is offered the frame after that.
    //
    // Inbound on every record: a forwarded frame is observed once, on the port it
    // arrived on, so there is never a second observation to relate one to.
    let decision = tap_decision(
        &inspection,
        verdict,
        TapDirection::Inbound,
        deciding.configuration.generation(),
    );
    match verdict {
        pipeline::Verdict::Drop(reason) => {
            counters.drops.record(reason);
            Routed::Dropped(decision)
        }
        pipeline::Verdict::Forward {
            egress: decided, ..
        } if decided != egress => {
            bump(&mut counters.misrouted);
            Routed::Discarded
        }
        pipeline::Verdict::Forward {
            source,
            destination,
            ..
        } => Routed::Forward {
            source,
            destination,
            decision,
        },
    }
}

/// Rewrite the snapshot for its next hop and put the changed headers back into
/// the pool, answering the verdict the transmitting driver acts on.
fn forward(
    pool: &Pool,
    descriptor: &Descriptor,
    scratch: &mut [u8; BUFFER_SIZE],
    frame_len: usize,
    source: MacAddress,
    destination: MacAddress,
    counters: &mut RouteCounters,
) -> Verdict {
    // The snapshot's own length, which `decide` already parsed successfully at;
    // an empty slice fails the same parse and discards rather than branching on
    // a span `snapshot` cannot produce.
    let frame_bytes: &mut [u8] = scratch.get_mut(..frame_len).unwrap_or_default();
    let mut frame = match Frame::parse(frame_bytes) {
        Ok(frame) => frame,
        Err(error) => {
            counters.unparsable.record(error);
            return Verdict::Discard;
        }
    };
    match frame.rewrite_for_forwarding(source, destination) {
        Ok(()) => write_back(pool, descriptor, scratch, counters),
        // The routing stage refuses a TTL that cannot survive a hop before it
        // resolves a route, so this is one rejection reached through the
        // second of two enforcers. Recording it under the reason the first
        // would have used keeps one refused packet to one drop.
        Err(TtlExpired { .. }) => {
            counters.drops.record(DropReason::TtlExpired);
            Verdict::Discard
        }
    }
}

/// Copy `bytes` into pool buffer `index` at `offset`, leaving the rest untouched.
///
/// # Errors
/// [`WriteOutsideBuffer`] when the span leaves the buffer, bounded here rather
/// than by faulting.
fn place(pool: &Pool, index: u32, offset: u32, bytes: &[u8]) -> Result<(), WriteOutsideBuffer> {
    // SAFETY: `write_at`'s two clauses, and the mapping under them.
    //
    // * The mapping is the `<map mr="pool0"/"pool1"/"mgmt_tx_pool" perms="rw"
    //   cached="true">` grant in `systems/qemu-x86_64/librefirewall.system`,
    //   taken through `attach_region!`.
    // * `bytes` is the caller's own storage, which cannot alias a pool the
    //   caller holds no reference into.
    // * The span is `write_at`'s own business: it bounds `offset + len`
    //   unconditionally and answers in its return value.
    // * Exclusive ownership of `index` is the clause this crate cannot
    //   guarantee at every call site; the crate header records it as accepted
    //   residue, and violating it yields bytes another domain was concurrently
    //   writing, never a dangling or aliased reference (`packet_buffer`).
    unsafe { pool.write_at(index as usize, offset as usize, bytes) }
}

/// Put the rewritten headers back into the pool buffer, and answer whether the
/// frame may still be transmitted.
///
/// Only [`REWRITTEN_HEADER_LEN`] bytes go back. The payload is never written:
/// it is the sender's, this stage does not alter it, and copying it back would
/// overwrite whatever the peer has legitimately done to those bytes since.
fn write_back(
    pool: &Pool,
    descriptor: &Descriptor,
    scratch: &[u8; BUFFER_SIZE],
    counters: &mut RouteCounters,
) -> Verdict {
    // A fixed range of a fixed-size array, bounded at build time by the
    // `REWRITTEN_HEADER_LEN <= BUFFER_SIZE` assertion above.
    match place(
        pool,
        descriptor.buffer,
        descriptor.offset,
        &scratch[..REWRITTEN_HEADER_LEN],
    ) {
        Ok(()) => Verdict::Transmit,
        Err(_) => {
            bump(&mut counters.writeback_failed);
            Verdict::Discard
        }
    }
}

#[cfg(test)]
mod tests {
    /// One poll under a connection table of its own.
    ///
    /// Every case below is about the rings, the pool or the stage around the
    /// verdict chain, and a table carried between two polls would make an
    /// identical frame's second appearance `Established` and settle it in front
    /// of the filter. That behaviour belongs to `pipeline`'s own tests; here a
    /// fresh table keeps each case about the plumbing it names.
    ///
    /// Owned, on the same reasoning: an unowned appliance settles every frame
    /// in front of the rings this macro's callers are about, so a case driven
    /// under one would pass whatever the plumbing did. Ownership's own two sides
    /// are `pipeline`'s and `owner`'s to state.
    macro_rules! poll {
        ($stage:expr, $pipeline:expr, $configuration:expr, $tap:expr) => {{
            let mut flows = ::std::boxed::Box::new($crate::ApplianceTestFlows::new());
            $stage.poll(
                $pipeline,
                $configuration,
                &mut Tracking::new(&mut flows, lfw_clock::Monotonic::BOOT),
                $crate::Ownership::Owned,
                $tap,
            )
        }};
    }
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use net_headers::{
        EtherType, Ipv4Address, MacAddress, ParseFailure, Protocol, Transport, UDP_HEADER_LEN,
    };
    use proptest::prelude::*;
    use routing::{Interface, Neighbour, Router};
    use std::alloc;
    use std::boxed::Box;
    use std::collections::BTreeSet;
    use std::sync::LazyLock;

    /// What the forwarding domain's handler occupies, and the stack it is
    /// declared with.
    ///
    /// `sel4_microkit`'s `run_main` holds the handler as a temporary of its own
    /// frame — `catch_unwind(|| match init().run() { .. })` with
    /// `Handler::run(&mut self)` — so a field of the handler is on the
    /// protection domain's stack and not in BSS. That makes the domain's state
    /// and its `stack_size` one number to keep in step, and this is the side
    /// that can measure it: the composition below is `pds/forwarder`'s
    /// `Forwarder`, which is not host-testable.
    ///
    /// The bound is the measured total with room to spare for call frames, and
    /// the declared stack is twice it again. A field that grows past this fails
    /// here rather than as a boot that dies before the console domain claims
    /// the UART.
    #[test]
    fn the_forwarding_domains_state_fits_the_stack_it_is_declared_with() {
        /// `<protection_domain name="forwarder" stack_size="0x20000">`.
        const FORWARDER_STACK: usize = 0x20000;
        /// Eight `&'static` region references, a `RingSink` and the handler's
        /// own alignment slack, rounded up: what the composition below carries
        /// beside the five measured fields.
        const REFERENCES: usize = 256;

        let state = size_of::<ConfigurationSwitch<MAX_INTERFACES, MAX_NEIGHBOURS>>()
            + size_of::<pipeline::Pipeline>()
            + 2 * size_of::<RouteStage<'static>>()
            + size_of::<Tap<'static>>()
            // The re-decision a commit owes, carried across wakeups. A cursor, a
            // generation and four counters, so it moves this total by tens of
            // bytes — measured here rather than assumed, which is the whole point
            // of the composition being written out.
            + size_of::<pipeline::PolicySweep>()
            + REFERENCES;

        assert!(
            state <= FORWARDER_STACK / 2,
            "the forwarder's handler is {state} bytes against a {FORWARDER_STACK}-byte stack, \
             which leaves under the twofold headroom its call frames are sized by"
        );
    }

    /// The same for the configuration domain, whose stack this landing overflowed
    /// once and has now grown twice.
    ///
    /// Two things live here that did not. The **datastore is a field** rather than
    /// a local: until a document could be submitted there was no path to a second
    /// commit, so the store was dropped at the end of `init`; now every later
    /// document is staged against it and it is resident for the domain's life.
    /// Beside it is **one document of scratch**, 64 KiB, which a submission is
    /// copied out of the peer-written request region into and a read is rendered
    /// into — one field because a demand is one or the other and never both.
    ///
    /// On top of those sits a commit's own call frame, which is unchanged: three
    /// models live at once — the datastore's running and candidate pair, and the
    /// one `stage` hands back — plus the byte image built from the third.
    /// Measured here rather than in `pds/config` because that domain is not
    /// host-testable and because the types are this crate's dependency to see.
    #[test]
    fn the_configuration_domains_state_fits_the_stack_it_is_declared_with() {
        /// `<protection_domain name="config" stack_size="0x80000">`.
        const CONFIG_STACK: usize = 0x80000;
        /// Eight `&'static` region references, a `RingSink`, a `ConfigPublisher`,
        /// a `ConfigResponder`, the submission counters and the frames' own
        /// alignment slack, rounded up.
        const REFERENCES: usize = 512;

        let resident = size_of::<config::Datastore>() + wire::MAX_DOCUMENT_BYTES + REFERENCES;
        let commit = size_of::<config::Staged>()
            + size_of::<config::CommitReport>()
            + size_of::<wire::ConfigImage>();
        let state = resident + commit;

        assert!(
            state <= CONFIG_STACK / 2,
            "a configuration commit occupies {state} bytes ({resident} resident, {commit} in the \
             commit's own frame) against a {CONFIG_STACK}-byte stack, which leaves under the \
             twofold headroom its call frames are sized by"
        );
    }

    /// The same for the management domain, which is now the largest state in the
    /// system by a wide margin and had no such guard.
    ///
    /// Two things grew it in one change and neither is visible from this file:
    /// the exposition's staging buffer, sized by the renderer's worst case and so
    /// by one series per rule the configuration ABI admits, and the snapshot the
    /// exposition is rendered from, which is every shard read whole and therefore
    /// grew with the per-rule block reserved in each. The snapshot is a call-frame
    /// temporary rather than a field, so it is measured beside the handler rather
    /// than inside it — a bound that ignored it would be the wrong number about
    /// the right stack.
    #[test]
    fn the_management_domains_state_fits_the_stack_it_is_declared_with() {
        /// `<protection_domain name="management" stack_size="0x100000">`.
        const MANAGEMENT_STACK: usize = 0x100000;
        /// Six `&'static` region references, a `RingSink`, the `Downloads` and
        /// the handler's own alignment slack, rounded up.
        const REFERENCES: usize = 512;

        let state =
            size_of::<EndpointStage<'static>>() + size_of::<lfw_metrics::Snapshot>() + REFERENCES;

        assert!(
            state <= MANAGEMENT_STACK / 2,
            "the management handler and the snapshot it renders from are {state} bytes against a \
             {MANAGEMENT_STACK}-byte stack, which leaves under the twofold headroom its call \
             frames are sized by"
        );
    }

    /// A ruleset that accepts every frame the routing stage resolves.
    ///
    /// Every test below is about *routing* — which port a frame leaves by and
    /// under which MACs — and the filter behind it is default-deny, so under an
    /// empty ruleset each of them would pass for the wrong reason. Stating the
    /// permission explicitly keeps what each test proves the thing it says it
    /// proves; the filter's own behaviour is `pipeline`'s to test.
    static ALLOW_ALL: LazyLock<pipeline::Ruleset> = LazyLock::new(|| {
        pipeline::Ruleset::build(core::iter::once(pipeline::Rule {
            ingress: None,
            egress: None,
            source: None,
            destination: None,
            protocol: None,
            source_port: None,
            destination_port: None,
            icmp_type: None,
            tracking: None,
            action: pipeline::RuleAction::Accept,
        }))
        .expect("one rule is inside any capacity")
    });

    /// The same shape, dropping. A frame the routing stage resolves and this
    /// rule matches is refused by policy rather than by anything about where it
    /// was going.
    static DROP_ALL: LazyLock<pipeline::Ruleset> = LazyLock::new(|| {
        pipeline::Ruleset::build(core::iter::once(pipeline::Rule {
            ingress: None,
            egress: None,
            source: None,
            destination: None,
            protocol: None,
            source_port: None,
            destination_port: None,
            icmp_type: None,
            tracking: None,
            action: pipeline::RuleAction::Drop,
        }))
        .expect("one rule is inside any capacity")
    });

    /// No rules at all, which is not the absence of a policy but the whole of
    /// one: the filter denies what nothing matched.
    static NO_RULES: LazyLock<pipeline::Ruleset> = LazyLock::new(|| pipeline::Ruleset::EMPTY);
    use std::thread;
    use std::vec::Vec;

    const PORT0: PortId = PortId(0);
    const PORT1: PortId = PortId(1);
    const GATEWAY0_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]);
    const GATEWAY1_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x51]);
    const HOST_A_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]);
    const HOST_B_MAC: MacAddress = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]);
    const HOST_A: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 2]);
    const HOST_B: Ipv4Address = Ipv4Address::from_octets([10, 0, 1, 2]);

    /// The offset a published frame sits at, as the receiving driver publishes
    /// it: the device's own 12-byte header occupies the front of the buffer, so
    /// a stage that assumed a frame starts at zero would rewrite the header's
    /// bytes and read the frame's as headers.
    const DEVICE_HEADER_LEN: u32 = 12;

    /// Bytes of UDP payload the concurrent chain carries its sequence number
    /// in — a `u64`, so half a million frames are all distinguishable.
    const SEQUENCE_LEN: usize = 8;

    /// Turns a thread of the concurrent chain spins without progress before it
    /// declares the run stalled. Measured worst case on an idle host is a few
    /// thousand, so this leaves five orders of magnitude of headroom and is
    /// still seconds rather than forever — which is what turns a buffer lost
    /// across a commit, or an assertion that killed the thread holding the far
    /// end, into a named failure instead of a test that hangs.
    const STALL_SPINS: u64 = 1 << 28;

    /// The configuration `pds/forwarder` compiles in, so what these tests hold
    /// the stage to is the appliance's own topology rather than one invented
    /// here.
    const INTERFACE0: Interface = Interface {
        port: PORT0,
        mac: GATEWAY0_MAC,
        address: Ipv4Address::from_octets([10, 0, 0, 1]),
        prefix_length: 24,
        enabled: true,
    };
    const INTERFACE1: Interface = Interface {
        port: PORT1,
        mac: GATEWAY1_MAC,
        address: Ipv4Address::from_octets([10, 0, 1, 1]),
        prefix_length: 24,
        enabled: true,
    };
    const NEIGHBOURS: [Neighbour; 2] = [
        Neighbour {
            port: PORT0,
            address: HOST_A,
            mac: HOST_A_MAC,
        },
        Neighbour {
            port: PORT1,
            address: HOST_B,
            mac: HOST_B_MAC,
        },
    ];

    /// Built once and shared, the appliance's own two-port topology at the
    /// generation a first commit produces.
    static ROUTER: LazyLock<Router<2, 2>> = LazyLock::new(|| {
        Router::from_slices(&[INTERFACE0, INTERFACE1], &NEIGHBOURS).expect("two of each fit in two")
    });

    /// The same topology with port 0 administratively down, so the one drop
    /// reason a fully enabled configuration cannot reach is reachable here.
    static ROUTER_PORT0_DOWN: LazyLock<Router<2, 2>> = LazyLock::new(|| {
        Router::from_slices(
            &[
                Interface {
                    enabled: false,
                    ..INTERFACE0
                },
                INTERFACE1,
            ],
            &NEIGHBOURS,
        )
        .expect("two of each fit in two")
    });

    /// What a test decides under when the configuration is not what it is
    /// about: the appliance's own table, at the generation a first commit
    /// produces.
    fn running() -> Configuration<'static, 2, 2> {
        Configuration::new(1, &ROUTER, &ALLOW_ALL)
    }

    /// The two addresses generation `number` writes into a forwarded frame: the
    /// egress interface's own MAC, and the MAC of the neighbour it resolves the
    /// next hop to. Both carry `number`, so no two generations share either,
    /// and a frame rewritten out of two tables at once names a pair that
    /// belongs to neither.
    fn generation_macs(number: u8) -> (MacAddress, MacAddress) {
        (
            MacAddress([0x52, 0x54, 0x00, 0xAA, number, 0x01]),
            MacAddress([0x52, 0x54, 0x00, 0xBB, number, 0x02]),
        )
    }

    /// One generation of the appliance's configuration: the two real subnets
    /// throughout, with `port0_up` deciding whether the ingress interface is
    /// administratively up and [`generation_macs`] supplying the pair a rewrite
    /// is attributed by.
    fn generation(number: u8, port0_up: bool) -> (u32, Router<2, 2>) {
        let (egress_mac, next_hop_mac) = generation_macs(number);
        let table = Router::from_slices(
            &[
                Interface {
                    enabled: port0_up,
                    ..INTERFACE0
                },
                Interface {
                    mac: egress_mac,
                    ..INTERFACE1
                },
            ],
            &[
                NEIGHBOURS[0],
                Neighbour {
                    mac: next_hop_mac,
                    ..NEIGHBOURS[1]
                },
            ],
        )
        .expect("two of each fit in two");
        (u32::from(number), table)
    }

    /// One pipeline's three regions, allocated the way a protection domain is
    /// handed them: separate mappings that share nothing.
    struct Regions {
        pool: Box<Pool>,
        rings: Box<ForwardRings>,
        returns: Box<ReturnRing>,
    }

    impl Regions {
        fn new() -> Self {
            Self {
                pool: Box::new(Pool::new()),
                rings: Box::new(ForwardRings::new()),
                returns: Box::new(ReturnRing::new()),
            }
        }
    }

    /// Overwrite a ring's shared cursors the way a byzantine peer that maps the
    /// region read-write can at any moment. The cursors are private to `queue`,
    /// so reach them through the region's known ABI: `head` then `tail`, both
    /// `u32`, at the ring's front (pinned by that crate's own layout asserts).
    fn forge_cursors(ring: &Ring, head: u32, tail: u32) {
        let base = core::ptr::from_ref(ring).cast::<AtomicU32>();
        // SAFETY: `SpscRing` is `#[repr(C)]` with `head` at offset 0 and `tail`
        // at offset 4 as `AtomicU32`s (asserted in `queue`), so both pointers
        // are in bounds and correctly aligned for the live ring borrowed here.
        // Atomic stores are exactly what a peer domain performs on these words.
        unsafe {
            (*base).store(head, Ordering::Relaxed);
            (*base.add(1)).store(tail, Ordering::Relaxed);
        }
    }

    /// One frame an endpoint puts on the wire, in the shape the tests vary it:
    /// every field a routing decision reads, and nothing else.
    struct FrameSpec {
        destination_mac: MacAddress,
        /// The sender's own MAC, a field only because a reply comes from the
        /// other station: every other case is host A putting a frame on port 0.
        source_mac: MacAddress,
        source: Ipv4Address,
        destination: Ipv4Address,
        ttl: u8,
        tagged: bool,
        payload_len: usize,
        /// The transport source port. Fixed for every case but a reply, which
        /// swaps it with the destination: what makes a reply the *same flow* is
        /// its tuple, and a tuple with one end's port unswapped is a different
        /// conversation.
        source_port: u16,
        /// The transport destination port, which is what a filter rule written
        /// for a port matches on — so a case about the policy varies this and
        /// nothing else.
        destination_port: u16,
        /// What rides behind the IPv4 header. The connection tracker in front of
        /// the filter refuses a shape it cannot keep state for, so a case about
        /// one of its reasons varies this and nothing else.
        transport: Transport_,
    }

    /// The transport shapes these cases need, which is a UDP datagram plus one
    /// per class of thing the tracker turns away.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Transport_ {
        Udp,
        /// A TCP segment with `flags` exactly, so a case chooses between a `SYN`
        /// that opens a flow, a combination no exchange produces, and a
        /// mid-stream `ACK`. `sequence` is what puts a segment outside a window.
        Tcp {
            flags: u8,
            sequence: u32,
            acknowledgement: u32,
        },
        /// An ICMP message of `message_type`: an echo request opens a flow, an
        /// echo reply names one, an error quotes one, and anything else is a type
        /// the tracker neither tracks nor relates. `quote` is the datagram an
        /// error carries, absent for the echo types.
        Icmp {
            message_type: u8,
            quote: Quote,
        },
        /// A protocol byte the parser does not break down.
        Unparsed(u8),
        /// A UDP datagram whose transport header is cut short by the IPv4 total
        /// length.
        Truncated,
        /// The second piece of a fragmented datagram, which carries no transport
        /// header at its offset.
        Fragment,
    }

    /// What an ICMP error's quoted datagram is, which is what decides whether the
    /// error names a flow at all.
    ///
    /// A quote is bytes the *sender* chose, so the two failing shapes are as much
    /// part of the fixture as the working one: `lfw_flow::icmp` corroborates a quote
    /// against the table rather than reading it, and a test that could only build a
    /// well-formed quote would exercise none of that.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Quote {
        /// None at all, which is what the echo types carry.
        Absent,
        /// An IPv4 header claiming a version nothing reads, so the quote refuses
        /// itself rather than naming a flow.
        Unreadable,
        /// A UDP datagram from `source` to `destination` on those ports — a real
        /// one, so an error carrying it names the flow that datagram opened.
        Datagram {
            source: Ipv4Address,
            destination: Ipv4Address,
            source_port: u16,
            destination_port: u16,
        },
    }

    impl Quote {
        fn bytes(self) -> Vec<u8> {
            match self {
                Self::Absent => Vec::new(),
                Self::Unreadable => std::vec![0x65; IPV4_HEADER_LEN],
                Self::Datagram {
                    source,
                    destination,
                    source_port,
                    destination_port,
                } => {
                    // The IPv4 header of the quoted datagram, then the four bytes
                    // of UDP header a five-tuple is read from. A real error quotes
                    // at least this much, and nothing behind it is examined.
                    let mut out = Vec::with_capacity(IPV4_HEADER_LEN + 4);
                    let mut ip = [0u8; IPV4_HEADER_LEN];
                    ip[0] = 0x45;
                    ip[2..4].copy_from_slice(&((IPV4_HEADER_LEN + 8) as u16).to_be_bytes());
                    ip[8] = 64;
                    ip[9] = Protocol::UDP.0;
                    ip[12..16].copy_from_slice(&source.octets());
                    ip[16..20].copy_from_slice(&destination.octets());
                    out.extend_from_slice(&ip);
                    out.extend_from_slice(&source_port.to_be_bytes());
                    out.extend_from_slice(&destination_port.to_be_bytes());
                    out
                }
            }
        }
    }

    impl FrameSpec {
        /// Host A to host B across the appliance: the frame the whole dataplane
        /// exists to carry, and the base every rejection below is one edit from.
        fn a_to_b() -> Self {
            Self {
                destination_mac: GATEWAY0_MAC,
                source_mac: HOST_A_MAC,
                source: HOST_A,
                destination: HOST_B,
                ttl: 64,
                tagged: false,
                payload_len: 24,
                source_port: 4444,
                destination_port: 5000,
                transport: Transport_::Udp,
            }
        }

        /// The same frame carrying `transport`.
        fn carrying(transport: Transport_) -> Self {
            Self {
                transport,
                ..Self::a_to_b()
            }
        }

        /// The same frame the other way round, which is what a reply is: it is
        /// still injected on the ingress port the stage was attached to, because
        /// what decides a flow's direction is its tuple and never the port.
        fn reversed(&self) -> Self {
            Self {
                // The far interface's MAC, because a reply is addressed to the
                // appliance on the port it arrives on, and the far station's,
                // because that is who sent it.
                destination_mac: GATEWAY1_MAC,
                source_mac: HOST_B_MAC,
                source: self.destination,
                destination: self.source,
                source_port: self.destination_port,
                destination_port: self.source_port,
                ..*self
            }
        }

        /// The same frame with a different transport, for a script that walks one
        /// five-tuple through several segments.
        fn with(&self, transport: Transport_) -> Self {
            Self { transport, ..*self }
        }

        /// The bytes behind the IPv4 header, and the protocol byte in front of
        /// them.
        fn payload(&self) -> (u8, Vec<u8>) {
            let mut out = Vec::new();
            match self.transport {
                Transport_::Udp | Transport_::Truncated | Transport_::Fragment => {
                    out.extend_from_slice(&self.source_port.to_be_bytes());
                    out.extend_from_slice(&self.destination_port.to_be_bytes());
                    out.extend_from_slice(
                        &((UDP_HEADER_LEN + self.payload_len) as u16).to_be_bytes(),
                    );
                    out.extend_from_slice(&0u16.to_be_bytes());
                    out.extend(payload_pattern(self.payload_len));
                    (Protocol::UDP.0, out)
                }
                Transport_::Tcp {
                    flags,
                    sequence,
                    acknowledgement,
                } => {
                    out.extend_from_slice(&self.source_port.to_be_bytes());
                    out.extend_from_slice(&self.destination_port.to_be_bytes());
                    out.extend_from_slice(&sequence.to_be_bytes());
                    out.extend_from_slice(&acknowledgement.to_be_bytes());
                    // Data offset 5, then the flags, then a window wide enough
                    // that a peer's own advertisement is never what refuses a
                    // segment here.
                    out.extend_from_slice(&[0x50, flags]);
                    out.extend_from_slice(&0xffffu16.to_be_bytes());
                    out.extend_from_slice(&0u32.to_be_bytes());
                    (Protocol::TCP.0, out)
                }
                Transport_::Icmp {
                    message_type,
                    quote,
                } => {
                    out.extend_from_slice(&[message_type, 0, 0, 0, 0, 9, 0, 1]);
                    out.extend_from_slice(&quote.bytes());
                    (Protocol::ICMP.0, out)
                }
                Transport_::Unparsed(protocol) => {
                    out.extend(payload_pattern(16));
                    (protocol, out)
                }
            }
        }

        fn build(&self) -> Vec<u8> {
            let mut frame = Vec::new();
            frame.extend_from_slice(&self.destination_mac.0);
            frame.extend_from_slice(&self.source_mac.0);
            if self.tagged {
                frame.extend_from_slice(&EtherType::VLAN.0.to_be_bytes());
                frame.extend_from_slice(&0x0064u16.to_be_bytes());
            }
            frame.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());

            let (protocol, payload) = self.payload();
            // A truncation is stated in the datagram's own length rather than by
            // sending fewer bytes: what the parser reads is bounded by the total
            // length, so this is how a sender claims a header it did not carry.
            let claimed = if matches!(self.transport, Transport_::Truncated) {
                2
            } else {
                payload.len()
            };
            let total_length = (IPV4_HEADER_LEN + claimed) as u16;
            let mut ip = [0u8; IPV4_HEADER_LEN];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total_length.to_be_bytes());
            if matches!(self.transport, Transport_::Fragment) {
                // Offset 1 in eight-byte units, so this is not the first piece.
                ip[6..8].copy_from_slice(&1u16.to_be_bytes());
            }
            ip[8] = self.ttl;
            ip[9] = protocol;
            ip[12..16].copy_from_slice(&self.source.octets());
            ip[16..20].copy_from_slice(&self.destination.octets());
            let checksum = ipv4_checksum(&ip);
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            frame.extend_from_slice(&ip);
            frame.extend_from_slice(&payload);
            frame
        }
    }

    /// A recognisable payload, so "the payload was not touched" is a claim
    /// about bytes that could have been changed rather than about a run of
    /// zeroes that would look untouched however it were corrupted.
    fn payload_pattern(len: usize) -> impl Iterator<Item = u8> {
        (0..len).map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
    }

    /// The RFC 1071 header checksum, written the naive way rather than reusing
    /// `net_headers`: a builder that computed it the way the parser verifies it
    /// would agree with itself no matter which of the two was wrong.
    fn ipv4_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
        let mut sum = 0u32;
        for (index, pair) in header.chunks(2).enumerate() {
            if index == 5 {
                continue;
            }
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Stand in for the receiving NIC: take a free buffer, fill it as a DMA
    /// would — behind the device header, where a real frame lands — and publish
    /// the span on the pipeline's `rx` ring. Returns the buffer index
    /// published, or `None` when the pool is momentarily empty.
    fn receive(
        pool: &Pool,
        owner: &mut PoolOwner<'_>,
        rx: &mut RingProducer<'_, RING_SLOTS>,
        frame: &[u8],
    ) -> Option<u32> {
        let buffer = owner.alloc()?;
        let index = buffer.index();
        // SAFETY: `buffer` came from our ledger, so we own it exclusively until
        // `lend` transfers it; `frame` is a local, not a pool borrow.
        unsafe { pool.write_at(index as usize, DEVICE_HEADER_LEN as usize, frame) }
            .expect("the test frames are far smaller than a buffer");
        match owner.lend(
            rx,
            buffer,
            DEVICE_HEADER_LEN,
            frame.len() as u32,
            Verdict::Transmit,
        ) {
            Ok(()) => Some(index),
            Err(buffer) => {
                owner.release(buffer);
                None
            }
        }
    }

    /// Stand in for the transmitting NIC: drain every frame queued on `tx`,
    /// read its payload back, and return the buffer to its owner on `free`,
    /// invoking `on_payload` for each. Returns how many frames were transmitted.
    fn transmit(
        pool: &Pool,
        tx: &mut RingConsumer<'_, RING_SLOTS>,
        free: &mut RingProducer<'_, RING_SLOTS>,
        mut on_frame: impl FnMut(&Descriptor, &[u8]),
    ) -> usize {
        let mut count = 0;
        // One buffer's worth of private storage, reused across the drain: what
        // `on_frame` inspects is a snapshot here, never a borrow of the pool.
        let mut storage = [0u8; BUFFER_SIZE];
        for descriptor in tx.drain(DRAIN_LIMIT) {
            {
                // SAFETY: we dequeued this descriptor, so we own its buffer
                // until it is returned below. The data is the `len` bytes at
                // `offset` the rx side published, and the snapshot lands in
                // `storage`, so the borrow handed to `on_frame` is of this
                // frame's own memory and ends before the buffer is returned.
                let bytes = unsafe {
                    pool.copy_out(
                        descriptor.buffer as usize,
                        descriptor.offset as usize,
                        descriptor.len,
                        &mut storage,
                    )
                }
                .expect("`receive` published a span within one buffer");
                on_frame(&descriptor, bytes);
            }
            // Under either verdict: this is the only domain that can return the
            // buffer, which is what the verdict rides in the descriptor for.
            free.try_enqueue(descriptor)
                .expect("free ring has a slot for every pool buffer");
            count += 1;
        }
        count
    }

    #[test]
    fn zeroed_regions_are_valid_and_empty() {
        // Regions built from zeroed memory (as seL4 provides) must be empty and
        // immediately usable. A fresh handle starts at position zero, which is
        // exactly what a zeroed region's cursors say, so attaching to one sees
        // an empty ring without reading anything a peer could have written.
        let r = Regions::new();
        assert!(r.rings.rx.consumer().is_empty());
        assert!(r.rings.tx.consumer().is_empty());
        assert!(r.returns.free.consumer().is_empty());
        assert_eq!(r.pool.capacity(), POOL_BUFFERS);
        assert_eq!(PoolOwner::attach(&r.returns).owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_pool_region_gives_every_buffer_the_region_alignment() {
        // The property `packet_buffer` names this crate as the owner of. A pool
        // is the whole of its region, so there is no offset in the chain and
        // the region base's alignment is each buffer's, up to the stride.
        assert!(MAPPING_ALIGN.is_multiple_of(BUFFER_SIZE));
        let pool_paddr = 0x3100_0000u64;
        assert!(pool_paddr.is_multiple_of(MAPPING_ALIGN as u64));
        for index in 0..POOL_BUFFERS as u32 {
            assert!(buffer_paddr(pool_paddr, index).is_multiple_of(BUFFER_SIZE as u64));
        }
        // The last buffer ends exactly at the region's end: the grant holds the
        // pool and not one byte more.
        assert_eq!(
            buffer_paddr(pool_paddr, POOL_BUFFERS as u32 - 1) + BUFFER_SIZE as u64,
            pool_paddr + POOL_REGION_SIZE as u64
        );
    }

    #[test]
    fn the_region_layout_is_the_pinned_cross_domain_abi() {
        // The same offsets the `const _` blocks pin, restated as values so a
        // reviewer sees the actual region map and the sizes the system
        // description must reserve.
        assert_eq!(size_of::<Pool>(), POOL_BUFFERS * BUFFER_SIZE);
        assert_eq!(size_of::<Ring>(), 8 + RING_SLOTS * size_of::<Descriptor>());
        assert_eq!(offset_of!(ForwardRings, rx), 0);
        assert_eq!(offset_of!(ForwardRings, tx), size_of::<Ring>());
        assert_eq!(size_of::<ForwardRings>(), 2 * size_of::<Ring>());
        assert_eq!(offset_of!(ReturnRing, free), 0);
        assert_eq!(size_of::<ReturnRing>(), size_of::<Ring>());
        assert_eq!(align_of::<ForwardRings>(), 4);
        assert_eq!(align_of::<ReturnRing>(), 4);
        // The three grants the system description must declare, as values.
        assert_eq!(size_of::<Pool>(), 0x20000);
        assert_eq!(size_of::<ForwardRings>(), 4112);
        assert_eq!(size_of::<ReturnRing>(), 2056);
        assert_eq!(POOL_REGION_SIZE, 0x20000);
        assert_eq!(FORWARD_REGION_SIZE, 0x2000);
        assert_eq!(RETURN_REGION_SIZE, 0x1000);
        // And what the split costs, as values: 0x23000 against the 0x22000 one
        // region holding all four components rounds up to — one page.
        assert_eq!(
            POOL_REGION_SIZE + FORWARD_REGION_SIZE + RETURN_REGION_SIZE,
            0x23000
        );
        assert_eq!(
            (size_of::<Pool>() + 3 * size_of::<Ring>()).next_multiple_of(MAPPING_ALIGN),
            0x22000
        );
    }

    #[test]
    fn descriptor_bounds_reject_out_of_pool_spans() {
        let max = BUFFER_SIZE as u32;
        assert!(descriptor_in_bounds(&Descriptor::new(
            0,
            0,
            max,
            Verdict::Transmit
        )));
        assert!(descriptor_in_bounds(&Descriptor::new(
            POOL_BUFFERS as u32 - 1,
            max - 1,
            1,
            Verdict::Transmit
        )));
        assert!(descriptor_in_bounds(&Descriptor::new(
            0,
            max,
            0,
            Verdict::Transmit
        )));
        // Buffer index outside the pool.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            POOL_BUFFERS as u32,
            0,
            1,
            Verdict::Transmit
        )));
        // Span runs past the buffer end.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            0,
            1,
            max,
            Verdict::Transmit
        )));
        // Offset + len overflows.
        assert!(!descriptor_in_bounds(&Descriptor::new(
            0,
            u32::MAX,
            u32::MAX,
            Verdict::Transmit
        )));
    }

    #[test]
    #[should_panic(expected = "buffer_paddr would address outside the pool")]
    fn a_paddr_for_an_index_outside_the_pool_faults_rather_than_leaving_the_region() {
        // The exact step by which a forged index used to become a DMA-writable
        // address outside the shared region. Ungated: the bound is compiled
        // into every profile, so gating this on `debug_assertions` would prove
        // a property of a build that never boots.
        let _ = buffer_paddr(0x3100_0000, POOL_BUFFERS as u32);
    }

    #[test]
    fn attaching_to_an_aligned_zeroed_region_yields_the_empty_state() {
        // What a protection domain actually does at start-up: seL4 hands over a
        // zeroed, page-aligned mapping, and attaching to it must observe empty
        // rings and a full pool without touching anything a peer controls.
        let rings = Box::into_raw(Box::new(ForwardRings::new()));
        let returns = Box::into_raw(Box::new(ReturnRing::new()));
        // SAFETY: both pointers come from `Box::into_raw`, so each is aligned,
        // live, and exactly its region type's size holding a valid value; both
        // are reclaimed below, after the borrows end.
        let (rings_ref, returns_ref) =
            unsafe { (attach_region(rings), attach_region::<ReturnRing>(returns)) };
        assert!(rings_ref.rx.consumer().is_empty());
        assert!(rings_ref.tx.consumer().is_empty());
        assert_eq!(PoolOwner::attach(returns_ref).owned(), POOL_BUFFERS);
        // SAFETY: the borrows above have ended and both pointers are the ones
        // `Box::into_raw` produced, so reconstituting the boxes is the matching
        // deallocation.
        unsafe {
            drop(Box::from_raw(rings));
            drop(Box::from_raw(returns));
        }
    }

    /// The connection table's exclusive borrow is taken once and faults on a
    /// second attempt.
    ///
    /// The enforcer of the one safety clause `attach_flow_table!` does not
    /// delegate: a second `&mut` to those bytes would be undefined behaviour, and
    /// nothing about a macro stops it being expanded twice. Both borrows are
    /// leaked deliberately — a `&'static mut` is what the caller gets and there
    /// is nothing to give back — and the region is leaked with them, this being
    /// the only test that may take the one guard in the process.
    #[test]
    #[should_panic(expected = "borrow was taken twice")]
    fn the_connection_tables_borrow_cannot_be_taken_twice() {
        // Allocated zeroed on the heap rather than built as a value: the
        // appliance's table is sixty-eight mebibytes, so materialising one would
        // overflow the stack before the borrow could be taken. The layout is the
        // type's own, so the size and the 64-byte alignment are the real ones.
        let layout = alloc::Layout::new::<ApplianceFlowTable>();
        // SAFETY: the layout has a non-zero size, which is `alloc_zeroed`'s one
        // requirement.
        let region = unsafe { alloc::alloc_zeroed(layout) }.cast::<ApplianceFlowTable>();
        assert!(!region.is_null(), "the test could not reserve the region");
        // SAFETY: the allocation is aligned for the type, live, exactly its size,
        // and zero-filled — so the bytes are a valid, if unlinked, table. It is
        // deliberately never freed, so the `&'static mut` cannot dangle.
        let first = unsafe { attach_flow_table_region(region) };
        assert!(first.is_empty(), "a zeroed region is a table with no flows");
        // SAFETY: as above. This call must fault on the guard rather than produce
        // a second reference to the same bytes.
        let _second = unsafe { attach_flow_table_region(region) };
    }

    #[test]
    #[should_panic(expected = "region is misaligned")]
    fn attaching_to_a_misaligned_region_faults_before_the_reference_is_made() {
        // Alignment is a soundness precondition of the reference `attach_region`
        // creates, so it must fault before that, not after — in every profile,
        // which is why this test is not gated on `debug_assertions`.
        let mut backing = Box::new([0u8; size_of::<ForwardRings>() + 8]);
        // SAFETY: the offset stays inside the live allocation, so forming the
        // pointer is defined; the call is expected to fault on the alignment
        // check before it ever dereferences it.
        let misaligned = unsafe { backing.as_mut_ptr().add(1) }.cast::<ForwardRings>();
        // SAFETY: as above — this must panic on the alignment assertion; nothing
        // past it is expected to run.
        let _ = unsafe { attach_region(misaligned) };
    }

    #[test]
    fn a_routable_packet_is_rewritten_in_the_pool_and_marked_for_transmission() {
        // The whole of what the stage is for, asserted on the bytes the
        // transmitting NIC will read rather than on the verdict alone: a frame
        // marked `Transmit` whose pool buffer still held the arriving MACs
        // would be sent straight back to the subnet it came from.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let sent = FrameSpec::a_to_b().build();
        receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
        assert_eq!(poll!(stage, &mut pipeline, running(), None), 1);
        assert_eq!(stage.counters().forwarded, 1);
        assert_eq!(stage.counters().drops.total(), 0);

        let mut seen = 0;
        transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
            seen += 1;
            assert_eq!(
                Verdict::from_bits(descriptor.verdict),
                Some(Verdict::Transmit)
            );
            assert_eq!(
                descriptor.offset, DEVICE_HEADER_LEN,
                "the span must be the one published"
            );
            assert_eq!(descriptor.len as usize, sent.len());

            // Re-parsed rather than compared byte-wise, so what is asserted is
            // what the next hop will make of the frame.
            let mut copy = bytes.to_vec();
            let frame = Frame::parse(&mut copy).expect("a rewritten frame stays well-formed");
            assert_eq!(
                frame.source_mac(),
                GATEWAY1_MAC,
                "the egress interface's own MAC"
            );
            assert_eq!(frame.destination_mac(), HOST_B_MAC, "the next hop's MAC");
            assert_eq!(frame.ipv4().ttl, 63);
            assert_eq!(frame.ipv4().source, HOST_A);
            assert_eq!(frame.ipv4().destination, HOST_B);
            assert!(matches!(frame.transport(), Transport::Udp(_)));

            // Everything past the two rewritten headers is the sender's, and
            // is byte-identical to what arrived.
            assert_eq!(
                &bytes[REWRITTEN_HEADER_LEN..],
                &sent[REWRITTEN_HEADER_LEN..]
            );
        });
        assert_eq!(seen, 1);
        assert_eq!(owner.reclaim(), 1);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    /// The same frame, on an appliance no management plane has taken: the
    /// buffer travels on so its owner gets it back, and the bytes in the pool
    /// are the ones that arrived.
    ///
    /// The pool is what makes this worth stating through the plumbing rather
    /// than in `pipeline` alone. A refusal that still rewrote the frame would
    /// leave an unowned node putting its own MACs onto a buffer it then hands
    /// back, and a verdict comparison would not see it.
    #[test]
    fn an_unowned_appliance_discards_a_routable_frame_and_leaves_the_pool_as_it_arrived() {
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let sent = FrameSpec::a_to_b().build();
        receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
        let mut flows = Box::new(ApplianceTestFlows::new());
        assert_eq!(
            stage.poll(
                &mut pipeline,
                running(),
                &mut Tracking::new(&mut flows, lfw_clock::Monotonic::BOOT),
                Ownership::Unowned,
                None,
            ),
            1,
            "the descriptor must still travel on, or the buffer is lost to its owner"
        );
        assert_eq!(stage.counters().forwarded, 0);
        assert_eq!(stage.counters().drops.get(DropReason::Unowned), 1);
        assert_eq!(
            stage.counters().drops.total(),
            1,
            "the refusal is ownership's and no other stage reached the frame"
        );

        let mut seen = 0;
        transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
            seen += 1;
            assert_eq!(
                Verdict::from_bits(descriptor.verdict),
                Some(Verdict::Discard),
                "an unowned appliance marked a frame for transmission"
            );
            assert_eq!(bytes, &sent[..], "a refused frame was rewritten");
        });
        assert_eq!(seen, 1);
        assert_eq!(owner.reclaim(), 1);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_forwarded_frame_is_rewritten_where_the_producer_published_it() {
        // The frame sits behind the device's own header, so the rewrite must
        // land at the descriptor's `offset`. A stage that wrote back at the
        // buffer's front would corrupt that header and leave the frame's own
        // first 34 bytes as they arrived — which still parses, still routes,
        // and loops.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();

        let sent = FrameSpec::a_to_b().build();
        let index =
            receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
        assert_eq!(poll!(stage, &mut pipeline, running(), None), 1);

        let mut whole = [0u8; BUFFER_SIZE];
        // SAFETY: the buffer is lent, and this test is the only other party to
        // the pool; the snapshot lands in this function's own storage.
        let buffer = unsafe {
            r.pool
                .copy_out(index as usize, 0, BUFFER_SIZE as u32, &mut whole)
        }
        .expect("a whole buffer is in bounds");
        assert_eq!(
            &buffer[..DEVICE_HEADER_LEN as usize],
            &[0u8; DEVICE_HEADER_LEN as usize],
            "the device header space was written over"
        );
        let mut frame_bytes = buffer[DEVICE_HEADER_LEN as usize..][..sent.len()].to_vec();
        let frame = Frame::parse(&mut frame_bytes).expect("the rewritten frame parses");
        assert_eq!(frame.destination_mac(), HOST_B_MAC);
    }

    #[test]
    fn lend_publishes_the_verdict_it_was_given() {
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut rx_out = r.rings.rx.consumer();
        for verdict in [Verdict::Transmit, Verdict::Discard] {
            let buffer = owner.alloc().expect("a full pool has buffers");
            let index = buffer.index();
            owner
                .lend(&mut rx_in, buffer, 4, 8, verdict)
                .expect("the ring is empty");
            assert_eq!(
                rx_out.try_dequeue(),
                Some(Descriptor::new(index, 4, 8, verdict))
            );
        }
    }

    #[test]
    fn the_verdict_a_producer_published_is_replaced_by_this_stages_own_decision() {
        // The rx driver's verdict word is peer input: a byzantine one can mark
        // a perfectly routable frame `Discard`, or write a word that decodes to
        // nothing at all. Neither may decide anything here — this stage is the
        // domain that judges the frame, and it overwrites the word it was
        // handed with what it concluded.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();

        let sent = FrameSpec::a_to_b().build();
        for forged in [Verdict::Discard.to_bits(), 0xDEAD_BEEF] {
            let buffer = owner.alloc().expect("a full pool has buffers");
            let index = buffer.index();
            // SAFETY: the token is ours, and `sent` is a local rather than a
            // pool borrow.
            unsafe {
                r.pool
                    .write_at(index as usize, DEVICE_HEADER_LEN as usize, &sent)
            }
            .expect("a frame is far smaller than a buffer");
            // A field-wise literal, not `Descriptor::new`: `lend` takes a
            // `Verdict`, so a word decoding to nothing can only be published by
            // a peer writing the slot itself — which is what this is.
            rx_in
                .try_enqueue(Descriptor {
                    buffer: index,
                    offset: DEVICE_HEADER_LEN,
                    len: sent.len() as u32,
                    verdict: forged,
                })
                .expect("the ring is empty");
            drop(buffer);

            assert_eq!(poll!(stage, &mut pipeline, running(), None), 1);
            let handed_on = tx_out.try_dequeue().expect("the frame was handed on");
            assert_eq!(
                Verdict::from_bits(handed_on.verdict),
                Some(Verdict::Transmit),
                "a routable frame must be transmitted whatever the producer claimed"
            );
        }
        assert_eq!(stage.counters().forwarded, 2);
    }

    #[test]
    fn a_full_destination_ring_is_counted_and_stops_the_drain() {
        // A byzantine rx peer over-fills `rx` while the tx driver stalls.
        // The destination is filled *through the stage itself*, since a second
        // producer handle would restart at slot zero and prove nothing. The
        // buffers those refused descriptors named are lost to the pool, which
        // is the residue the crate header records.
        let r = Regions::new();
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();

        // Descriptors naming empty buffers: in bounds, so they reach the
        // destination ring under a `Discard` verdict and fill it.
        let capacity = r.rings.tx.capacity();
        for index in 0..capacity as u32 {
            rx_in
                .try_enqueue(Descriptor::new(
                    index % POOL_BUFFERS as u32,
                    0,
                    64,
                    Verdict::Transmit,
                ))
                .unwrap();
        }
        assert_eq!(
            poll!(stage, &mut pipeline, running(), None),
            capacity,
            "the destination is now full"
        );
        assert_eq!(stage.counters().egress_full, 0);

        for index in 0..4 {
            rx_in
                .try_enqueue(Descriptor::new(index, 0, 64, Verdict::Transmit))
                .unwrap();
        }
        assert_eq!(poll!(stage, &mut pipeline, running(), None), 0);
        assert_eq!(stage.counters().egress_full, 1);
        // Draining stopped at the first refusal rather than emptying `rx` into
        // a full destination and losing every buffer with it.
        assert_eq!(r.rings.rx.consumer().len(), 3);
    }

    #[test]
    fn poll_is_bounded_when_a_peer_keeps_the_source_ring_non_empty() {
        // A peer that keeps advancing its published `tail` makes the source
        // look permanently non-empty. Work per poll must still be finite.
        let r = Regions::new();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();
        for round in 0..8u32 {
            forge_cursors(&r.rings.rx, 0, round.wrapping_mul(37).wrapping_add(11));
            let handed_on = poll!(stage, &mut pipeline, running(), None);
            assert!(
                handed_on <= DRAIN_LIMIT,
                "poll handled {handed_on} descriptors"
            );
            // Keep the destination drained so the bound, not fullness, is what
            // stops the loop.
            let _ = tx_out.drain(DRAIN_LIMIT).count();
        }
    }

    #[test]
    fn a_descriptor_naming_no_pool_buffer_is_counted_and_never_dereferenced() {
        // The forged descriptor is the one thing the stage may not hand on:
        // it names no buffer the transmitting driver could return, so passing
        // it along would be inventing a return rather than granting one. It is
        // also the case where a missing bounds check would have the stage read
        // outside the pool.
        let r = Regions::new();
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();

        for forged in [
            Descriptor::new(POOL_BUFFERS as u32, 0, 64, Verdict::Transmit),
            Descriptor::new(u32::MAX, 0, 64, Verdict::Transmit),
            Descriptor::new(0, 1, BUFFER_SIZE as u32, Verdict::Transmit),
            Descriptor::new(0, u32::MAX, u32::MAX, Verdict::Transmit),
        ] {
            rx_in.try_enqueue(forged).expect("the ring has room");
        }

        assert_eq!(
            poll!(stage, &mut pipeline, running(), None),
            0,
            "nothing may be handed on"
        );
        assert_eq!(stage.counters().malformed_descriptor, 4);
        assert_eq!(stage.counters().snapshot_failed, 0);
        assert_eq!(tx_out.try_dequeue(), None);
    }

    #[test]
    fn every_reason_the_pipeline_refuses_a_frame_for_still_hands_the_buffer_back() {
        // The property the verdict mechanism exists for, over every drop the
        // pipeline can reach: this domain maps no `free` ring, so a frame it
        // decides against must still travel to the transmitting driver — the
        // only domain that can give the buffer back. A stage that dropped the
        // descriptor instead would shrink the pool by one buffer per hostile
        // packet, which is a denial of service with no counter attached.
        let cases = [
            (
                DropReason::UnconfiguredIngressPort,
                &*ROUTER,
                PortId(7),
                FrameSpec::a_to_b(),
            ),
            (
                DropReason::InterfaceDisabled,
                &*ROUTER_PORT0_DOWN,
                PORT0,
                FrameSpec::a_to_b(),
            ),
            (
                DropReason::NotAddressedToUs,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination_mac: MacAddress::BROADCAST,
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::VlanTagged,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    tagged: true,
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::MartianSource,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    source: Ipv4Address::from_octets([224, 0, 0, 1]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::UnroutableDestination,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([255, 255, 255, 255]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::AddressedToThisRouter,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([10, 0, 1, 1]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::TtlExpired,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    ttl: 1,
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::NoRoute,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([192, 0, 2, 9]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::EgressIsIngress,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([10, 0, 0, 9]),
                    ..FrameSpec::a_to_b()
                },
            ),
            (
                DropReason::NoNeighbour,
                &*ROUTER,
                PORT0,
                FrameSpec {
                    destination: Ipv4Address::from_octets([10, 0, 1, 77]),
                    ..FrameSpec::a_to_b()
                },
            ),
            // The two the filter names, on a frame the routing stage resolves:
            // what refuses these is the policy, so the table and the frame are
            // the ones every forwarded case uses and only the ruleset differs.
            (
                DropReason::PolicyDenied,
                &*ROUTER,
                PORT0,
                FrameSpec::a_to_b(),
            ),
            (
                DropReason::NoPolicyMatch,
                &*ROUTER,
                PORT0,
                FrameSpec::a_to_b(),
            ),
            // The connection tracker's, each on a frame the routing stage
            // resolves: every one of these is refused for what it carries behind
            // the IPv4 header and for nothing about where it was going.
            (
                DropReason::FlowUnsupportedProtocol,
                &*ROUTER,
                PORT0,
                FrameSpec::carrying(Transport_::Unparsed(47)),
            ),
            (
                DropReason::FlowFragment,
                &*ROUTER,
                PORT0,
                FrameSpec::carrying(Transport_::Fragment),
            ),
            (
                DropReason::FlowMalformed,
                &*ROUTER,
                PORT0,
                FrameSpec::carrying(Transport_::Truncated),
            ),
            (
                DropReason::FlowInvalidFlags,
                &*ROUTER,
                PORT0,
                // No flags at all, which no exchange produces.
                FrameSpec::carrying(Transport_::Tcp {
                    flags: 0,
                    sequence: 1_000,
                    acknowledgement: 0,
                }),
            ),
            (
                DropReason::FlowMidStream,
                &*ROUTER,
                PORT0,
                // A bare `ACK` for a five-tuple nothing opened.
                FrameSpec::carrying(Transport_::Tcp {
                    flags: 0x10,
                    sequence: 1_000,
                    acknowledgement: 1,
                }),
            ),
            (
                DropReason::FlowNoSuchFlow,
                &*ROUTER,
                PORT0,
                // An echo reply answering a request that never travelled.
                FrameSpec::carrying(Transport_::Icmp {
                    message_type: 0,
                    quote: Quote::Absent,
                }),
            ),
            (
                DropReason::FlowQuotedInvalid,
                &*ROUTER,
                PORT0,
                // An unreachable error quoting bytes that are not IPv4.
                FrameSpec::carrying(Transport_::Icmp {
                    message_type: 3,
                    quote: Quote::Unreadable,
                }),
            ),
            (
                DropReason::FlowUnsupportedIcmp,
                &*ROUTER,
                PORT0,
                // Redirect: excluded outright, being a routing instruction.
                FrameSpec::carrying(Transport_::Icmp {
                    message_type: 5,
                    quote: Quote::Absent,
                }),
            ),
        ];

        /// The five reasons no frame driven through this loop reaches. Four need
        /// the table to already be in a particular condition — two need a flow
        /// this frame is not the first packet of, and two need a table or a
        /// bucket with no room left — and the fifth is not about the frame at
        /// all: every poll here runs on an owned appliance, an unowned one
        /// refusing whatever is put in front of it.
        ///
        /// They are excluded here and covered elsewhere rather than left
        /// unstated: `a_flow_state_refusal_still_hands_the_buffer_back` drives
        /// the first two through this same stage across two polls, the two
        /// capacity refusals are `lfw_flow`'s own property tests — the table's
        /// capacity being that crate's subject and not this one's — and
        /// `an_unowned_appliance_discards_a_routable_frame_and_leaves_the_pool_as_it_arrived`
        /// drives the last through this stage and asserts the same return. What
        /// makes the exclusion safe is that the buffer-return path below does
        /// not branch on the reason at all: every `Verdict::Drop` takes one arm.
        const NEEDS_A_PRIMED_TABLE: [DropReason; 5] = [
            DropReason::Unowned,
            DropReason::FlowInvalidState,
            DropReason::FlowOutOfWindow,
            DropReason::FlowTableFull,
            DropReason::FlowBucketFull,
        ];

        // What makes the name of this test true rather than aspirational: a
        // reason added to the enum without a case here, and without a place in
        // the exclusion above, fails at once.
        let mut covered: Vec<DropReason> = cases.iter().map(|(reason, ..)| *reason).collect();
        covered.extend(NEEDS_A_PRIMED_TABLE);
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(
            covered,
            DropReason::ALL.to_vec(),
            "a drop reason no case here reaches"
        );

        for (reason, table, ingress, spec) in cases {
            // The ruleset is the reason for two of these cases and merely
            // permissive for the rest, so it is chosen here rather than carried
            // in a column that would read as empty on eleven of thirteen rows.
            let rules: &pipeline::Ruleset = match reason {
                DropReason::PolicyDenied => &DROP_ALL,
                DropReason::NoPolicyMatch => &NO_RULES,
                _ => &ALLOW_ALL,
            };
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = RouteStage::attach(&r.rings, &r.pool, ingress, PORT1);
            let mut pipeline = Pipeline::new();
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();

            let sent = spec.build();
            receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
            assert_eq!(
                poll!(
                    stage,
                    &mut pipeline,
                    Configuration::new(1, table, rules),
                    None
                ),
                1,
                "{reason}: the descriptor must travel on"
            );

            let counters = stage.counters();
            assert_eq!(counters.drops.get(reason), 1, "{reason}: not counted");
            assert_eq!(
                counters.drops.total(),
                1,
                "{reason}: counted as something else too"
            );
            assert_eq!(counters.forwarded, 0, "{reason}");

            let mut seen = 0;
            transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
                seen += 1;
                assert_eq!(
                    Verdict::from_bits(descriptor.verdict),
                    Some(Verdict::Discard),
                    "{reason}: a refused frame must not be transmitted"
                );
                assert_eq!(bytes, sent, "{reason}: a refused frame was rewritten");
            });
            assert_eq!(seen, 1, "{reason}");
            // The buffer is back where it started: nothing leaked.
            assert_eq!(owner.reclaim(), 1, "{reason}");
            assert_eq!(owner.owned(), POOL_BUFFERS, "{reason}");
        }
    }

    /// The two tracker refusals that need a flow already in the table, driven
    /// through the appliance's real shape — and with every buffer accounted for
    /// on the way, so the exclusion the case list above records points at a real
    /// test rather than at an argument.
    ///
    /// **Two stages, one table**, which is the forwarder's own arrangement and the
    /// only one a handshake can be driven through: a reply is routed out of the
    /// port the request arrived on, so it has to arrive on the other one, and the
    /// flow both halves belong to is a single entry because the table is shared.
    /// The first three steps walk a handshake to `Established`; the last two are
    /// the segments that flow then refuses.
    #[test]
    fn a_flow_state_refusal_still_hands_the_buffer_back() {
        /// The two sequence spaces the handshake opens on.
        const CLIENT_ISN: u32 = 100_000;
        const SERVER_ISN: u32 = 900_000;

        /// One direction's whole apparatus: a pipeline's regions, its pool owner
        /// and the four handles a frame passes through.
        struct Direction {
            regions: Regions,
        }

        let forward = Direction {
            regions: Regions::new(),
        };
        let back = Direction {
            regions: Regions::new(),
        };
        let mut owners = [
            PoolOwner::attach(&forward.regions.returns),
            PoolOwner::attach(&back.regions.returns),
        ];
        let mut producers = [
            forward.regions.rings.rx.producer(),
            back.regions.rings.rx.producer(),
        ];
        let mut stages = [
            RouteStage::attach(&forward.regions.rings, &forward.regions.pool, PORT0, PORT1),
            RouteStage::attach(&back.regions.rings, &back.regions.pool, PORT1, PORT0),
        ];
        let mut pipeline = Pipeline::new();
        let mut flows = Box::new(ApplianceTestFlows::new());

        let base = FrameSpec::a_to_b();
        let segment = |flags: u8, sequence: u32, acknowledgement: u32| Transport_::Tcp {
            flags,
            sequence,
            acknowledgement,
        };
        // Every step: which direction carries it, the frame, and what the stage
        // must have counted afterwards.
        let script = [
            // The handshake, which must be carried in full — a tracker that
            // refused any of it would make the two refusals below vacuous.
            (0usize, base.with(segment(0x02, CLIENT_ISN, 0)), None),
            (
                1,
                base.reversed()
                    .with(segment(0x12, SERVER_ISN, CLIENT_ISN.wrapping_add(1))),
                None,
            ),
            (
                0,
                base.with(segment(
                    0x10,
                    CLIENT_ISN.wrapping_add(1),
                    SERVER_ISN.wrapping_add(1),
                )),
                None,
            ),
            // A segment a gibibyte past anything the peer authorised.
            (
                0,
                base.with(segment(
                    0x10,
                    CLIENT_ISN.wrapping_add(1).wrapping_add(1 << 30),
                    SERVER_ISN.wrapping_add(1),
                )),
                Some(DropReason::FlowOutOfWindow),
            ),
            // And a `SYN` on a flow that is already synchronized, which is the
            // shape an off-path attacker uses to try to reopen one.
            (
                0,
                base.with(segment(0x02, CLIENT_ISN, 0)),
                Some(DropReason::FlowInvalidState),
            ),
        ];

        let mut sent = [0usize; 2];
        for (step, (which, spec, expected)) in script.iter().enumerate() {
            let direction = if *which == 0 { &forward } else { &back };
            let bytes = spec.build();
            receive(
                &direction.regions.pool,
                &mut owners[*which],
                &mut producers[*which],
                &bytes,
            )
            .expect("a full pool has buffers");
            sent[*which] += 1;
            assert_eq!(
                stages[*which].poll(
                    &mut pipeline,
                    Configuration::new(1, &*ROUTER, &ALLOW_ALL),
                    &mut Tracking::new(&mut flows, lfw_clock::Monotonic::BOOT),
                    Ownership::Owned,
                    None,
                ),
                1,
                "step {step}: the descriptor must travel on"
            );
            if let Some(reason) = expected {
                assert_eq!(
                    stages[*which].counters().drops.get(*reason),
                    1,
                    "step {step}: not refused as {reason}"
                );
            }
        }
        // The handshake was carried whole, and exactly the two intended segments
        // were refused: the flow is one entry and the counters name it.
        assert_eq!(flows.len(), 1, "the handshake left more than one flow");
        assert_eq!(stages[0].counters().forwarded, 2);
        assert_eq!(stages[1].counters().forwarded, 1);
        assert_eq!(stages[0].counters().drops.total(), 2);
        assert_eq!(stages[1].counters().drops.total(), 0);

        // Every buffer back where it started: nothing leaked on a refusal path.
        for (which, direction) in [(0usize, &forward), (1, &back)] {
            let mut tx_out = direction.regions.rings.tx.consumer();
            let mut free_in = direction.regions.returns.free.producer();
            let mut seen = 0;
            transmit(
                &direction.regions.pool,
                &mut tx_out,
                &mut free_in,
                |_, _| {
                    seen += 1;
                },
            );
            assert_eq!(seen, sent[which], "direction {which}");
            assert_eq!(owners[which].reclaim(), sent[which], "direction {which}");
            assert_eq!(owners[which].owned(), POOL_BUFFERS, "direction {which}");
        }
    }

    /// **The connection history, end to end.** One TCP conversation opened,
    /// advanced, refused mid-window and closed, with the tap attached — so what a
    /// recorder is handed is asserted against the traffic that produced it rather
    /// than against a composition this test performed.
    ///
    /// Two stages and one table, as the refusal test above: a handshake cannot be
    /// driven any other way, a reply being routed out of the port its request
    /// arrived on. The events are the whole point, and each is a *transition* —
    /// the third `ACK` moves the flow to `Established` and the last one moves it
    /// to `TimeWait`, while a retransmission that moves nothing carries no event
    /// at all.
    #[test]
    fn a_conversation_opens_advances_and_closes_in_the_events_the_tap_records() {
        /// The two sequence spaces the handshake opens on.
        const CLIENT_ISN: u32 = 500_000;
        const SERVER_ISN: u32 = 700_000;

        let forward = Regions::new();
        let back = Regions::new();
        let ring = TapRing::new();
        let mut tap = Tap::attach(&ring.records, &ring.consume);
        let mut owners = [
            PoolOwner::attach(&forward.returns),
            PoolOwner::attach(&back.returns),
        ];
        let mut producers = [forward.rings.rx.producer(), back.rings.rx.producer()];
        let mut stages = [
            RouteStage::attach(&forward.rings, &forward.pool, PORT0, PORT1),
            RouteStage::attach(&back.rings, &back.pool, PORT1, PORT0),
        ];
        let mut pipeline = Pipeline::new();
        let mut flows = Box::new(ApplianceTestFlows::new());

        let base = FrameSpec::a_to_b();
        let segment = |flags: u8, sequence: u32, acknowledgement: u32| Transport_::Tcp {
            flags,
            sequence,
            acknowledgement,
        };
        // A TCP frame this spec builds carries a bare header, so the only
        // sequence space a segment occupies is the phantom byte each of `SYN` and
        // `FIN` takes.
        let client_after_syn = CLIENT_ISN.wrapping_add(1);
        let server_after_syn = SERVER_ISN.wrapping_add(1);
        let client_after_fin = client_after_syn.wrapping_add(1);
        let server_after_fin = server_after_syn.wrapping_add(1);
        // Each step: the direction, the frame, the event the record must carry,
        // and the state it must name — absent on the refusal, a refused packet
        // being one the tracker keeps no state for and so names no flow of.
        let script = [
            (
                0usize,
                base.with(segment(0x02, CLIENT_ISN, 0)),
                (
                    wire::TapEvent::FlowOpened,
                    Some(wire::TapFlowState::SynSent),
                ),
            ),
            (
                1,
                base.reversed()
                    .with(segment(0x12, SERVER_ISN, client_after_syn)),
                (
                    wire::TapEvent::FlowAdvanced,
                    Some(wire::TapFlowState::SynReceived),
                ),
            ),
            (
                0,
                base.with(segment(0x10, client_after_syn, server_after_syn)),
                (
                    wire::TapEvent::FlowAdvanced,
                    Some(wire::TapFlowState::Established),
                ),
            ),
            // A segment a gibibyte past anything the peer authorised: the tracker
            // refuses it, so it never reaches the filter and no rule is named.
            (
                0,
                base.with(segment(
                    0x10,
                    client_after_syn.wrapping_add(1 << 30),
                    server_after_syn,
                )),
                (wire::TapEvent::FlowRefused, None),
            ),
            // The close, both halves and its acknowledgement.
            (
                0,
                base.with(segment(0x11, client_after_syn, server_after_syn)),
                (
                    wire::TapEvent::FlowAdvanced,
                    Some(wire::TapFlowState::FinWait),
                ),
            ),
            (
                1,
                base.reversed()
                    .with(segment(0x11, server_after_syn, client_after_fin)),
                (
                    wire::TapEvent::FlowAdvanced,
                    Some(wire::TapFlowState::Closing),
                ),
            ),
            (
                0,
                base.with(segment(0x10, client_after_fin, server_after_fin)),
                (
                    wire::TapEvent::FlowClosed,
                    Some(wire::TapFlowState::TimeWait),
                ),
            ),
        ];

        for (step, (which, spec, _)) in script.iter().enumerate() {
            let regions = if *which == 0 { &forward } else { &back };
            let bytes = spec.build();
            receive(
                &regions.pool,
                &mut owners[*which],
                &mut producers[*which],
                &bytes,
            )
            .expect("a full pool has buffers");
            assert_eq!(
                stages[*which].poll(
                    &mut pipeline,
                    Configuration::new(1, &*ROUTER, &ALLOW_ALL),
                    &mut Tracking::new(&mut flows, lfw_clock::Monotonic::BOOT),
                    Ownership::Owned,
                    Some(&mut tap),
                ),
                1,
                "step {step}: the descriptor must travel on"
            );
        }

        let read = ring.drain();
        assert_eq!(
            read.len(),
            script.len(),
            "one observation per decided frame"
        );
        // One conversation, so one identity: every record names the same slot and
        // the same occupant of it, which is what lets a reader fold the events
        // into a single connection.
        let identity = read
            .first()
            .and_then(|(checked, _)| checked.flow)
            .map(|flow| (flow.slot, flow.generation))
            .expect("the opening record names the flow it opened");
        for (step, ((checked, _), (_, _, (event, state)))) in read.iter().zip(&script).enumerate() {
            assert_eq!(checked.event, Some(*event), "step {step}: the event");
            assert_eq!(
                checked.flow.map(|flow| flow.state),
                *state,
                "step {step}: the state"
            );
            if let Some(flow) = checked.flow {
                assert_eq!(
                    (flow.slot, flow.generation),
                    identity,
                    "step {step}: a different conversation"
                );
            }
            // Under a rule that accepts everything, the opening is the one packet
            // the filter was consulted about — every other step was decided by the
            // tracker, and a rule on one of those would credit a hit to a rule
            // that never ran.
            assert_eq!(
                checked.rule.map(wire::TapRule::position),
                (*event == wire::TapEvent::FlowOpened).then_some(0),
                "step {step}: the rule"
            );
        }
        // The refused segment is the one record whose verdict is a drop, and the
        // reason is the tracker's own.
        let refused: Vec<_> = read
            .iter()
            .filter(|(checked, _)| checked.event == Some(wire::TapEvent::FlowRefused))
            .map(|(checked, _)| checked.outcome)
            .collect();
        assert_eq!(
            refused,
            std::vec![wire::TapOutcome::Dropped(
                wire::TapDropReason::FlowOutOfWindow
            )]
        );
        assert_eq!(flows.len(), 1, "the script left more than one conversation");
    }

    /// A packet on a conversation already accounted for carries no event, and a
    /// packet the *filter* refused carries the event that says which of its two
    /// refusals it was.
    ///
    /// The first is what keeps the connection history's rate bounded by
    /// admissions rather than by traffic; the second is what makes a deny
    /// attributable to a rule, and a fallthrough distinguishable from it.
    #[test]
    fn traffic_on_a_known_flow_carries_no_event_and_a_denied_opening_names_its_rule() {
        let regions = Regions::new();
        let ring = TapRing::new();
        let mut tap = Tap::attach(&ring.records, &ring.consume);
        let mut owner = PoolOwner::attach(&regions.returns);
        let mut rx_in = regions.rings.rx.producer();
        let mut stage = RouteStage::attach(&regions.rings, &regions.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut flows = Box::new(ApplianceTestFlows::new());

        // The same datagram twice under a rule that accepts it: the first opens
        // the conversation, and the second is a retransmission that moves
        // nothing, so it belongs to the capture alone.
        let spec = FrameSpec::a_to_b();
        for rules in [&*ALLOW_ALL, &*ALLOW_ALL, &*DROP_ALL, &*ALLOW_ALL] {
            let bytes = spec.build();
            receive(&regions.pool, &mut owner, &mut rx_in, &bytes)
                .expect("a full pool has buffers");
            assert_eq!(
                stage.poll(
                    &mut pipeline,
                    Configuration::new(1, &*ROUTER, rules),
                    &mut Tracking::new(&mut flows, lfw_clock::Monotonic::BOOT),
                    Ownership::Owned,
                    Some(&mut tap),
                ),
                1
            );
        }

        let read = ring.drain();
        let events: Vec<_> = read.iter().map(|(checked, _)| checked.event).collect();
        assert_eq!(
            events,
            std::vec![
                Some(wire::TapEvent::FlowOpened),
                // Held: the datagram is the same one, in the same direction, so
                // the flow stays one-way and its state does not move.
                None,
                // The dropping ruleset never sees a new conversation — the flow
                // is already open, so the tracker settles it in front of the
                // filter and the rule is not consulted.
                None,
                None,
            ]
        );
        // Every record still carries the conversation and its verdict, which is
        // what the capture is for.
        for (checked, _) in &read {
            assert!(checked.flow.is_some());
            assert_eq!(checked.outcome, wire::TapOutcome::Forwarded);
        }
    }

    /// A ruleset that admits an opening UDP conversation and, second, the ICMP
    /// errors an existing conversation is the reason for.
    ///
    /// Two rules rather than one `tracking="any"`, because that is what the
    /// document an operator writes looks like: admission and related traffic are
    /// separate decisions, and a policy that meant to allow one and not the other
    /// must be able to say so.
    static ALLOW_OPENING_AND_RELATED: LazyLock<pipeline::Ruleset> = LazyLock::new(|| {
        let opening = pipeline::Rule {
            ingress: None,
            egress: None,
            source: None,
            destination: None,
            protocol: Some(Protocol::UDP),
            source_port: None,
            destination_port: None,
            icmp_type: None,
            tracking: Some(pipeline::Tracked::Opening),
            action: pipeline::RuleAction::Accept,
        };
        let related = pipeline::Rule {
            protocol: Some(Protocol::ICMP),
            tracking: Some(pipeline::Tracked::Related),
            ..opening
        };
        pipeline::Ruleset::build([opening, related].into_iter())
            .expect("two rules are inside any capacity")
    });

    /// The same, without the related rule: a document that admits conversations and
    /// says nothing about the errors reporting on them.
    static ALLOW_OPENING_ONLY: LazyLock<pipeline::Ruleset> = LazyLock::new(|| {
        pipeline::Ruleset::build(core::iter::once(pipeline::Rule {
            ingress: None,
            egress: None,
            source: None,
            destination: None,
            protocol: Some(Protocol::UDP),
            source_port: None,
            destination_port: None,
            icmp_type: None,
            tracking: Some(pipeline::Tracked::Opening),
            action: pipeline::RuleAction::Accept,
        }))
        .expect("one rule is inside any capacity")
    });

    /// **A genuinely related ICMP error is the filter's to decide, and the record
    /// says which way it went.**
    ///
    /// The error quotes a real datagram of a conversation the table holds, so the
    /// tracker's own corroboration accepts it — which settles where it would go and
    /// must not settle whether it may. Under a document with no rule about related
    /// traffic it is refused by the default deny; under one that admits it, it is
    /// forwarded.
    ///
    /// The denial is the half that has to reach the **connection history**: an error
    /// opens no conversation, so its transition is `Held`, and a filter decision on a
    /// `Held` frame produced no event at all until the arm that names one was
    /// written. A refusal nothing records is a refusal an operator cannot see.
    ///
    /// **Two stages, one table**, which is the forwarder's own arrangement and the
    /// only one this can be driven through: an error travels from a router back to
    /// the sender of the datagram it quotes, so it arrives on the port that
    /// datagram left by.
    #[test]
    fn a_related_icmp_error_is_decided_by_the_filter_and_the_record_names_the_decision() {
        let opening = FrameSpec::a_to_b();
        // Addressed to A and quoting the datagram A sent to B, which is the
        // agreement `lfw_flow::icmp` refuses a forged quote by: an error is only
        // about a datagram that was travelling away from the party being told.
        let error = opening.reversed().with(Transport_::Icmp {
            message_type: 3,
            quote: Quote::Datagram {
                source: HOST_A,
                destination: HOST_B,
                source_port: opening.source_port,
                destination_port: opening.destination_port,
            },
        });

        for (rules, forwarded, event) in [
            (
                &*ALLOW_OPENING_ONLY,
                false,
                Some(wire::TapEvent::PolicyNoMatch),
            ),
            (&*ALLOW_OPENING_AND_RELATED, true, None),
        ] {
            let regions = [Regions::new(), Regions::new()];
            let ring = TapRing::new();
            let mut tap = Tap::attach(&ring.records, &ring.consume);
            let mut owners = [
                PoolOwner::attach(&regions[0].returns),
                PoolOwner::attach(&regions[1].returns),
            ];
            let mut producers = [
                regions[0].rings.rx.producer(),
                regions[1].rings.rx.producer(),
            ];
            let mut stages = [
                RouteStage::attach(&regions[0].rings, &regions[0].pool, PORT0, PORT1),
                RouteStage::attach(&regions[1].rings, &regions[1].pool, PORT1, PORT0),
            ];
            let mut pipeline = Pipeline::new();
            let mut flows = Box::new(ApplianceTestFlows::new());

            // The conversation first, on port 0, so the error has a flow to be
            // related to; then the error itself, on port 1, which is where a
            // report about that datagram comes back from.
            for (which, spec) in [(0usize, &opening), (1, &error)] {
                let bytes = spec.build();
                receive(
                    &regions[which].pool,
                    &mut owners[which],
                    &mut producers[which],
                    &bytes,
                )
                .expect("a full pool has buffers");
                assert_eq!(
                    stages[which].poll(
                        &mut pipeline,
                        Configuration::new(1, &*ROUTER, rules),
                        &mut Tracking::new(&mut flows, lfw_clock::Monotonic::BOOT),
                        Ownership::Owned,
                        Some(&mut tap),
                    ),
                    1
                );
            }

            let read = ring.drain();
            let (opened, related) = (&read[0].0, &read[1].0);
            assert_eq!(
                opened.event,
                Some(wire::TapEvent::FlowOpened),
                "the conversation the error reports on was not opened"
            );
            assert_eq!(
                related.flow.and_then(|flow| flow.classification),
                Some(wire::TapClassification::Related),
                "the quote did not name the flow, so this proves nothing about policy"
            );
            assert_eq!(
                related.outcome == wire::TapOutcome::Forwarded,
                forwarded,
                "the error's verdict is not the one the policy states"
            );
            assert_eq!(
                related.event, event,
                "the record does not name what the filter decided"
            );
        }
    }

    /// The two filter refusals as the tap records them: a rule that says drop,
    /// and no rule at all.
    #[test]
    fn the_filters_two_refusals_are_distinguishable_in_the_record() {
        for (rules, expected, rule) in [
            (&*DROP_ALL, wire::TapEvent::PolicyDenied, Some(0u16)),
            (
                &pipeline::Ruleset::EMPTY,
                wire::TapEvent::PolicyNoMatch,
                None,
            ),
        ] {
            let regions = Regions::new();
            let ring = TapRing::new();
            let mut tap = Tap::attach(&ring.records, &ring.consume);
            let mut owner = PoolOwner::attach(&regions.returns);
            let mut rx_in = regions.rings.rx.producer();
            let mut stage = RouteStage::attach(&regions.rings, &regions.pool, PORT0, PORT1);
            let mut pipeline = Pipeline::new();

            let bytes = FrameSpec::a_to_b().build();
            receive(&regions.pool, &mut owner, &mut rx_in, &bytes)
                .expect("a full pool has buffers");
            assert_eq!(
                poll!(
                    stage,
                    &mut pipeline,
                    Configuration::new(1, &*ROUTER, rules),
                    Some(&mut tap)
                ),
                1
            );

            let read = ring.drain();
            let (checked, _) = read.first().expect("the frame was decided on");
            assert_eq!(checked.event, Some(expected));
            assert_eq!(checked.rule.map(wire::TapRule::position), rule);
            // The flow the opening packet took is named even though it has been
            // withdrawn, so a reader can see the slot was given back rather than
            // held by a conversation the policy refused.
            assert!(checked.flow.is_some());
        }
    }

    /// An admission or routing refusal carries no event: no conversation was
    /// involved and no policy was consulted, so it belongs to the capture alone.
    #[test]
    fn a_routing_refusal_carries_a_verdict_and_no_event() {
        let regions = Regions::new();
        let ring = TapRing::new();
        let mut tap = Tap::attach(&ring.records, &ring.consume);
        let mut owner = PoolOwner::attach(&regions.returns);
        let mut rx_in = regions.rings.rx.producer();
        let mut stage = RouteStage::attach(&regions.rings, &regions.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();

        let bytes = FrameSpec {
            ttl: 1,
            ..FrameSpec::a_to_b()
        }
        .build();
        receive(&regions.pool, &mut owner, &mut rx_in, &bytes).expect("a full pool has buffers");
        assert_eq!(poll!(stage, &mut pipeline, running(), Some(&mut tap)), 1);

        let read = ring.drain();
        let (checked, _) = read.first().expect("the frame was decided on");
        assert_eq!(checked.event, None);
        assert_eq!(checked.flow, None);
        assert_eq!(checked.rule, None);
        assert_eq!(
            checked.outcome,
            wire::TapOutcome::Dropped(wire::TapDropReason::TtlExpired)
        );
    }

    /// The three outcomes a filtering appliance owes an operator, driven through
    /// the same poll the domain runs and read back off the shard it publishes:
    /// a packet a rule allowed, a packet a rule denied, and a packet no rule was
    /// about.
    ///
    /// Asserted through [`policy_sample`] rather than off the counters directly,
    /// because the mapping is the part a scrape depends on: a `denied` total in
    /// the `accepted` slot, or a hit block published at the wrong offset, reports
    /// one rule's traffic under another rule's name and nothing about the
    /// counters themselves would notice.
    #[test]
    fn the_filters_three_outcomes_reach_three_different_places_in_the_shard() {
        /// The port the accepting rule names, which is [`FrameSpec::a_to_b`]'s.
        const ALLOWED: u16 = 5000;
        /// The port the dropping rule names.
        const BLOCKED: u16 = 5001;
        /// A port neither rule names, so the frame falls past both to the
        /// default deny.
        const UNMATCHED: u16 = 5002;

        /// The dropping rule first: a rule's place in the document is its
        /// precedence, and its position is the slot its counter occupies.
        fn port_rule(port: u16, action: pipeline::RuleAction) -> pipeline::Rule {
            pipeline::Rule {
                ingress: None,
                egress: None,
                source: None,
                destination: None,
                protocol: Some(Protocol::UDP),
                source_port: None,
                destination_port: Some(pipeline::PortRange {
                    low: port,
                    high: port,
                }),
                icmp_type: None,
                tracking: None,
                action,
            }
        }
        let rules = pipeline::Ruleset::build(
            [
                port_rule(BLOCKED, pipeline::RuleAction::Drop),
                port_rule(ALLOWED, pipeline::RuleAction::Accept),
            ]
            .into_iter(),
        )
        .expect("two rules are inside any capacity");

        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let mut sent = Vec::new();
        for port in [ALLOWED, BLOCKED, UNMATCHED] {
            let spec = FrameSpec {
                destination_port: port,
                ..FrameSpec::a_to_b()
            };
            let frame = spec.build();
            receive(&r.pool, &mut owner, &mut rx_in, &frame).expect("a full pool has buffers");
            sent.push(frame);
        }
        assert_eq!(
            poll!(
                stage,
                &mut pipeline,
                Configuration::new(1, &ROUTER, &rules),
                None
            ),
            sent.len(),
            "every descriptor travels on, whatever the verdict"
        );

        // One forwarded and two discarded, which is the wire's own account of
        // the same three decisions.
        let mut verdicts = Vec::new();
        transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, _| {
            verdicts.push(Verdict::from_bits(descriptor.verdict));
        });
        assert_eq!(
            verdicts,
            [
                Some(Verdict::Transmit),
                Some(Verdict::Discard),
                Some(Verdict::Discard)
            ]
        );

        // The two refusals are told apart by reason, which is what makes a
        // policy denial and the default deny two facts rather than one.
        let drops = &stage.counters().drops;
        assert_eq!(drops.get(DropReason::PolicyDenied), 1);
        assert_eq!(drops.get(DropReason::NoPolicyMatch), 1);
        assert_eq!(drops.total(), 2);
        assert_eq!(stage.counters().forwarded, 1);

        // The datagram's own length, which is what a byte total is stated in.
        let datagram = u64::from((IPV4_HEADER_LEN + UDP_HEADER_LEN + 24) as u16);
        let published = policy_sample(pipeline.policy_counters());
        assert_eq!(published.accepted_packets, 1);
        assert_eq!(published.accepted_bytes, datagram);
        assert_eq!(published.denied_packets, 2);
        assert_eq!(published.denied_bytes, 2 * datagram);

        // Each rule's own slot, and nothing at the positions the policy did not
        // declare — the default deny is not a rule and has no counter of its own.
        assert_eq!(published.rule_hits[0], 1, "the dropping rule at position 0");
        assert_eq!(
            published.rule_hits[1], 1,
            "the accepting rule at position 1"
        );
        assert!(
            published.rule_hits[2..].iter().all(|hits| *hits == 0),
            "a position no rule occupies counted something"
        );

        assert_eq!(owner.reclaim(), sent.len());
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_frame_that_is_not_a_routable_packet_is_discarded_and_handed_back() {
        // Arbitrary bytes on the wire: not IPv4, not long enough, and a frame
        // whose IPv4 header contradicts itself. None of them is attributable to
        // a routing decision, so none of them may be counted as one.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let mut truncated_ip = FrameSpec::a_to_b().build();
        truncated_ip.truncate(ETHERNET_HEADER_LEN + 4);
        let mut bad_checksum = FrameSpec::a_to_b().build();
        bad_checksum[ETHERNET_HEADER_LEN + 10] ^= 0xff;
        let unroutable = [
            std::vec![0xAA; 64],
            std::vec![0x00; 10],
            truncated_ip,
            bad_checksum,
        ];
        for frame in &unroutable {
            receive(&r.pool, &mut owner, &mut rx_in, frame).expect("a full pool has buffers");
        }

        assert_eq!(
            poll!(stage, &mut pipeline, running(), None),
            unroutable.len()
        );
        let unparsable = stage.counters().unparsable;
        assert_eq!(unparsable.total(), unroutable.len() as u64);
        // And each under the class an operator would act on: a frame of
        // arbitrary bytes is an EtherType this appliance does not route, a ten-byte
        // frame carries no headers at all, four bytes past L2 carry no IPv4
        // header, and a flipped checksum byte is corruption on the path.
        assert_eq!(unparsable.get(ParseFailure::Ethernet), 1);
        assert_eq!(unparsable.get(ParseFailure::FrameTooShort), 2);
        assert_eq!(unparsable.get(ParseFailure::Ipv4Checksum), 1);
        assert_eq!(unparsable.get(ParseFailure::Ipv4), 0);
        assert_eq!(
            stage.counters().drops.total(),
            0,
            "no routing decision was made"
        );
        assert_eq!(stage.counters().forwarded, 0);

        let returned = transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, _| {
            assert_eq!(
                Verdict::from_bits(descriptor.verdict),
                Some(Verdict::Discard)
            );
        });
        assert_eq!(returned, unroutable.len());
        assert_eq!(owner.reclaim(), unroutable.len());
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_route_out_of_a_port_this_stage_is_not_wired_to_is_discarded() {
        // A stage is a fixed cross-connect. This one is wired ingress port 0 to
        // egress port 0, so the pipeline's verdict — out of port 1 — names a
        // ring this stage does not hold, and carrying it out would put the
        // frame back on the subnet it arrived from.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT0);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();

        let sent = FrameSpec::a_to_b().build();
        receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");

        assert_eq!(poll!(stage, &mut pipeline, running(), None), 1);
        assert_eq!(stage.counters().misrouted, 1);
        assert_eq!(stage.counters().forwarded, 0);
        assert_eq!(
            stage.counters().drops.total(),
            0,
            "the pipeline had no objection; this stage did"
        );
        let handed_on = tx_out.try_dequeue().expect("the buffer must travel back");
        assert_eq!(
            Verdict::from_bits(handed_on.verdict),
            Some(Verdict::Discard)
        );
    }

    /// The tap ring is far larger than a stack frame, so every test heaps it.
    struct TapRing {
        records: Box<wire::TapRecords>,
        consume: Box<wire::TapConsume>,
    }

    impl TapRing {
        fn new() -> Self {
            Self {
                records: Box::new(wire::TapRecords::zero()),
                consume: Box::new(wire::TapConsume::zero()),
            }
        }

        fn drain(&self) -> Vec<(wire::CheckedTap, Vec<u8>)> {
            let mut reader = self.consume.reader(&self.records);
            let mut into = [0u8; wire::TAP_SNAP_LEN];
            let mut read = Vec::new();
            reader.drain(usize::MAX, &mut into, |one| {
                let (checked, bytes) = one.expect("this producer writes decodable annotations");
                read.push((checked, bytes.to_vec()));
            });
            read
        }
    }

    #[test]
    fn a_tapped_pass_records_one_observation_per_decided_frame_as_it_arrived() {
        // The whole of Part A in one run: a forwarded frame and a dropped one,
        // each recorded once, under the verdict the stage reached and with the
        // bytes the wire carried — not the rewritten headers the next hop sees.
        let r = Regions::new();
        let ring = TapRing::new();
        let mut tap = Tap::attach(&ring.records, &ring.consume);
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();

        let forwarded = FrameSpec::a_to_b().build();
        let dropped = FrameSpec {
            ttl: 1,
            ..FrameSpec::a_to_b()
        }
        .build();
        for frame in [&forwarded, &dropped] {
            receive(&r.pool, &mut owner, &mut rx_in, frame).expect("a full pool has buffers");
        }

        assert_eq!(poll!(stage, &mut pipeline, running(), Some(&mut tap)), 2);
        assert_eq!(stage.counters().forwarded, 1);

        let read = ring.drain();
        assert_eq!(read.len(), 2, "one observation per decided frame");
        let (first, first_bytes) = &read[0];
        assert_eq!(first.outcome, wire::TapOutcome::Forwarded);
        assert_eq!(first.interface_id, PORT0.0);
        assert_eq!(first.direction, Some(wire::TapDirection::Inbound));
        assert_eq!(
            first.generation, 1,
            "the generation `running` decides under"
        );
        assert_eq!(first.original_len, forwarded.len() as u32);
        assert_eq!(
            first_bytes.as_slice(),
            forwarded.as_slice(),
            "the recorded bytes are the frame as it arrived"
        );
        let (second, second_bytes) = &read[1];
        assert_eq!(
            second.outcome,
            wire::TapOutcome::Dropped(wire::TapDropReason::TtlExpired)
        );
        assert_eq!(second_bytes.as_slice(), dropped.as_slice());
        // Identities are per appliance and monotone, which is what relates two
        // observations of one frame once the egress one is recorded too.
        assert_eq!(second.packet_id, first.packet_id + 1);
        assert_eq!(tap.counters().observed, 2);
        assert_eq!(tap.counters().dropped, 0);
    }

    #[test]
    fn a_frame_no_routing_decision_was_reached_about_is_counted_and_not_recorded() {
        // `wire::TapDropReason` mirrors `pipeline::DropReason` exactly, so a
        // frame the pipeline never saw has no honest encoding — and inventing one
        // would put a claim in an artifact that is evidence.
        let r = Regions::new();
        let ring = TapRing::new();
        let mut tap = Tap::attach(&ring.records, &ring.consume);
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();

        receive(&r.pool, &mut owner, &mut rx_in, &std::vec![0xAA; 64])
            .expect("a full pool has buffers");
        assert_eq!(poll!(stage, &mut pipeline, running(), Some(&mut tap)), 1);

        assert_eq!(stage.counters().unparsable.total(), 1);
        assert_eq!(tap.counters().observed, 0);
        assert!(ring.drain().is_empty());
    }

    #[test]
    fn a_full_tap_ring_costs_frames_nothing() {
        // The rule the whole tap rests on: anyone who can send packets must not
        // be able to stall forwarding by outrunning the recorder's medium.
        let r = Regions::new();
        let ring = TapRing::new();
        let mut tap = Tap::attach(&ring.records, &ring.consume);
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        // Fill the tap to refusal before a frame is ever offered, so every one
        // of the frames below is decided against a ring with no slot left.
        let filler = [0u8; 16];
        for _ in 0..ring.records.capacity() {
            tap.observe(Observation {
                timestamp: 0,
                interface_id: 0,
                decision: wire::TapDecision {
                    outcome: wire::TapOutcome::Forwarded,
                    direction: Some(wire::TapDirection::Inbound),
                    generation: 0,
                    flow: None,
                    rule: None,
                    event: None,
                },
                frame: &filler,
            });
        }

        let sent = FrameSpec::a_to_b().build();
        let offered = 8;
        let mut forwarded = 0;
        for _ in 0..offered {
            receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
            forwarded += poll!(stage, &mut pipeline, running(), Some(&mut tap));
            transmit(&r.pool, &mut tx_out, &mut free_in, |_, _| {});
            owner.reclaim();
        }

        assert_eq!(forwarded, offered, "no frame was held back by a full tap");
        assert_eq!(stage.counters().forwarded, offered as u64);
        assert_eq!(tap.counters().dropped, offered as u64);
        assert_eq!(owner.owned(), POOL_BUFFERS, "no buffer was lost either");
    }

    #[test]
    fn a_snapshot_that_cannot_be_taken_names_what_it_refused() {
        // Both refusals `snapshot` can answer with, neither of which
        // `RouteStage::poll` can reach: `descriptor_in_bounds` rules out the
        // span, and the stage's own storage is a whole buffer. They exist
        // because the alternative to answering is a truncated frame that still
        // parses — a decision made on bytes that are not the packet.
        let r = Regions::new();
        let mut short = [0u8; 8];
        assert_eq!(
            snapshot(
                &r.pool,
                &Descriptor::new(0, 0, 16, Verdict::Transmit),
                &mut short
            ),
            Err(CopyOutError::DestinationTooSmall {
                len: 16,
                capacity: 8
            })
        );

        let mut whole = [0u8; BUFFER_SIZE];
        assert_eq!(
            snapshot(
                &r.pool,
                &Descriptor::new(POOL_BUFFERS as u32, 0, 4, Verdict::Transmit),
                &mut whole
            ),
            Err(CopyOutError::SpanOutsideBuffer {
                index: POOL_BUFFERS,
                offset: 0,
                len: 4
            })
        );
    }

    #[test]
    fn a_write_back_the_pool_refuses_discards_the_frame_rather_than_transmitting_it() {
        // The header window is written at the descriptor's own offset, so a
        // span the descriptor validator passes can still leave no room for it.
        // Transmitting anyway would put the frame on the wire with the MACs and
        // the TTL it arrived with, which is a loop rather than a hop.
        let r = Regions::new();
        let mut counters = RouteCounters::default();
        let scratch = [0u8; BUFFER_SIZE];
        let no_room = Descriptor::new(0, BUFFER_SIZE as u32 - 4, 4, Verdict::Transmit);
        assert!(
            descriptor_in_bounds(&no_room),
            "the span itself is in bounds"
        );
        assert_eq!(
            write_back(&r.pool, &no_room, &scratch, &mut counters),
            Verdict::Discard
        );
        assert_eq!(counters.writeback_failed, 1);
    }

    #[test]
    fn single_threaded_pipeline_round_trip_forwards_both_frames_in_order() {
        // The three-PD routed chain in one thread: receive two frames, route
        // them, transmit them, then reclaim — full pool ownership must return
        // and both payloads must survive intact and in order.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let frames: Vec<Vec<u8>> = [7usize, 8]
            .into_iter()
            .map(|payload_len| {
                FrameSpec {
                    payload_len,
                    ..FrameSpec::a_to_b()
                }
                .build()
            })
            .collect();
        for frame in &frames {
            assert!(receive(&r.pool, &mut owner, &mut rx_in, frame).is_some());
        }
        assert_eq!(owner.owned(), POOL_BUFFERS - 2);

        assert_eq!(poll!(stage, &mut pipeline, running(), None), 2);

        let mut seen = Vec::new();
        let transmitted = transmit(&r.pool, &mut tx_out, &mut free_in, |_, bytes| {
            seen.push(bytes[REWRITTEN_HEADER_LEN..].to_vec());
        });
        assert_eq!(transmitted, 2);
        let expected: Vec<Vec<u8>> = frames
            .iter()
            .map(|frame| frame[REWRITTEN_HEADER_LEN..].to_vec())
            .collect();
        assert_eq!(seen, expected, "payloads must arrive intact and in order");

        // Buffers are back on the free ring; reclaiming restores full ownership.
        assert_eq!(owner.reclaim(), 2);
        assert_eq!(owner.owned(), POOL_BUFFERS);
        assert_eq!(owner.counters(), PoolCounters::default());
    }

    /// The lent set names which buffers are out, and differencing it across a
    /// `reclaim` names which returns that call accepted — the question its count
    /// cannot answer. A caller keeping its own record of ownership needs exactly
    /// this: with only a number, a legitimate return it did not queue itself is
    /// indistinguishable from a forged one.
    #[test]
    fn the_lent_set_names_which_returns_a_reclaim_accepted() {
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut free_in = r.returns.free.producer();

        assert_eq!(owner.lent(), [false; POOL_BUFFERS], "nothing starts lent");

        let mut lent = Vec::new();
        for _ in 0..3 {
            let buffer = owner.alloc().expect("a full pool has buffers");
            let index = buffer.index();
            owner
                .lend(&mut rx_in, buffer, 0, 64, Verdict::Transmit)
                .expect("the ring is empty");
            lent.push(index);
        }
        for index in &lent {
            assert!(owner.lent()[*index as usize], "index {index} is out");
        }

        // Return the middle one, plus a forged index and a replay of a buffer
        // that is not out: only the real return may move a flag.
        let real = lent[1];
        for descriptor in [real, POOL_BUFFERS as u32, lent[0].wrapping_add(32)] {
            free_in
                .try_enqueue(Descriptor::new(descriptor, 0, 0, Verdict::Transmit))
                .expect("the free ring has room");
        }
        let before = owner.lent();
        assert_eq!(owner.reclaim(), 1, "one of the three returns is legitimate");
        let after = owner.lent();

        let accepted: Vec<u32> = (0..POOL_BUFFERS as u32)
            .filter(|index| before[*index as usize] && !after[*index as usize])
            .collect();
        assert_eq!(
            accepted,
            std::vec![real],
            "the difference must name exactly the return that was accepted"
        );
        // And nothing is ever added by a reclaim, which is what makes the
        // difference a complete answer rather than half of one.
        for index in 0..POOL_BUFFERS {
            assert!(
                before[index] || !after[index],
                "a reclaim lent a buffer out"
            );
        }
    }

    #[test]
    fn lend_reports_a_full_ring_and_hands_the_token_back_unlent() {
        // `lend` is a thin publish onto the ring; when the ring is full it must
        // return the token so the caller keeps the buffer, and must not record
        // it as lent — nothing was handed over.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();

        // The ring is sized above the pool, so fill it with bare descriptors
        // first; only then can a real lend be refused.
        for _ in 0..r.rings.rx.capacity() {
            rx_in.try_enqueue(Descriptor::ZERO).unwrap();
        }
        let buffer = owner.alloc().expect("a full pool has buffers");
        let index = buffer.index();
        let Err(returned) = owner.lend(&mut rx_in, buffer, 0, 0, Verdict::Transmit) else {
            panic!("a full ring must refuse the lend");
        };
        assert_eq!(returned.index(), index);
        owner.release(returned);
        assert_eq!(owner.owned(), POOL_BUFFERS);

        // Having never been lent, that index cannot be returned by the peer.
        let mut free_in = r.returns.free.producer();
        free_in
            .try_enqueue(Descriptor::new(index, 0, 0, Verdict::Transmit))
            .expect("the free ring is empty");
        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_not_lent, 1);
    }

    #[test]
    fn a_forged_out_of_range_return_is_dropped_and_counted() {
        // The critical path: a peer injects an index that never named a buffer.
        // Accepting it put a forged index on the free stack, `alloc` handed it
        // out, and `buffer_paddr` turned it into a DMA-writable address outside
        // the region.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut free_in = r.returns.free.producer();
        for forged in [POOL_BUFFERS as u32, 999, u32::MAX] {
            free_in
                .try_enqueue(Descriptor::new(forged, 0, 0, Verdict::Transmit))
                .expect("the free ring has room");
        }

        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_not_lent, 3);
        assert_eq!(owner.counters().reclaim_refused, 0);
        // The ledger is untouched and still hands out only real buffers.
        assert_eq!(owner.owned(), POOL_BUFFERS);
        let mut seen = BTreeSet::new();
        while let Some(buffer) = owner.alloc() {
            assert!((buffer.index() as usize) < POOL_BUFFERS);
            assert!(seen.insert(buffer.index()), "an index was handed out twice");
            drop(buffer);
        }
        assert_eq!(seen.len(), POOL_BUFFERS);
    }

    #[test]
    fn a_duplicate_return_is_accepted_once_and_then_refused() {
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut free_in = r.returns.free.producer();

        let buffer = owner.alloc().expect("a full pool has buffers");
        let index = buffer.index();
        owner
            .lend(&mut rx_in, buffer, 0, 0, Verdict::Transmit)
            .expect("the ring is empty");
        for _ in 0..3 {
            free_in
                .try_enqueue(Descriptor::new(index, 0, 0, Verdict::Transmit))
                .expect("the free ring has room");
        }

        assert_eq!(owner.reclaim(), 1, "only the first return is legitimate");
        assert_eq!(owner.counters().reclaim_not_lent, 2);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_return_of_a_buffer_still_held_by_this_domain_is_refused() {
        // The hole the lent set closes: the buffer is outstanding — posted to
        // our own NIC as a DMA target — so the ledger alone would accept the
        // return, free it, and let `alloc` hand the live DMA target to a second
        // owner.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut free_in = r.returns.free.producer();

        let posted = owner.alloc().expect("a full pool has buffers");
        let index = posted.index();
        free_in
            .try_enqueue(Descriptor::new(index, 0, 0, Verdict::Transmit))
            .expect("the free ring is empty");

        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_not_lent, 1);
        assert_eq!(owner.owned(), POOL_BUFFERS - 1);
        // We still hold it, and returning it ourselves still works.
        owner.release(posted);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_ledger_that_disagrees_with_the_lent_set_is_counted_not_faulted() {
        // `reclaim_refused` is unreachable through the public API, since a lent
        // index is by construction outstanding. Corrupt the private lent set
        // directly — the only way to reach it — to prove the disagreement
        // surfaces as a counted drop rather than a panic or a freed buffer.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut free_in = r.returns.free.producer();
        owner.lent[3] = true;
        free_in
            .try_enqueue(Descriptor::new(3, 0, 0, Verdict::Transmit))
            .expect("the free ring is empty");

        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_refused, 1);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn an_over_return_beyond_the_ring_capacity_is_dropped_not_panicked() {
        // A peer fills the whole `free` ring with returns of buffers that were
        // never lent — more of them than the pool has buffers. The old code
        // asserted on the first one.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut free_in = r.returns.free.producer();
        let mut offered = 0u64;
        while free_in
            .try_enqueue(Descriptor::new(
                offered as u32 % POOL_BUFFERS as u32,
                0,
                0,
                Verdict::Transmit,
            ))
            .is_ok()
        {
            offered += 1;
        }
        assert!(offered > POOL_BUFFERS as u64);

        assert_eq!(owner.reclaim(), 0);
        assert_eq!(owner.counters().reclaim_not_lent, offered);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn reclaim_is_bounded_when_a_peer_keeps_the_free_ring_non_empty() {
        // A forged `tail` makes the free ring look permanently non-empty; the
        // domain must return from `reclaim` and get on with servicing its NIC.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        for round in 0..8u32 {
            forge_cursors(&r.returns.free, 0, round.wrapping_mul(29).wrapping_add(5));
            let reclaimed = owner.reclaim();
            assert!(reclaimed <= DRAIN_LIMIT);
        }
        // Every phantom descriptor read out of an untouched ring names buffer 0,
        // which was never lent, so all of them were rejected.
        assert!(owner.counters().reclaim_not_lent > 0);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn a_lapping_peer_cursor_redelivers_returns_that_the_lent_set_refuses() {
        // The upper half of the division of responsibility `queue`'s
        // `a_forged_tail_that_laps_the_ring_does_redeliver_and_this_layer_permits_it`
        // states the lower half of. That test proves the ring *will* hand a
        // descriptor over twice when a peer rewinds its published cursor far
        // enough to lap the consumer; this one proves the second delivery buys
        // the peer nothing, because a return is accepted only for an index that
        // is currently lent, and the first delivery cleared that bit.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut free_in = r.returns.free.producer();

        // Lend three buffers and let the transmitting peer return them
        // legitimately, which is what advances the owner's private `head` to 3
        // and clears the three lent bits.
        let mut lent = Vec::new();
        for _ in 0..3 {
            let buffer = owner.alloc().expect("a full pool has buffers");
            lent.push(buffer.index());
            owner
                .lend(&mut rx_in, buffer, 0, 0, Verdict::Transmit)
                .expect("the ring is empty");
        }
        for index in &lent {
            free_in
                .try_enqueue(Descriptor::new(*index, 0, 0, Verdict::Transmit))
                .expect("the free ring has room");
        }
        assert_eq!(owner.reclaim(), 3, "the legitimate returns are accepted");
        assert_eq!(owner.owned(), POOL_BUFFERS);
        assert_eq!(owner.counters(), PoolCounters::default());

        // Now the lap. The owner's private head is 3; a published tail of 2
        // keeps the ring looking non-empty until head walks all the way round
        // to it, replaying every slot on the way — the three real returns
        // included.
        forge_cursors(&r.returns.free, 0, 2);

        // Not one is accepted a second time, and each refusal is attributed to
        // the peer rather than to this domain's own bookkeeping.
        assert_eq!(owner.reclaim(), 0, "a redelivered return was accepted");
        assert_eq!(
            owner.counters().reclaim_not_lent,
            (RING_SLOTS - 1) as u64,
            "every slot the lap replayed must be refused as not lent"
        );
        assert_eq!(owner.counters().reclaim_refused, 0);

        // The pool is whole and still hands out each index exactly once, which
        // is what a doubly accepted return would have broken.
        assert_eq!(owner.owned(), POOL_BUFFERS);
        let mut seen = BTreeSet::new();
        while let Some(buffer) = owner.alloc() {
            assert!(seen.insert(buffer.index()), "an index was handed out twice");
        }
        assert_eq!(seen.len(), POOL_BUFFERS);
    }

    #[test]
    fn a_peer_restart_that_rezeroes_the_cursors_does_not_double_own_a_buffer() {
        // The peer crashes mid-stream and comes back with both shared cursors
        // zeroed while buffers are in flight. The owner's ledger and lent set
        // are private, so nothing is freed twice; at worst descriptors are
        // replayed, and a replayed return is refused.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut free_in = r.returns.free.producer();

        let mut indices = Vec::new();
        for _ in 0..4 {
            let buffer = owner.alloc().expect("a full pool has buffers");
            indices.push(buffer.index());
            owner
                .lend(&mut rx_in, buffer, 0, 0, Verdict::Transmit)
                .expect("the ring is empty");
        }
        for index in &indices {
            free_in
                .try_enqueue(Descriptor::new(*index, 0, 0, Verdict::Transmit))
                .expect("the free ring has room");
        }
        assert_eq!(owner.reclaim(), 4);
        assert_eq!(owner.owned(), POOL_BUFFERS);

        // The restart. The owner's consume position is private, so a peer that
        // resumes from its own position zero cannot rewind it; what it can do
        // is drive the position onward over slots it never published, which
        // walks the ring all the way round and presents the four already-
        // consumed returns a second time. Every one of them must be refused.
        forge_cursors(&r.returns.free, 0, 3);
        assert_eq!(owner.reclaim(), 0, "a replayed return frees nothing");
        assert!(owner.counters().reclaim_not_lent >= 4);
        assert_eq!(owner.owned(), POOL_BUFFERS);
    }

    #[test]
    fn one_stage_polled_under_three_tables_decides_each_frame_under_the_one_it_was_handed() {
        // The stage carries no configuration of its own, which is the whole of
        // what makes a second commit expressible. The same stage over the same
        // frame three times, with nothing between the polls but the table
        // handed to the next: two that forward it to different next hops under
        // different source MACs, and one that refuses it outright.
        let r = Regions::new();
        let mut owner = PoolOwner::attach(&r.returns);
        let mut rx_in = r.rings.rx.producer();
        let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
        let mut pipeline = Pipeline::new();
        let mut tx_out = r.rings.tx.consumer();
        let mut free_in = r.returns.free.producer();

        let sent = FrameSpec::a_to_b().build();
        for (tag, port0_up) in [(1u8, true), (2u8, true), (3u8, false)] {
            let (number, table) = generation(tag, port0_up);
            receive(&r.pool, &mut owner, &mut rx_in, &sent).expect("a full pool has buffers");
            assert_eq!(
                poll!(
                    stage,
                    &mut pipeline,
                    Configuration::new(number, &table, &ALLOW_ALL),
                    None
                ),
                1
            );
            assert_eq!(stage.counters().generation, number);

            let expected = port0_up.then(|| generation_macs(tag));
            let mut seen = 0;
            transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
                seen += 1;
                let verdict = Verdict::from_bits(descriptor.verdict);
                match expected {
                    Some((egress_mac, next_hop_mac)) => {
                        assert_eq!(verdict, Some(Verdict::Transmit), "generation {number}");
                        assert_eq!(&bytes[..6], &next_hop_mac.0, "generation {number}");
                        assert_eq!(&bytes[6..12], &egress_mac.0, "generation {number}");
                    }
                    None => assert_eq!(verdict, Some(Verdict::Discard), "generation {number}"),
                }
            });
            assert_eq!(seen, 1);
            assert_eq!(owner.reclaim(), 1);
            assert_eq!(owner.owned(), POOL_BUFFERS);
        }
        assert_eq!(stage.counters().forwarded, 2);
        assert_eq!(stage.counters().drops.get(DropReason::InterfaceDisabled), 1);
    }

    #[test]
    fn a_configuration_swapped_under_load_decides_every_frame_under_exactly_one_table() {
        // The three-PD routed scenario end to end under real threads, with the
        // configuration replaced between polls throughout: an rx-driver thread
        // fills and publishes buffers, a forwarder thread routes them onward
        // under a table it exchanges for the other one after every poll that
        // carried traffic, and a tx-driver thread consumes and returns them, so
        // every buffer cycles rx -> route -> tx -> free far more times than the
        // pool holds and every one of those cycles crosses a commit. Both rings
        // wrap repeatedly and every buffer is reused.
        //
        // Three things must hold, and the two tables are built to make the
        // first of them observable: they share neither the egress interface's
        // MAC nor the next hop's, so the pair in a frame's rewritten header
        // names exactly one generation, and a frame carrying one table's source
        // MAC under the other's destination MAC — a decision taken across a
        // swap — matches neither and fails here.
        //
        //  * every forwarded frame is rewritten out of one table, never a blend;
        //  * the pool comes back whole, so no commit lost or duplicated a
        //    buffer in flight across it;
        //  * the sequence-numbered payloads arrive intact and in order under
        //    those rewritten headers.
        //
        // The forwarder thread borrows `rings` and `pool`, which is the grant
        // the system description gives that domain: it can reach `returns` here
        // no more than it can there. It owns the two tables, as the domain will
        // own its running and staged configurations, and nothing else can
        // reach them — which is what leaves the swap point at a poll boundary.
        const TOTAL: u64 = 500_000;
        let r = Regions::new();
        let pool: &Pool = &r.pool;
        let rings: &ForwardRings = &r.rings;
        let returns: &ReturnRing = &r.returns;
        let generations = [generation(1, true), generation(2, true)];
        let generations = &generations;
        let rewrites = [generation_macs(1), generation_macs(2)];

        // Scoped threads because each domain's role type borrows its region: a
        // handle *is* that domain's position, so it is taken once inside the
        // thread that owns the role and kept for the thread's life, exactly as a
        // protection domain takes it once at attach.
        let (applied, per_generation) = thread::scope(|scope| {
            scope.spawn(move || {
                let mut owner = PoolOwner::attach(returns);
                let mut rx_in = rings.rx.producer();
                // One frame, its payload patched per send: the IPv4 checksum
                // covers the header alone, so a sequence number written into
                // the payload leaves the frame exactly as well-formed and the
                // 500,000 sends cost no rebuilding.
                let mut frame = FrameSpec {
                    payload_len: SEQUENCE_LEN,
                    ..FrameSpec::a_to_b()
                }
                .build();
                let sequence_at = frame.len() - SEQUENCE_LEN;
                let mut sent = 0u64;
                let mut idle = 0u64;
                while sent < TOTAL {
                    owner.reclaim();
                    frame[sequence_at..].copy_from_slice(&sent.to_le_bytes());
                    if receive(pool, &mut owner, &mut rx_in, &frame).is_some() {
                        sent += 1;
                        idle = 0;
                    } else {
                        idle += 1;
                        assert!(
                            idle < STALL_SPINS,
                            "the chain stopped taking frames at {sent}"
                        );
                        std::hint::spin_loop();
                    }
                }
                // Wait for the chain to hand every buffer back.
                let mut idle = 0u64;
                while owner.owned() != POOL_BUFFERS {
                    owner.reclaim();
                    idle += 1;
                    assert!(
                        idle < STALL_SPINS,
                        "{} buffers never came back",
                        POOL_BUFFERS - owner.owned()
                    );
                    std::hint::spin_loop();
                }
                assert_eq!(owner.counters(), PoolCounters::default());
            });

            let forwarder = scope.spawn(move || {
                let mut stage = RouteStage::attach(rings, pool, PORT0, PORT1);
                let mut pipeline = Pipeline::new();
                let mut handed_on = 0u64;
                let mut current = 0usize;
                let mut applied = 0u64;
                let mut idle = 0u64;
                while handed_on < TOTAL {
                    let (number, table) = &generations[current];
                    let moved = poll!(
                        stage,
                        &mut pipeline,
                        Configuration::new(*number, table, &ALLOW_ALL),
                        None
                    );
                    if moved > 0 {
                        handed_on += moved as u64;
                        // The commit, and the only point one can occur: the
                        // tables are this thread's own, and the poll the last
                        // of them was lent to has returned.
                        current ^= 1;
                        applied += 1;
                        idle = 0;
                    } else {
                        idle += 1;
                        assert!(idle < STALL_SPINS, "nothing to route after {handed_on}");
                    }
                    std::hint::spin_loop();
                }
                let counters = stage.counters();
                assert_eq!(counters.egress_full, 0);
                assert_eq!(counters.forwarded, TOTAL, "every frame was routable");
                assert_eq!(counters.drops.total(), 0);
                assert_eq!(
                    counters.generation,
                    generations[current ^ 1].0,
                    "the sample names a generation other than the one it was taken under"
                );
                applied
            });

            let transmitter = scope.spawn(move || {
                let mut tx_out = rings.tx.consumer();
                let mut free_in = returns.free.producer();
                let mut expected = 0u64;
                let mut per_generation = [0u64; 2];
                let mut idle = 0u64;
                while expected < TOTAL {
                    let before = expected;
                    transmit(pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
                        assert_eq!(
                            Verdict::from_bits(descriptor.verdict),
                            Some(Verdict::Transmit)
                        );
                        // Which table decided this frame, taken from the source
                        // MAC alone, and then the next hop held to that same
                        // table's neighbour. A frame decided across a commit
                        // carries one generation's source MAC under the other's
                        // destination MAC, which is a pair neither table holds.
                        let decided_by = rewrites
                            .iter()
                            .position(|(egress_mac, _)| bytes[6..12] == egress_mac.0)
                            .expect("a source MAC no configuration's egress interface holds");
                        assert_eq!(
                            &bytes[..6],
                            &rewrites[decided_by].1.0,
                            "the next hop and the source MAC come from different generations"
                        );
                        per_generation[decided_by] += 1;
                        // The rewrite happened, and it happened to this frame:
                        // a stage that wrote one buffer's header into another's
                        // would show up here as the wrong sequence number under
                        // a correct MAC, or the reverse.
                        let value = u64::from_le_bytes(
                            bytes[bytes.len() - SEQUENCE_LEN..]
                                .try_into()
                                .expect("the payload is the sequence number"),
                        );
                        assert_eq!(value, expected, "out-of-order or corrupted buffer");
                        expected += 1;
                    });
                    if expected == before {
                        idle += 1;
                        assert!(idle < STALL_SPINS, "nothing to transmit after {expected}");
                    } else {
                        idle = 0;
                    }
                    std::hint::spin_loop();
                }
                per_generation
            });

            (
                forwarder.join().expect("the forwarder thread"),
                transmitter.join().expect("the tx-driver thread"),
            )
        });

        // What makes the run evidence rather than a green light: a poll moves
        // at most `DRAIN_LIMIT` descriptors, so carrying `TOTAL` frames takes
        // at least this many polls that carried traffic — and the table is
        // exchanged after every one of them. A run in which nothing was
        // swapped attributes every frame to one generation and fails here.
        let least_polls = TOTAL.div_ceil(DRAIN_LIMIT as u64);
        assert!(
            applied >= least_polls,
            "{applied} commits over {TOTAL} frames, fewer than the {least_polls} the drain \
             bound forces"
        );
        assert_eq!(per_generation[0] + per_generation[1], TOTAL);
        for (index, forwarded) in per_generation.iter().enumerate() {
            assert!(
                *forwarded >= least_polls / 2,
                "generation {} decided {forwarded} frames, too few to have run under load",
                generations[index].0
            );
        }
        println!(
            "swapped configuration {applied} times under load; generation {} decided {} frames \
             and generation {} decided {}",
            generations[0].0, per_generation[0], generations[1].0, per_generation[1]
        );
    }

    /// The traffic mix both properties below draw from: every shape the stage
    /// answers differently, in the proportions that keep each answer frequent.
    /// The unroutable ones are not decoration — a stage that leaked a buffer
    /// would leak it on exactly these.
    fn any_frame() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // Routable in the direction under test, and its reverse, which this
            // stage must refuse rather than send back out of its ingress port.
            4 => Just(FrameSpec::a_to_b().build()),
            2 => Just(FrameSpec {
                destination_mac: GATEWAY1_MAC,
                source: HOST_B,
                destination: HOST_A,
                ..FrameSpec::a_to_b()
            }.build()),
            // One frame per family of pipeline rejection.
            1 => Just(FrameSpec { ttl: 1, ..FrameSpec::a_to_b() }.build()),
            1 => Just(FrameSpec { tagged: true, ..FrameSpec::a_to_b() }.build()),
            1 => Just(FrameSpec {
                destination: Ipv4Address::from_octets([203, 0, 113, 4]),
                ..FrameSpec::a_to_b()
            }.build()),
            1 => Just(FrameSpec {
                destination_mac: MacAddress::BROADCAST,
                ..FrameSpec::a_to_b()
            }.build()),
            // And what the wire really carries: bytes of any length that were
            // never a frame at all.
            3 => prop::collection::vec(any::<u8>(), 0..600),
        ]
    }

    /// One move a byzantine neighbour can make against the pool owner and the
    /// routing stage.
    #[derive(Clone, Debug)]
    enum PeerStep {
        /// Take a buffer, fill it with a frame, and publish it as the receiving
        /// driver legitimately would.
        Receive(Vec<u8>),
        /// Take a buffer and keep it, as a buffer posted to the NIC is kept.
        Hold,
        /// Route what is queued.
        Route,
        /// Push an arbitrary descriptor onto the `free` ring, as a byzantine tx
        /// driver does: forged indices, duplicates, buffers never lent.
        ReturnBare(u32),
        /// Take the returns back.
        Reclaim,
        /// Scribble a ring's shared cursors.
        ForgeCursors(u8, u32, u32),
        /// Overwrite a pool buffer's bytes, which every domain mapping the pool
        /// can do at any instant — including between this stage's snapshot and
        /// the transmitting NIC's read.
        ScribblePool(u32, u8),
    }

    fn any_peer_step() -> impl Strategy<Value = PeerStep> {
        prop_oneof![
            4 => any_frame().prop_map(PeerStep::Receive),
            1 => Just(PeerStep::Hold),
            3 => Just(PeerStep::Route),
            // Biased towards real indices so duplicate and never-lent returns
            // are reached, with arbitrary values keeping forged ones in the mix.
            3 => (0..POOL_BUFFERS as u32).prop_map(PeerStep::ReturnBare),
            2 => any::<u32>().prop_map(PeerStep::ReturnBare),
            3 => Just(PeerStep::Reclaim),
            2 => (0u8..3, any::<u32>(), any::<u32>())
                .prop_map(|(ring, head, tail)| PeerStep::ForgeCursors(ring, head, tail)),
            2 => (0..POOL_BUFFERS as u32, any::<u8>())
                .prop_map(|(index, byte)| PeerStep::ScribblePool(index, byte)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        /// The whole `alloc -> lend -> route -> reclaim` chain driven by an
        /// arbitrary hostile neighbour: arbitrary frames, forged and duplicated
        /// indices on the `free` ring, scribbled cursors on every ring,
        /// rewritten pool bytes, and arbitrary interleaving. Nothing may panic,
        /// every step must do bounded work, and the owner set must stay
        /// conserved — the ledger may only ever hand out real, distinct pool
        /// indices, and the buffers it holds free plus those it has lent or that
        /// are held in hand can never exceed the pool.
        #[test]
        fn a_byzantine_neighbour_cannot_panic_or_double_own_a_buffer(
            steps in prop::collection::vec(any_peer_step(), 0..250),
        ) {
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
            let mut pipeline = Pipeline::new();
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();
            // Tokens this domain holds, standing in for buffers posted to a NIC.
            let mut held: Vec<OwnedBuffer<POOL_BUFFERS>> = Vec::new();

            for step in steps {
                match step {
                    PeerStep::Receive(frame) => {
                        let _ = receive(&r.pool, &mut owner, &mut rx_in, &frame);
                    }
                    PeerStep::Hold => {
                        if let Some(buffer) = owner.alloc() {
                            held.push(buffer);
                        }
                    }
                    PeerStep::Route => {
                        prop_assert!(poll!(stage, &mut pipeline, running(), None) <= DRAIN_LIMIT);
                        // Play the tx driver: take what arrived and hand each
                        // buffer straight back, as a well-behaved peer would.
                        for descriptor in tx_out.drain(DRAIN_LIMIT) {
                            let _ = free_in.try_enqueue(descriptor);
                        }
                    }
                    PeerStep::ReturnBare(index) => {
                        let _ = free_in.try_enqueue(Descriptor::new(index, 0, 0, Verdict::Transmit));
                    }
                    PeerStep::Reclaim => {
                        prop_assert!(owner.reclaim() <= DRAIN_LIMIT);
                    }
                    PeerStep::ForgeCursors(which, head, tail) => {
                        let ring = match which {
                            0 => &r.rings.rx,
                            1 => &r.rings.tx,
                            _ => &r.returns.free,
                        };
                        forge_cursors(ring, head, tail);
                    }
                    PeerStep::ScribblePool(index, byte) => {
                        // SAFETY: `write_at`'s ownership clause is exactly the
                        // one a byzantine peer disregards, which is what this
                        // step reproduces; the source is a local, so it cannot
                        // alias the pool, and the span is the accessor's own
                        // business — it answers in its return value.
                        let _ = unsafe {
                            r.pool.write_at(index as usize, 0, &[byte; BUFFER_SIZE])
                        };
                    }
                }
                // Nothing was invented: free plus held can never exceed the
                // pool, and a buffer in hand is never also on the free stack.
                prop_assert!(owner.owned() <= POOL_BUFFERS);
                prop_assert!(owner.owned() + held.len() <= POOL_BUFFERS);
            }

            // The ledger still hands out only real, distinct indices, and never
            // one this domain is still holding — the conserved owner set.
            let still_held: BTreeSet<u32> =
                held.iter().map(OwnedBuffer::<POOL_BUFFERS>::index).collect();
            let mut handed_out: BTreeSet<u32> = BTreeSet::new();
            while let Some(buffer) = owner.alloc() {
                let index = buffer.index();
                prop_assert!((index as usize) < POOL_BUFFERS, "a forged index was handed out");
                prop_assert!(handed_out.insert(index), "one buffer was handed to two owners");
                prop_assert!(!still_held.contains(&index), "a held buffer was handed out again");
                drop(buffer);
            }
            prop_assert!(handed_out.len() + still_held.len() <= POOL_BUFFERS);
        }

        /// The no-leak invariant the whole verdict mechanism exists for: over
        /// any mix of routable, unroutable, malformed and garbage traffic,
        /// every descriptor that enters the stage leaves it, so every buffer
        /// reaches the one domain that can return it and the pool comes back
        /// whole.
        ///
        /// Forged descriptors are in the mix and are the one exception, stated
        /// as such rather than excluded: they name no buffer, so there is
        /// nothing to hand back and nothing to lose. The pool is what proves
        /// the difference — a stage that silently dropped a real descriptor
        /// would leave the ledger short, whatever its counters said.
        #[test]
        fn no_frame_the_stage_accepts_costs_the_pool_a_buffer(
            frames in prop::collection::vec(any_frame(), 1..40),
            forged in prop::collection::vec(any::<u32>(), 0..8),
        ) {
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
            let mut pipeline = Pipeline::new();
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();

            let mut published = 0usize;
            for frame in &frames {
                if receive(&r.pool, &mut owner, &mut rx_in, frame).is_some() {
                    published += 1;
                }
            }
            // Descriptors naming no buffer, interleaved after the real ones so
            // they cannot be dismissed as a prefix the stage never reached.
            for index in &forged {
                let _ = rx_in.try_enqueue(Descriptor::new(
                    index.saturating_add(POOL_BUFFERS as u32),
                    0,
                    64,
                    Verdict::Transmit,
                ));
            }

            // Fewer than the pool holds and far fewer than a ring, so nothing
            // here can be refused for want of room: what the stage does with a
            // descriptor is the only thing under test.
            let handed_on = poll!(stage, &mut pipeline, running(), None);
            let counters = stage.counters();
            prop_assert_eq!(counters.egress_full, 0);
            prop_assert_eq!(handed_on, published, "a real descriptor did not travel on");
            prop_assert_eq!(counters.malformed_descriptor, forged.len() as u64);

            // Every verdict is one of the two, and the tallies account for
            // every frame exactly once.
            let discarded = counters.drops.total()
                + counters.unparsable.total()
                + counters.misrouted
                + counters.snapshot_failed
                + counters.writeback_failed;
            prop_assert_eq!(counters.forwarded + discarded, published as u64);

            // The tx driver takes them all and returns each buffer, whichever
            // verdict it carries; the pool must then be whole again.
            let returned = transmit(&r.pool, &mut tx_out, &mut free_in, |_, _| {});
            prop_assert_eq!(returned, published);
            prop_assert_eq!(owner.reclaim(), published);
            prop_assert_eq!(owner.owned(), POOL_BUFFERS);
            prop_assert_eq!(owner.counters(), PoolCounters::default());
        }

        /// A configuration exchanged between polls, over an arbitrary schedule
        /// of tables and an arbitrary traffic mix. At every boundary a commit
        /// falls on, the pool must be whole — nothing lost to the swap and
        /// nothing returned twice across it — and every frame a poll forwarded
        /// must carry the rewrite of the table *that* poll was handed, not a
        /// neighbouring generation's. A stage keeping a table of its own would
        /// answer with the previous generation's addresses here.
        #[test]
        fn swapping_configuration_between_polls_never_loses_a_buffer(
            schedule in prop::collection::vec((1u8..=9, any::<bool>()), 1..12),
            frames in prop::collection::vec(any_frame(), 1..8),
        ) {
            let r = Regions::new();
            let mut owner = PoolOwner::attach(&r.returns);
            let mut rx_in = r.rings.rx.producer();
            let mut stage = RouteStage::attach(&r.rings, &r.pool, PORT0, PORT1);
            let mut pipeline = Pipeline::new();
            let mut tx_out = r.rings.tx.consumer();
            let mut free_in = r.returns.free.producer();

            for (tag, port0_up) in schedule {
                let (number, table) = generation(tag, port0_up);
                let mut published = 0usize;
                for frame in &frames {
                    if receive(&r.pool, &mut owner, &mut rx_in, frame).is_some() {
                        published += 1;
                    }
                }
                prop_assert_eq!(poll!(stage, &mut pipeline, Configuration::new(number, &table, &ALLOW_ALL), None), published);
                prop_assert_eq!(stage.counters().generation, number);

                let (egress_mac, next_hop_mac) = generation_macs(tag);
                let mut rewritten = Vec::new();
                let returned = transmit(&r.pool, &mut tx_out, &mut free_in, |descriptor, bytes| {
                    if Verdict::from_bits(descriptor.verdict) == Some(Verdict::Transmit) {
                        rewritten.push((bytes[..6].to_vec(), bytes[6..12].to_vec()));
                    }
                });
                for (destination, source) in rewritten {
                    prop_assert_eq!(destination, next_hop_mac.0.to_vec());
                    prop_assert_eq!(source, egress_mac.0.to_vec());
                }
                prop_assert_eq!(returned, published);
                prop_assert_eq!(owner.reclaim(), published);
                prop_assert_eq!(owner.owned(), POOL_BUFFERS);
                prop_assert_eq!(owner.counters(), PoolCounters::default());
            }
        }

        /// The untrusted-descriptor validator accepts exactly the triples that
        /// name a span within one pool buffer and rejects the rest, computed
        /// against a widened-arithmetic reference so it never disagrees and never
        /// overflows — including at the `u32` extremes where `offset + len`
        /// would wrap a 32-bit sum. `any::<u32>()` biases toward those edges;
        /// the explicit boundary strategies pin the exact pool/buffer limits.
        #[test]
        fn descriptor_in_bounds_matches_a_widened_reference(
            buffer in prop_oneof![
                any::<u32>(),
                (POOL_BUFFERS as u32 - 2)..=(POOL_BUFFERS as u32 + 2),
            ],
            offset in prop_oneof![any::<u32>(), (BUFFER_SIZE as u32 - 2)..=(BUFFER_SIZE as u32 + 2)],
            len in prop_oneof![any::<u32>(), 0u32..=(BUFFER_SIZE as u32 + 2)],
        ) {
            let descriptor = Descriptor::new(buffer, offset, len, Verdict::Transmit);
            // Reference in `usize`, which cannot overflow for two `u32`s on a
            // 64-bit host — the authority the checked-arithmetic implementation
            // must match exactly.
            let expected = (buffer as usize) < POOL_BUFFERS
                && (offset as usize) + (len as usize) <= BUFFER_SIZE;
            prop_assert_eq!(descriptor_in_bounds(&descriptor), expected);
        }
    }
}
