//! `virtio::pci` and the bring-up chain that consumes it, under a hostile or
//! malfunctioning device.
//!
//! # The adversary and the surface
//!
//! Every byte of a PCI function's 4 KiB configuration space is the device's
//! — a hostile or malfunctioning device's. The capability chain the
//! driver walks to find the virtio structures is therefore attacker-controlled
//! in its entirety: the chain pointers, the capability lengths and types, the
//! BAR index, and all four structure offsets. So is the BAR window the driver
//! then maps, which is where the common-configuration registers and the
//! doorbells live.
//!
//! # What the adversary may express here
//!
//! The configuration space and the BAR window are filled from **two disjoint
//! runs of input bytes**, so the device chooses its capability chain and its
//! register values independently. Filling both from one slice — as this harness
//! used to — tied every register value to the chain that had to be well-formed
//! to reach it, and left the register space reachable only in whatever shapes a
//! parseable chain happened to spell.
//!
//! On top of that: the `queue_notify_off` a device would report, the BAR-window
//! sizes the offsets are bounded against, the BAR index a caller probes, and the
//! physical address the BAR is relocated to. One input bit stamps the
//! virtio-net `(vendor, device)` id pair into the page. That bit only makes the
//! deep chain *reachable often*: the unstamped page is still fully generated,
//! and the ids are two bytes the fuzzer could always have produced itself, so
//! nothing is excluded — it converts a 1-in-2^32 coin flip into a coverage
//! plateau the fuzzer can build on.
//!
//! # The device answers each register access, rather than echoing the driver
//!
//! The bring-up typestate is one straight line of MMIO over a window that is
//! plain RAM, so every register the driver reads back is a register the driver
//! itself last wrote. That is a *passive* device, and a passive device cannot
//! take the branches that exist for an active one. `drive_registers` is the
//! answer for everything reachable through `virtio::pci`'s public register API:
//! it re-arms the device's registers from the fuzzer's own byte stream
//! **between** driver calls, so `CommonCfg::setup_queue` is answered afresh on
//! every call rather than from what the previous call programmed.
//!
//! That is what makes a **refusal of the transmit queue** expressible. Inside
//! `Negotiated::configure_queues` the receive queue is programmed first, and
//! programming it writes `queue_size` into the one un-banked window word the
//! transmit queue then reads back, so `QueueSetupError::QueueAbsent` and
//! `QueueTooSmall` could only ever name queue 0. Here the two calls are made
//! separately with the register re-armed in between, and `index` is an
//! unreduced `u16`, so a device that offers a receive queue and refuses the
//! transmit queue is an ordinary input.
//!
//! # The device that answers inside the call: [`ScriptedDevice`]
//!
//! Re-arming registers between calls is still not enough for the behaviours
//! that are a disagreement *within* one driver call, and there are three:
//!
//! * **A reset that is never acknowledged.** `CommonCfg::reset` writes zero to
//!   `device_status` and polls the same byte; over RAM the poll reads the zero
//!   the write just placed, so `ResetError::NotAcknowledged` — and
//!   `BringUpError::ResetRefused` above it — cannot be produced.
//! * **A device that clears `FEATURES_OK` on readback.**
//!   `Acknowledged::negotiate_features` writes the status byte and re-reads it
//!   in the same call, so the readback check that exists precisely to catch
//!   this device cannot see one, and `BringUpError::FeaturesRejected` is
//!   unreachable.
//! * **A feature bitmap whose halves differ.** `CommonCfg::device_features`
//!   writes `device_feature_select` and reads `device_feature` twice; over RAM
//!   both reads hit the same word, so only bitmaps with `high == low` exist.
//!
//! All three are what `nic_driver_core::bringup::VirtioDevice` is a seam *for*,
//! and [`ScriptedDevice`] is an implementation of it that answers every access
//! from its own run of the fuzzer's bytes at the moment the driver asks. The
//! whole typestate is driven over it, from `Offered` to `DRIVER_OK`, so the two
//! refusals that `configure_queues` orders behind a *successful* receive queue
//! — `QueueSetupRefused { index: TX_QUEUE }` and `DoorbellRefused { index:
//! TX_QUEUE }` — are ordinary inputs here as well.
//!
//! # Bias towards the deep states, never a filter on the shallow ones
//!
//! Every one of the device's six answers is chosen by a `u32` the fuzzer owns,
//! and every answer deviates from a conforming device on exactly one quarter of
//! those values (`selector % 4 == 3`). That is a **bias**, not a capability
//! filter: each deviation stays reachable on a quarter of all
//! selectors and each deviating answer's payload is unreduced, so no outcome is
//! excluded — but a device that refused half of what it was asked would stop
//! most inputs at the first state and leave `go_live` reached by luck. The
//! quarter is also why a *spent* input is a conforming device rather than a
//! refusing one: `any_u32` yields zero once the bytes run out, and zero is the
//! conforming answer everywhere, so a short input drives the deep path instead
//! of dying at the reset.
//!
//! # What is asserted
//!
//! * **A successful parse yields a real BAR.** `caps.bar <= 5`, which is the
//!   one property `find_virtio_caps` promises about a device-supplied index.
//! * **The bounds predicates are total and monotone.** `within` and
//!   `notify_slot_within` refuse a zero-byte window, accept an unbounded one
//!   (which is a real claim: it says the checked arithmetic never overflows on
//!   a 64-bit `usize`, whatever the device puts in a `u32` offset or a `u32`
//!   multiplier), and never accept a smaller window while refusing a larger.
//! * **The typed BAR-index boundary.** `bar_is_64bit` refuses exactly the
//!   indices above 5, and `reprogram_bar64` additionally refuses BAR 5.
//! * **The precondition chain `PlacedBar::map` rests on, in full.** `map`'s
//!   safety comment names `identify` as the component that established *two*
//!   independent facts about a device-chosen offset — `within(BAR_WINDOW_SIZE)`
//!   for the extent and `common_is_aligned()` for the alignment. Both are
//!   asserted here on every successful `identify`, so the named guarantor is
//!   checked rather than believed.
//! * **Every register access lands where virtio 1.0 says.** The offsets
//!   `drive_registers` arms are asserted against the accessors that read
//!   them, in both directions, by
//!   `the_register_offsets_are_the_ones_virtio_1_0_fixes` — so an arm that
//!   silently missed its register could not pass as a device answer.
//! * **`setup_queue`'s outcome and its side effects**, against a model: the
//!   error variant and its payload, that a refusal leaves the ring addresses
//!   and `queue_enable` exactly as the device left them (which is the whole of
//!   "a caller that gives up leaves the device with no ring addresses it could
//!   act on"), and that an acceptance programmes the size, the three areas and
//!   the enable bit.
//! * **`Doorbell::new`'s outcome**, against `notify_slot_within` and the
//!   parity rule, and that ringing a placed doorbell writes its two bytes at
//!   the offset the device named and nowhere else.
//! * **The handshake is driven to `DRIVER_OK`** over a fuzzer-filled BAR
//!   window, so the device's `device_features`, `num_queues`, `queue_size` and
//!   `queue_notify_off` answers all come from the adversary.
//! * **The handshake's outcome over [`ScriptedDevice`], against a model of
//!   what the device answered.** Reaching `Live` implies every one of the six
//!   answers was the conforming one; each rejection is matched to the answer
//!   that caused it, including that `QueueSetupRefused`/`DoorbellRefused` name
//!   the queue the *driver* was programming and not the index the device put
//!   inside the error it returned.
//! * **The ordering virtio 1.0 section 3.1.1 fixes, under a hostile device.** Reset
//!   first; driver features never before `ACKNOWLEDGE | DRIVER`; `DRIVER_OK`
//!   never before both queues are programmed and both doorbells placed; no
//!   doorbell rung before `DRIVER_OK`. The typestate exists to get this right
//!   and the ordering is not observable through a passive window, so it is
//!   asserted where a device can misbehave at every step.
//! * **DMA is granted once, and only after the reset.** With no IOMMU, bus
//!   mastering is the whole of the authority the other steps merely sequence: a
//!   device granted it while still holding the queue addresses it was left with
//!   may write them. So the grant sits immediately behind the reset, happens
//!   exactly once, and never happens at all for a device that refused its reset.
//! * **`STATUS_FAILED` is what a refusal leaves behind.** Every rejection from
//!   `Offered` onward claims `signalled_to_device()`, and the device's own
//!   record must show that write — the claim checked against what was actually
//!   written rather than against the enumeration that makes it.
//!
//! # The closed finding this target keeps closed
//!
//! This target found a real defect in `crates/virtio` and
//! `crates/nic-driver-core`. It is fixed; the input that found it is committed
//! as `fuzz/corpus/find_virtio_caps/unaligned_common_cfg_offset` and this
//! target is its permanent regression seed, so a reintroduction fails here
//! rather than in a driver on a real NIC.
//!
//! **What it was.** `find_virtio_caps` lifts `VirtioCaps::common` out of the
//! capability chain as a raw `u32` the device chose. `identify` checked only
//! `caps.within(BAR_WINDOW_SIZE)`, which is an *extent*, and `PlacedBar::map`
//! then formed `CommonCfg::new(bar_base + caps.common)`. Every `CommonCfg`
//! accessor casts that base and reads or writes a `u16`/`u32`/`u64` volatile,
//! so an odd `common` offset — which a hostile device simply advertises — was a
//! misaligned volatile MMIO access: undefined behaviour in the Rust abstract
//! machine, and a split transaction on the wire. `Doorbell::new` had checked
//! `offset.is_multiple_of(2)` for the notify slot all along, so the pattern
//! existed; it had never been applied to the common-configuration base. The
//! delegation chain terminated nowhere — no component enforced the
//! precondition — and `map`'s safety comment named `identify` as the guarantor
//! of something `identify` did not guarantee.
//!
//! **What closed it.** The fix is in the crates that own the fault, not here:
//! `virtio::pci::VirtioCaps::common_is_aligned` is the predicate, and
//! `nic_driver_core::bringup::identify` now refuses a device that fails it with
//! `BringUpError::CommonCfgMisaligned` before any `CommonCfg` is constructed.
//! The finding is a regression test in each owning crate's own
//! suite rather than only a corpus entry — `crates/virtio/src/pci.rs`'s
//! `a_misaligned_common_offset_survives_the_capability_walk_and_is_caught_by_the_predicate`
//! and `crates/nic-driver-core/src/bringup.rs`'s
//! `a_misaligned_common_configuration_offset_is_refused_before_any_dereference`,
//! with the property `identify_accepts_a_common_offset_only_when_bounded_and_aligned`
//! covering the two predicates together.
//!
//! **What this target guards now.** The *conjunction*. `map`'s safety comment
//! rests on two independent facts, and a future change that kept one while
//! dropping the other would still hand `CommonCfg::new` a base its accessors
//! cannot use — an extent check says nothing about alignment, and vice versa.
//! Both are asserted below on every successful `identify`, and the bring-up
//! chain stays in this target: removing it to shorten the harness would delete
//! the reach that found the defect — a harness narrowed below the adversary.

use std::cell::RefCell;
use std::rc::Rc;

use arbitrary::Unstructured;
use nic_driver_core::bringup::{
    ACCEPTED_FEATURES, BAR_WINDOW_SIZE, BringUpError, BusMaster, DriverVirtqueue, Offered,
    QueueDoorbell, RX_QUEUE, TX_QUEUE, VirtioDevice, identify,
};
use virtio::net::features;
use virtio::pci::{
    BarError, CommonCfg, Doorbell, NotifyError, PciConfig, QueueSetupError, ResetError,
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED, STATUS_FEATURES_OK,
    VirtioCaps, find_virtio_caps,
};
use virtio::queue::QueueLayout;

use crate::region::{ECAM_PAGE_BYTES, EcamPage, ZeroedRegion};
use crate::{MAX_OPERATIONS, any_u16, any_u32, next_op};

/// Offset of the `vendor_id`/`device_id` pair in configuration space.
const PCI_IDS_OFFSET: usize = 0;
/// The `(vendor, device)` pair `nic_driver_core::bringup::identify` insists on.
const VIRTIO_NET_IDS: [u8; 4] = [0xF4, 0x1A, 0x41, 0x10];

/// Where the harness pretends the virtqueue DMA region sits.
///
/// **Driver data, not device data.** `CommonCfg::setup_queue` adds the layout's
/// offsets to it and says so: "an overflow in these sums is a build-time
/// misconfiguration that must fail visibly, not device input". Handing it a
/// fuzzer-chosen `u64` would manufacture an overflow panic on a value no
/// adversary supplies and report the harness's own bug as a finding.
const RING_PADDR: u64 = 0x3100_0000;

/// The BAR window the driver maps, as its own over-aligned type.
///
/// Page-aligned for the same reason [`EcamPage`] is: `Doorbell::new`'s contract
/// requires the window to be at least two-byte aligned, and `PlacedBar::map`
/// forms the common-configuration pointer by adding a device-supplied offset to
/// this base. A harness that supplied an under-aligned base would be
/// manufacturing its own misalignment and could not tell the device's apart.
#[repr(C, align(4096))]
struct BarWindow([u8; BAR_WINDOW_SIZE]);

/// Byte offsets of the `virtio_pci_common_cfg` registers this harness arms,
/// relative to the structure's base.
///
/// **Cross-artifact fact:** these are virtio 1.0 section 4.1.4.3's layout, which
/// `crates/virtio/src/pci.rs` transcribes into private `CommonOff` constants a
/// consumer cannot name. The enforcer is
/// [`tests::the_register_offsets_are_the_ones_virtio_1_0_fixes`], which drives
/// each public accessor against the byte it is armed at and fails if the two
/// ever name different words.
mod offsets {
    pub(super) const DEVICE_FEATURE: usize = 4;
    pub(super) const NUM_QUEUES: usize = 18;
    pub(super) const DEVICE_STATUS: usize = 20;
    pub(super) const QUEUE_SELECT: usize = 22;
    pub(super) const QUEUE_SIZE: usize = 24;
    pub(super) const QUEUE_ENABLE: usize = 28;
    pub(super) const QUEUE_NOTIFY_OFF: usize = 30;
    pub(super) const QUEUE_DESC: usize = 32;
    pub(super) const QUEUE_DRIVER: usize = 40;
    pub(super) const QUEUE_DEVICE: usize = 48;
}

/// What one run of the harness reached, so a test can *demonstrate* that a
/// device behaviour is generable rather than assert that it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Observed {
    pub(crate) caps_found: bool,
    pub(crate) identified: bool,
    pub(crate) reached_driver_ok: bool,
    /// Register-level `setup_queue` refusals, split by which queue was refused,
    /// because refusing the *transmit* queue is the shape `configure_queues`
    /// cannot produce over an un-banked window.
    pub(crate) receive_queue_refused: u32,
    pub(crate) transmit_queue_refused: u32,
    pub(crate) other_queue_refused: u32,
    pub(crate) queues_programmed: u32,
    pub(crate) doorbells_placed: u32,
    pub(crate) doorbells_refused: u32,
    /// What the same input reached through the [`ScriptedDevice`] seam, which
    /// is independent of the capability chain: a stand-in device needs no BAR.
    pub(crate) seam: SeamObserved,
}

/// What the handshake over [`ScriptedDevice`] reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SeamObserved {
    pub(crate) outcome: SeamOutcome,
    /// The device answered `device_features` with a bitmap whose high 32 bits
    /// differ from its low 32 — the shape no un-banked window can produce.
    pub(crate) split_feature_halves: bool,
}

/// Where the handshake stopped, carrying the refusal itself so a demonstration
/// names the branch it reaches rather than a count that could stand for any of
/// them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SeamOutcome {
    /// The typestate was not driven at all.
    #[default]
    NotRun,
    /// `DRIVER_OK` was written and both doorbells are ringable.
    Live,
    Refused(BringUpError),
}

/// Drive the capability walk, the bounds predicates, the common-configuration
/// registers, and the bring-up chain over a device-controlled configuration
/// space and BAR window.
pub fn find_virtio_caps_harness(data: &[u8]) {
    let _ = observe(data);
}

/// The harness body, returning what it reached so a test can prove a shape
/// generable.
pub(crate) fn observe(data: &[u8]) -> Observed {
    let mut unstructured = Unstructured::new(data);
    let mut observed = Observed::default();

    let stamp_ids = (any_u32(&mut unstructured) & 1) == 1;
    let probe_bar = any_u32(&mut unstructured) as u8;
    let notify_off = any_u16(&mut unstructured);
    let window_a = any_u32(&mut unstructured) as usize;
    let window_b = any_u32(&mut unstructured) as usize;
    let bar_paddr = any_u32(&mut unstructured) as usize;
    // Two disjoint runs, so the chain and the registers vary independently.
    // Reduced against what is left rather than against a constant: the split is
    // a partition of the fuzzer's own bytes, not a limit on either side's
    // values.
    let page_run = any_u32(&mut unstructured);
    let window_run = any_u32(&mut unstructured);
    let device_run = any_u32(&mut unstructured);
    let page_bytes = take_run(&mut unstructured, page_run);
    let window_bytes = take_run(&mut unstructured, window_run);
    let device_bytes = take_run(&mut unstructured, device_run);

    // First, and unconditionally: the seam needs no capability chain and no
    // BAR, so gating it on either would put the branches it exists to reach
    // behind a walk that has nothing to do with them.
    observed.seam = drive_handshake(device_bytes);

    let page = EcamPage::zeroed();
    let page_base = page.as_ptr().cast::<u8>();
    // SAFETY: `page` is a live, zeroed, page-aligned `EcamPage` of exactly
    // `ECAM_PAGE_BYTES` bytes, and no reference into it exists yet.
    unsafe { overwrite(page_base, ECAM_PAGE_BYTES, page_bytes) };
    if stamp_ids {
        // SAFETY: as above; the four id bytes lie at the front of the page.
        unsafe { overwrite(page_base.add(PCI_IDS_OFFSET), 4, &VIRTIO_NET_IDS) };
    }

    // SAFETY: `page_base` is the base of a live, page-aligned 4 KiB region that
    // outlives `config` — `PciConfig::new`'s whole contract. Page alignment is
    // what makes the `u16`/`u32` casts in `read16`/`read32` naturally aligned
    // for the fixed, even, 4-aligned offsets they are called with; a `[u8; N]`
    // local would have `align_of == 1` and could not supply it.
    let config = unsafe { PciConfig::new(page_base) };

    // The typed BAR-index boundary: refused above 5, answered at or below.
    match config.bar_is_64bit(probe_bar) {
        Ok(_) => assert!(
            probe_bar <= 5,
            "a BAR index above 5 was answered, not refused"
        ),
        Err(BarError::IndexOutOfRange(index)) => {
            assert_eq!(index, probe_bar);
            assert!(
                probe_bar > 5,
                "a real BAR index was refused as out of range"
            );
        }
        Err(other) => panic!("bar_is_64bit refused index {probe_bar} with {other:?}"),
    }

    let Ok(caps) = find_virtio_caps(&config) else {
        return observed;
    };
    observed.caps_found = true;
    assert!(
        caps.bar <= 5,
        "find_virtio_caps accepted an invalid BAR index {}",
        caps.bar
    );

    // Total and monotone. `within(usize::MAX)` is a real claim about the
    // checked arithmetic, not a tautology: the offsets are `u32` and the
    // extents are small constants, so on a 64-bit `usize` no `checked_add` may
    // fail — and if one ever did, this would catch it.
    assert!(!caps.within(0), "something fitted a zero-byte BAR window");
    assert!(caps.within(usize::MAX), "the bounds arithmetic overflowed");
    assert!(!caps.notify_slot_within(notify_off, 0));
    assert!(caps.notify_slot_within(notify_off, usize::MAX));
    let (small, large) = if window_a <= window_b {
        (window_a, window_b)
    } else {
        (window_b, window_a)
    };
    if caps.within(small) {
        assert!(
            caps.within(large),
            "within is not monotone in the window size"
        );
        // Every structure needs at least one byte, so fitting implies the
        // offset itself is inside the window.
        assert!((caps.common as usize) < small);
        assert!((caps.notify as usize) < small);
        assert!((caps.device as usize) < small);
    }
    if caps.notify_slot_within(notify_off, small) {
        assert!(
            caps.notify_slot_within(notify_off, large),
            "notify_slot_within is not monotone in the window size"
        );
    }

    // The register stage runs on the two facts `CommonCfg::new` asks for and
    // nothing else — deliberately not on `identify`, which additionally demands
    // the virtio-net ids and a 64-bit BAR and would put most of the register
    // space behind a chain that also has to satisfy them.
    if caps.within(BAR_WINDOW_SIZE) && caps.common_is_aligned() {
        let window = ZeroedRegion::<BarWindow>::new();
        let base = window.as_ptr().cast::<u8>();
        // SAFETY: `window` is a live, zeroed, page-aligned `BarWindow` of
        // exactly `BAR_WINDOW_SIZE` bytes with no outstanding reference.
        unsafe { overwrite(base, BAR_WINDOW_SIZE, window_bytes) };
        // SAFETY: `caps.within(BAR_WINDOW_SIZE)`, just checked, puts
        // `caps.common + COMMON_CFG_MIN_LEN` inside the window `base` names;
        // `caps.common_is_aligned()`, also just checked, plus the 4096-byte
        // alignment `BarWindow` carries, makes the sum `COMMON_CFG_ALIGN`-
        // aligned. Those are exactly the two facts `CommonCfg::new` requires,
        // and they are established here rather than delegated.
        let registers = unsafe { Registers::new(base, caps.common as usize) };
        drive_registers(&mut unstructured, &registers, &caps, base, &mut observed);
    }

    let Ok(identified) = identify(&config) else {
        return observed;
    };
    observed.identified = true;
    // The guarantor `PlacedBar::map`'s safety comment names, checked — both
    // halves of it. The extent and the alignment are independent claims about
    // the same device-chosen `u32`: a structure can fit the window exactly and
    // still sit at an odd offset, which is precisely the finding recorded in
    // this module's header. Checking only the first is what let that through.
    let identified_caps = identified.caps();
    assert!(
        identified_caps.within(BAR_WINDOW_SIZE),
        "identify accepted structures outside the window map() then trusts"
    );
    assert!(
        identified_caps.common_is_aligned(),
        "identify accepted a common-configuration offset map() then builds a \
         misaligned CommonCfg on"
    );
    assert!(identified_caps.bar <= 5);
    assert_eq!(
        config.bar_is_64bit(identified_caps.bar),
        Ok(true),
        "identify accepted a BAR it then relocates as a 64-bit pair"
    );

    // `place_bar`'s outcome is fully determined by its inputs; assert the model
    // rather than merely that it did not panic.
    let placeable = bar_paddr != 0
        && bar_paddr.is_multiple_of(BAR_WINDOW_SIZE)
        && u32::try_from(bar_paddr).is_ok()
        && identified_caps.bar <= 4;
    let placed = identified.place_bar(&config, bar_paddr);
    assert_eq!(
        placed.is_ok(),
        placeable,
        "place_bar disagreed with its own documented preconditions for {bar_paddr:#x}"
    );
    let Ok(placed) = placed else {
        return observed;
    };

    let window = ZeroedRegion::<BarWindow>::new();
    let window_base = window.as_ptr().cast::<u8>();
    // SAFETY: `window` is a live, zeroed, page-aligned `BarWindow` of exactly
    // `BAR_WINDOW_SIZE` bytes with no outstanding reference into it.
    unsafe { overwrite(window_base, BAR_WINDOW_SIZE, window_bytes) };

    // SAFETY: `window_base` names a live, page-aligned mapping of exactly
    // `BAR_WINDOW_SIZE` bytes that outlives every value derived from it here —
    // `map`'s contract verbatim. `map` requires nothing of the caller about the
    // device's own offsets: `identify` bounded them, which was asserted above.
    let offered = unsafe { placed.map(window_base) };

    // The real `PciConfig` is the bus-master gate on this path, so the
    // command-register write the grant performs is the one a driver PD makes.
    // Its *value* is not asserted here: every byte of this ECAM page comes from
    // the input, so the register's initial state is the adversary's too.
    let Ok(acknowledged) = offered.acknowledge(&config) else {
        return observed;
    };
    let Ok(negotiated) = acknowledged.negotiate_features() else {
        return observed;
    };
    assert_eq!(
        negotiated.features() & !ACCEPTED_FEATURES,
        0,
        "the driver accepted a feature bit it does not implement"
    );
    let Ok(configured) = negotiated.configure_queues(RING_PADDR) else {
        return observed;
    };
    // Both doorbells were placed inside the mapped window or `configure_queues`
    // would have refused; ringing them writes only within it.
    let live = configured.go_live();
    live.ring_receive();
    live.ring_transmit();
    observed.reached_driver_ok = true;
    observed
}

/// Take a run of the remaining input, sized by a fuzzer-chosen value.
///
/// The reduction is against what is left, so the two runs partition the
/// fuzzer's bytes rather than capping what either may contain.
fn take_run<'data>(unstructured: &mut Unstructured<'data>, requested: u32) -> &'data [u8] {
    let available = unstructured.len();
    // `x % (n + 1) <= n` for every `x`, so `take <= available` whatever the
    // fuzzer asked for, and `Unstructured::bytes` returns `Ok` for any size at
    // most the remaining length. The proof is arithmetic rather than an
    // assumption about the input, which is what makes the `expect` sound
    // on a path reachable from untrusted bytes.
    let take = (requested as usize) % (available + 1);
    unstructured
        .bytes(take)
        .expect("take is at most the remaining length")
}

/// One thing the driver did to a [`ScriptedDevice`], in the order it did it.
///
/// Recorded because the bring-up typestate's whole job is *ordering*, and the
/// order is not a value any register holds: a device told `DRIVER_OK` before
/// its virtqueues carry addresses misbehaves as a dead link, which no readback
/// distinguishes from a working one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeviceEvent {
    Reset,
    /// The driver granted the device bus-master DMA.
    DmaEnabled,
    Status(u8),
    DriverFeatures(u64),
    /// The virtqueue the driver programmed, by the index it named.
    QueueConfigured(u16),
    /// A doorbell placed for the `queue_notify_off` the device itself reported;
    /// the device is told no index, which is why this carries the offset.
    DoorbellPlaced(u16),
    Rang(u16),
}

/// Everything a [`ScriptedDevice`] was asked and everything it answered.
///
/// Shared through an `Rc`, because the typestate consumes the device into each
/// successive state and drops it at `go_live`: without a second handle on the
/// record there would be nothing left to check the outcome against.
#[derive(Default)]
struct DeviceRecord {
    events: Vec<DeviceEvent>,
    /// The `device_status` byte the device is holding, so its *conforming*
    /// answer to a readback is the value the driver last wrote — which is what
    /// makes a cleared `FEATURES_OK` a deviation rather than the norm.
    held: u8,
    /// Every bitmap answered to `device_features`.
    offered: Vec<u64>,
    /// Every `device_status` byte answered to a readback.
    status_reads: Vec<u8>,
    /// Every virtqueue count answered to `num_queues`.
    queues_reported: Vec<u16>,
    /// Every answer to `setup_queue`, in call order — so which call refused is
    /// the length of this list, not something the harness has to be told.
    queue_answers: Vec<Result<u16, QueueSetupError>>,
    /// Every answer to `place_doorbell`, in call order.
    doorbell_answers: Vec<Result<u16, NotifyError>>,
    /// Whether the device refused its reset.
    reset_refused: bool,
}

/// The bus-master gate, recording into the same [`DeviceRecord`] the device
/// does.
///
/// A PCI command-register write cannot fail and answers nothing, so there is
/// nothing for the input to choose here: the only thing worth observing is
/// *when* the driver opened the gate, and it lands in one sequence with the
/// reset it must follow.
struct ScriptedBus {
    record: Rc<RefCell<DeviceRecord>>,
}

impl BusMaster for ScriptedBus {
    fn enable_dma(&self) {
        self.record
            .borrow_mut()
            .events
            .push(DeviceEvent::DmaEnabled);
    }
}

/// A virtio device that answers each access from its own run of the fuzzer's
/// bytes, at the moment the driver asks.
///
/// This is the implementation of the `VirtioDevice` seam that a fuzz target can
/// hold, and it exists because a `CommonCfg` over plain host memory reads back
/// exactly what was written: a disagreement *within* one driver call — the
/// reset that is never acknowledged, the `FEATURES_OK` cleared on readback, the
/// feature bitmap whose halves differ — has no other expression. Deterministic
/// rather than threaded: a second thread storing into the same words would be a
/// data race this harness manufactured itself.
struct ScriptedDevice<'data> {
    stream: RefCell<Unstructured<'data>>,
    record: Rc<RefCell<DeviceRecord>>,
}

/// A doorbell whose ring is recorded rather than written to MMIO.
struct ScriptedDoorbell {
    record: Rc<RefCell<DeviceRecord>>,
}

impl QueueDoorbell for ScriptedDoorbell {
    fn ring(&self, queue: u16) {
        self.record
            .borrow_mut()
            .events
            .push(DeviceEvent::Rang(queue));
    }
}

/// The share of selector values on which the device deviates from a conforming
/// one: `selector % DEVIATION == DEVIATION - 1`.
///
/// A coverage bias and not a capability filter — every deviation stays
/// reachable on a quarter of all selectors, and the payload of a deviating
/// answer is never reduced. See this module's header.
const DEVIATION: u32 = 4;

impl ScriptedDevice<'_> {
    /// The next word of the device's script. Zero once the input is spent,
    /// which is the conforming answer everywhere.
    fn word(&self) -> u32 {
        any_u32(&mut self.stream.borrow_mut())
    }

    /// Whether this answer deviates, and which deviating shape it takes.
    fn choose(&self, shapes: u32) -> Option<u32> {
        let selector = self.word();
        (selector % DEVIATION == DEVIATION - 1).then(|| (selector / DEVIATION) % shapes)
    }

    fn note(&self, event: DeviceEvent) {
        self.record.borrow_mut().events.push(event);
    }
}

impl VirtioDevice for ScriptedDevice<'_> {
    type Doorbell = ScriptedDoorbell;

    fn reset(&self) -> Result<(), ResetError> {
        self.note(DeviceEvent::Reset);
        let deviates = self.choose(1).is_some();
        let status = self.word() as u8;
        let mut record = self.record.borrow_mut();
        if deviates {
            record.reset_refused = true;
            return Err(ResetError::NotAcknowledged { status });
        }
        record.held = 0;
        Ok(())
    }

    fn status(&self) -> u8 {
        let deviates = self.choose(1).is_some();
        let arbitrary = self.word() as u8;
        let mut record = self.record.borrow_mut();
        let answer = if deviates { arbitrary } else { record.held };
        record.status_reads.push(answer);
        answer
    }

    fn set_status(&self, value: u8) {
        let mut record = self.record.borrow_mut();
        record.held = value;
        record.events.push(DeviceEvent::Status(value));
    }

    fn device_features(&self) -> u64 {
        let deviates = self.choose(1).is_some();
        // Two independent halves, which is the whole point: `device_features`
        // over an un-banked window can only ever report `high == low`.
        let high = u64::from(self.word());
        let low = u64::from(self.word());
        let raw = (high << 32) | low;
        // A conforming device offers the one bit this driver requires; a
        // deviating one answers with the raw bitmap, which may not carry it.
        let answer = if deviates {
            raw
        } else {
            raw | features::VIRTIO_F_VERSION_1
        };
        self.record.borrow_mut().offered.push(answer);
        answer
    }

    fn set_driver_features(&self, features: u64) {
        self.note(DeviceEvent::DriverFeatures(features));
    }

    fn num_queues(&self) -> u16 {
        let deviates = self.choose(1).is_some();
        let arbitrary = self.word() as u16;
        let answer = if deviates { arbitrary } else { TX_QUEUE + 1 };
        self.record.borrow_mut().queues_reported.push(answer);
        answer
    }

    fn setup_queue(
        &self,
        index: u16,
        _layout: &QueueLayout,
        _ring_paddr: u64,
    ) -> Result<u16, QueueSetupError> {
        let shape = self.choose(2);
        let notify_off = self.word() as u16;
        // The index inside the error is the *device's* to choose and is never
        // the one the driver asked about, so a driver that echoed the device's
        // claim as the queue it was programming would be caught.
        let claimed = self.word() as u16;
        let device_max = self.word() as u16;
        let required = self.word() as usize;
        let answer = match shape {
            Some(0) => Err(QueueSetupError::QueueAbsent { index: claimed }),
            Some(_) => Err(QueueSetupError::QueueTooSmall {
                index: claimed,
                device_max,
                required,
            }),
            None => Ok(notify_off),
        };
        self.record.borrow_mut().queue_answers.push(answer);
        if answer.is_ok() {
            self.note(DeviceEvent::QueueConfigured(index));
        }
        answer
    }

    fn place_doorbell(&self, notify_off: u16) -> Result<ScriptedDoorbell, NotifyError> {
        let shape = self.choose(3);
        let offset = self.word() as usize;
        let bar_size = self.word() as usize;
        let answer = match shape {
            Some(0) => Err(NotifyError::SlotMisaligned { offset }),
            Some(1) => Err(NotifyError::SlotOutsideBar {
                slot_end: Some(offset),
                bar_size,
            }),
            Some(_) => Err(NotifyError::SlotOutsideBar {
                slot_end: None,
                bar_size,
            }),
            None => Ok(notify_off),
        };
        self.record.borrow_mut().doorbell_answers.push(answer);
        match answer {
            Ok(notify_off) => {
                self.note(DeviceEvent::DoorbellPlaced(notify_off));
                Ok(ScriptedDoorbell {
                    record: Rc::clone(&self.record),
                })
            }
            Err(error) => Err(error),
        }
    }
}

/// Drive the whole bring-up typestate over a [`ScriptedDevice`], then check the
/// outcome and the ordering against what the device actually answered.
fn drive_handshake(script: &[u8]) -> SeamObserved {
    let record = Rc::new(RefCell::new(DeviceRecord::default()));
    let device = ScriptedDevice {
        stream: RefCell::new(Unstructured::new(script)),
        record: Rc::clone(&record),
    };

    let bus = ScriptedBus {
        record: Rc::clone(&record),
    };
    let outcome = match run_handshake(Offered::new(device), &bus) {
        Ok(()) => SeamOutcome::Live,
        Err(error) => SeamOutcome::Refused(error),
    };

    let record = record.borrow();
    assert_ordering(&record);
    assert_outcome_matches_the_device(&record, outcome);
    SeamObserved {
        outcome,
        split_feature_halves: record
            .offered
            .iter()
            .any(|bitmap| (bitmap >> 32) != (bitmap & 0xFFFF_FFFF)),
    }
}

/// `Offered` through to `DRIVER_OK`, ringing both doorbells once live.
fn run_handshake<D: VirtioDevice>(
    offered: Offered<D>,
    bus: &impl BusMaster,
) -> Result<(), BringUpError> {
    let negotiated = offered.acknowledge(bus)?.negotiate_features()?;
    assert_eq!(
        negotiated.features() & !ACCEPTED_FEATURES,
        0,
        "the driver accepted a feature bit it does not implement"
    );
    // `RING_PADDR` rather than a fuzzer-chosen address for the reason its own
    // comment gives: the virtqueue region is build data, and driving it from
    // the input would report the harness's own misconfiguration as a finding.
    let live = negotiated.configure_queues(RING_PADDR)?.go_live();
    live.ring_receive();
    live.ring_transmit();
    Ok(())
}

/// The order virtio 1.0 section 3.1.1 fixes, asserted against a device free to
/// misbehave at every step. None of this is observable through a passive
/// window, which is why the typestate carries it and why it is checked here.
fn assert_ordering(record: &DeviceRecord) {
    let events = &record.events;
    assert_eq!(
        events.first(),
        Some(&DeviceEvent::Reset),
        "the handshake touched the device before resetting it: {events:?}"
    );
    let position = |wanted: DeviceEvent| events.iter().position(|event| *event == wanted);
    let driver_ok = position(DeviceEvent::Status(
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    ));
    // DMA is the authority everything else here is only a protocol step beside:
    // with no IOMMU, a device that may master the bus may write anywhere. So it
    // is granted exactly once, immediately after the reset that cleared whatever
    // queue addresses the device was holding — and a device that refused its
    // reset is never granted it at all.
    match position(DeviceEvent::DmaEnabled) {
        Some(at) => {
            assert_eq!(
                at, 1,
                "DMA was not granted right after the reset: {events:?}"
            );
            assert!(
                !record.reset_refused,
                "a device that refused its reset was granted DMA: {events:?}"
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| **event == DeviceEvent::DmaEnabled)
                    .count(),
                1,
                "DMA was granted more than once: {events:?}"
            );
        }
        None => assert!(
            record.reset_refused,
            "the handshake ran without ever granting DMA: {events:?}"
        ),
    }
    if let Some(at) = position(DeviceEvent::Status(STATUS_ACKNOWLEDGE)) {
        assert!(
            position(DeviceEvent::Status(STATUS_ACKNOWLEDGE | STATUS_DRIVER))
                .is_some_and(|driver| driver > at),
            "ACKNOWLEDGE was not followed by ACKNOWLEDGE | DRIVER: {events:?}"
        );
    }
    for (index, event) in events.iter().enumerate() {
        match event {
            // Every write is a cumulative OR of the bits set so far, so a
            // device never sees `DRIVER` retract `ACKNOWLEDGE`. The one
            // exception is `STATUS_FAILED`, which retracts everything by
            // design.
            DeviceEvent::DriverFeatures(_) => assert!(
                position(DeviceEvent::Status(STATUS_ACKNOWLEDGE | STATUS_DRIVER))
                    .is_some_and(|acknowledged| acknowledged < index),
                "features were written before the driver announced itself: {events:?}"
            ),
            DeviceEvent::QueueConfigured(_) | DeviceEvent::DoorbellPlaced(_) => assert!(
                driver_ok.is_none_or(|at| index < at),
                "a queue was programmed after DRIVER_OK: {events:?}"
            ),
            DeviceEvent::Rang(_) => assert!(
                driver_ok.is_some_and(|at| index > at),
                "a doorbell was rung before DRIVER_OK: {events:?}"
            ),
            DeviceEvent::Reset | DeviceEvent::DmaEnabled | DeviceEvent::Status(_) => {}
        }
    }
}

/// Every outcome, matched to the answer that produced it.
///
/// A model rather than a smoke test: the branch alone would be satisfied by a
/// driver that refused for the wrong reason, or that named the wrong queue.
fn assert_outcome_matches_the_device(record: &DeviceRecord, outcome: SeamOutcome) {
    let signalled = record.events.contains(&DeviceEvent::Status(STATUS_FAILED));
    let error = match outcome {
        SeamOutcome::NotRun => unreachable!("the handshake is always driven"),
        SeamOutcome::Live => {
            assert!(!record.reset_refused, "a refused reset reached DRIVER_OK");
            assert_eq!(record.offered.len(), 1);
            assert!(
                record.offered[0] & features::VIRTIO_F_VERSION_1 != 0,
                "a device that never offered virtio 1.0 reached DRIVER_OK"
            );
            assert_eq!(record.status_reads.len(), 1, "the readback happens once");
            assert!(
                record.status_reads[0] & STATUS_FEATURES_OK != 0,
                "a device that refused the feature set reached DRIVER_OK"
            );
            assert!(
                record
                    .queues_reported
                    .first()
                    .is_some_and(|n| *n > TX_QUEUE),
                "a device with no transmit queue reached DRIVER_OK"
            );
            assert_eq!(record.queue_answers.len(), 2, "both queues are programmed");
            assert_eq!(
                record.doorbell_answers.len(),
                2,
                "both doorbells are placed"
            );
            assert!(record.queue_answers.iter().all(Result::is_ok));
            assert!(record.doorbell_answers.iter().all(Result::is_ok));
            assert!(!signalled, "a live device was told the driver had failed");
            return;
        }
        SeamOutcome::Refused(error) => error,
    };

    // Every rejection from `Offered` onward is raised with the device
    // reachable, so `signalled_to_device` must claim the write — and the
    // device's own record must show it. The claim is checked against what was
    // written, not against the enumeration that makes it.
    assert!(
        error.signalled_to_device(),
        "{error:?} was raised past the mapped BAR yet claims no signal"
    );
    assert!(
        signalled,
        "{error:?} claims a STATUS_FAILED it did not write"
    );

    match error {
        BringUpError::ResetRefused(ResetError::NotAcknowledged { .. }) => {
            assert!(record.reset_refused, "a reset was refused that was not");
            assert!(
                record.offered.is_empty(),
                "features were negotiated with a device that never reset"
            );
        }
        BringUpError::NoVirtio1 { offered } => {
            assert_eq!(record.offered.as_slice(), &[offered]);
            assert_eq!(offered & features::VIRTIO_F_VERSION_1, 0);
            assert!(
                !record
                    .events
                    .iter()
                    .any(|event| matches!(event, DeviceEvent::DriverFeatures(_))),
                "features were written to a device that cannot carry them"
            );
        }
        BringUpError::FeaturesRejected { status } => {
            assert_eq!(record.status_reads.as_slice(), &[status]);
            assert_eq!(status & STATUS_FEATURES_OK, 0);
            assert!(
                record.queue_answers.is_empty(),
                "a queue was programmed into a device that refused the features"
            );
        }
        BringUpError::TransmitQueueAbsent { offered, required } => {
            assert_eq!(record.queues_reported.as_slice(), &[offered]);
            assert_eq!(required, TX_QUEUE + 1);
            assert!(offered <= TX_QUEUE);
        }
        BringUpError::QueueSetupRefused { index, error } => {
            assert_eq!(
                index,
                driver_queue(record.queue_answers.len()),
                "the refusal named a queue other than the one being programmed"
            );
            assert_eq!(record.queue_answers.last().copied(), Some(Err(error)));
        }
        BringUpError::DoorbellRefused { index, error } => {
            assert_eq!(
                index,
                driver_queue(record.doorbell_answers.len()),
                "the refusal named a queue other than the one being programmed"
            );
            assert_eq!(record.doorbell_answers.last().copied(), Some(Err(error)));
            assert!(
                !record
                    .events
                    .iter()
                    .any(|event| matches!(event, DeviceEvent::Rang(_))),
                "a device whose doorbell could not be placed was rung"
            );
        }
        other => unreachable!("{other:?} cannot be raised past the mapped BAR"),
    }
}

/// Which virtqueue the driver was on when its `answers`-th answer refused.
///
/// `configure_queues` programs the receive queue and then the transmit queue,
/// so the count of answers the device has given *is* the call the driver was
/// making — which is what lets the assertions above tell the driver's own index
/// apart from the one the device put inside its error.
fn driver_queue(answers: usize) -> u16 {
    assert!(
        answers == 1 || answers == 2,
        "the driver made {answers} calls for two queues"
    );
    if answers == 1 { RX_QUEUE } else { TX_QUEUE }
}

/// The device's own reach into its mapped common-configuration structure.
///
/// Every method writes or reads one register the driver also reaches, at the
/// offset virtio 1.0 fixes. The point is the *timing*: a device answers each
/// access as it chooses, and re-arming a register between two driver calls is
/// the deterministic form of that, without a second thread whose unsynchronised
/// writes into the same volatile words would be a data race this harness
/// manufactured itself.
struct Registers {
    base: *mut u8,
}

impl Registers {
    /// # Safety
    /// `window` must name a live mapping of at least `common + 56` bytes, and
    /// `window + common` must be four-byte aligned — the same two facts
    /// `CommonCfg::new` requires, because this reaches the same registers.
    unsafe fn new(window: *mut u8, common: usize) -> Self {
        Self {
            // SAFETY: the caller guarantees the mapping covers `common + 56`
            // bytes, so `common` is inside it.
            base: unsafe { window.add(common) },
        }
    }

    /// Write one byte of the structure.
    fn arm8(&self, offset: usize, value: u8) {
        // SAFETY: every `offsets::` constant is under 56, which `Registers::new`
        // requires mapped; a byte access needs no alignment.
        unsafe { self.base.add(offset).write_volatile(value) };
    }

    /// Read one byte back, so a driver write can be checked where it landed.
    fn read8(&self, offset: usize) -> u8 {
        // SAFETY: as `arm8`.
        unsafe { self.base.add(offset).read_volatile() }
    }

    fn arm16(&self, offset: usize, value: u16) {
        // SAFETY: every `offsets::` constant used with a `u16` is even and
        // under 55, and the base is four-byte aligned per `Registers::new`.
        unsafe { self.base.add(offset).cast::<u16>().write_volatile(value) };
    }

    fn read16(&self, offset: usize) -> u16 {
        // SAFETY: as `arm16`.
        unsafe { self.base.add(offset).cast::<u16>().read_volatile() }
    }

    fn arm32(&self, offset: usize, value: u32) {
        // SAFETY: every `offsets::` constant used with a `u32` is a multiple of
        // four and under 53, and the base is four-byte aligned.
        unsafe { self.base.add(offset).cast::<u32>().write_volatile(value) };
    }

    /// Read one of the eight-byte registers as the two four-byte halves the
    /// driver writes it in.
    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: `QUEUE_DESC`/`QUEUE_DRIVER`/`QUEUE_DEVICE` are multiples of
        // four and end at 56, and the base is four-byte aligned.
        unsafe {
            let low = self.base.add(offset).cast::<u32>();
            u64::from(low.read_volatile()) | (u64::from(low.add(1).read_volatile()) << 32)
        }
    }
}

/// Drive the common-configuration registers against a device that answers each
/// access from the fuzzer's stream rather than from what the driver last wrote.
fn drive_registers(
    unstructured: &mut Unstructured<'_>,
    registers: &Registers,
    caps: &VirtioCaps,
    window: *mut u8,
    observed: &mut Observed,
) {
    // SAFETY: the caller established `caps.within(BAR_WINDOW_SIZE)` and
    // `caps.common_is_aligned()` over a live, page-aligned `BAR_WINDOW_SIZE`
    // window, which is `CommonCfg::new`'s contract in full; `registers` reaches
    // the same bytes and outlives neither.
    let common = unsafe { CommonCfg::new(window.add(caps.common as usize)) };
    let layout = &DriverVirtqueue::LAYOUT;
    // `LAYOUT.size` is `nic_driver_core::bringup::QUEUE_SIZE`, a driver
    // constant chosen so a loop bounded by it is bounded by a value the
    // adversary does not choose. It is not device input, so this
    // conversion cannot be driven to fail from outside.
    let required = u16::try_from(layout.size).expect("the driver's queue size fits a u16");

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(unstructured) else {
            break;
        };
        match op % 6 {
            0 => {
                // The device answers `queue_size` for *this* call, whatever the
                // previous call programmed — which is the whole point.
                let index = any_u16(unstructured);
                let device_max = any_u16(unstructured);
                let reported_notify_off = any_u16(unstructured);
                let sentinel = u64::from(any_u32(unstructured));
                registers.arm16(offsets::QUEUE_SIZE, device_max);
                registers.arm16(offsets::QUEUE_NOTIFY_OFF, reported_notify_off);
                registers.arm16(offsets::QUEUE_ENABLE, sentinel as u16);
                for area in [
                    offsets::QUEUE_DESC,
                    offsets::QUEUE_DRIVER,
                    offsets::QUEUE_DEVICE,
                ] {
                    registers.arm32(area, sentinel as u32);
                    registers.arm32(area + 4, (sentinel >> 32) as u32);
                }

                let expected = if device_max == 0 {
                    Err(QueueSetupError::QueueAbsent { index })
                } else if device_max < required {
                    Err(QueueSetupError::QueueTooSmall {
                        index,
                        device_max,
                        required: layout.size,
                    })
                } else {
                    Ok(reported_notify_off)
                };
                let outcome = common.setup_queue(index, layout, RING_PADDR);
                assert_eq!(
                    outcome, expected,
                    "setup_queue({index}) disagreed with the device's own queue_size {device_max}"
                );
                assert_eq!(
                    registers.read16(offsets::QUEUE_SELECT),
                    index,
                    "setup_queue selected a queue other than the one it was asked for"
                );

                match outcome {
                    Err(error) => {
                        // "Nothing is programmed in either case, so a caller
                        // that gives up leaves the device with no ring
                        // addresses it could act on" — checked, not believed.
                        assert_eq!(
                            registers.read16(offsets::QUEUE_ENABLE),
                            sentinel as u16,
                            "a refused queue was enabled anyway"
                        );
                        for area in [
                            offsets::QUEUE_DESC,
                            offsets::QUEUE_DRIVER,
                            offsets::QUEUE_DEVICE,
                        ] {
                            assert_eq!(
                                registers.read64(area),
                                sentinel,
                                "a refused queue was given a ring address"
                            );
                        }
                        let refused_index = match error {
                            QueueSetupError::QueueAbsent { index }
                            | QueueSetupError::QueueTooSmall { index, .. } => index,
                        };
                        match refused_index {
                            RX_QUEUE => observed.receive_queue_refused += 1,
                            TX_QUEUE => observed.transmit_queue_refused += 1,
                            _ => observed.other_queue_refused += 1,
                        }
                    }
                    Ok(_) => {
                        assert_eq!(registers.read16(offsets::QUEUE_SIZE), required);
                        assert_eq!(registers.read16(offsets::QUEUE_ENABLE), 1);
                        for (area, offset) in [
                            (offsets::QUEUE_DESC, layout.descriptor_offset),
                            (offsets::QUEUE_DRIVER, layout.driver_offset),
                            (offsets::QUEUE_DEVICE, layout.device_offset),
                        ] {
                            assert_eq!(
                                registers.read64(area),
                                RING_PADDR + offset as u64,
                                "a queue area was programmed somewhere other than its layout \
                                 offset within the ring"
                            );
                        }
                        observed.queues_programmed += 1;
                    }
                }
            }
            1 => {
                let offered = any_u16(unstructured);
                registers.arm16(offsets::NUM_QUEUES, offered);
                assert_eq!(
                    common.num_queues(),
                    offered,
                    "num_queues read a register other than the device's"
                );
            }
            2 => {
                // Both halves come back from the one un-banked word, which is
                // the third behaviour this target cannot express (see the
                // module header). Asserting it is what keeps the limitation
                // visible instead of implicit.
                let word = any_u32(unstructured);
                registers.arm32(offsets::DEVICE_FEATURE, word);
                assert_eq!(
                    common.device_features(),
                    u64::from(word) | (u64::from(word) << 32),
                    "device_features read a register other than the device's"
                );
            }
            3 => {
                let held = any_u32(unstructured) as u8;
                registers.arm8(offsets::DEVICE_STATUS, held);
                assert_eq!(
                    common.status(),
                    held,
                    "status read a register other than the device's"
                );
                let written = any_u32(unstructured) as u8;
                common.set_status(written);
                assert_eq!(
                    registers.read8(offsets::DEVICE_STATUS),
                    written,
                    "set_status wrote a register other than the device's"
                );
            }
            4 => {
                // Over a window that echoes the driver's own write, the poll
                // always sees the zero `reset` just placed. The success path is
                // still worth asserting; `ResetError::NotAcknowledged` is the
                // first of the three unreachable behaviours the header records.
                registers.arm8(offsets::DEVICE_STATUS, any_u32(unstructured) as u8);
                assert_eq!(common.reset(), Ok(()));
                assert_eq!(registers.read8(offsets::DEVICE_STATUS), 0);
            }
            _ => {
                let reported = any_u16(unstructured);
                let queue = any_u16(unstructured);
                // SAFETY: `window` names the live, page-aligned
                // `BAR_WINDOW_SIZE` mapping this function was called with, and
                // page alignment subsumes the two bytes `Doorbell::new` asks
                // for. The device's own `notify_off` needs nothing from this
                // side — `Doorbell::new` bounds and aligns it.
                let placed = unsafe { Doorbell::new(window, BAR_WINDOW_SIZE, caps, reported) };
                let fits = caps.notify_slot_within(reported, BAR_WINDOW_SIZE);
                let offset = (caps.notify as usize).wrapping_add(
                    (reported as usize).wrapping_mul(caps.notify_multiplier as usize),
                );
                match placed {
                    Ok(doorbell) => {
                        assert!(fits, "a doorbell outside the window was placed");
                        assert!(offset.is_multiple_of(2), "an odd doorbell was placed");
                        doorbell.ring(queue);
                        // SAFETY: `fits` puts `offset + 2` inside the window and
                        // the parity check makes the `u16` naturally aligned.
                        let landed = unsafe { window.add(offset).cast::<u16>().read_volatile() };
                        assert_eq!(
                            landed, queue,
                            "ringing the doorbell did not write the queue index at the offset the \
                             device named"
                        );
                        observed.doorbells_placed += 1;
                    }
                    Err(NotifyError::SlotOutsideBar { bar_size, .. }) => {
                        assert_eq!(bar_size, BAR_WINDOW_SIZE);
                        assert!(!fits, "a doorbell inside the window was refused as outside");
                        observed.doorbells_refused += 1;
                    }
                    Err(NotifyError::SlotMisaligned {
                        offset: reported_offset,
                    }) => {
                        assert!(fits, "a fitting doorbell was refused for its parity");
                        assert_eq!(reported_offset, offset);
                        assert!(!offset.is_multiple_of(2));
                        observed.doorbells_refused += 1;
                    }
                }
            }
        }
    }
}

/// Copy `bytes` over the front of a region, leaving the rest zeroed.
///
/// # Safety
/// `region` must point to at least `capacity` writable bytes that no other
/// reference aliases for the duration of the call.
unsafe fn overwrite(region: *mut u8, capacity: usize, bytes: &[u8]) {
    let len = bytes.len().min(capacity);
    // SAFETY: `len <= capacity` and the caller guarantees `capacity` writable,
    // unaliased bytes at `region`; `bytes` is a separate borrow of the fuzzer's
    // input, so the ranges cannot overlap.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), region, len) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Offsets within a PCI configuration space this builder writes.
    const PCI_STATUS: usize = 0x06;
    const PCI_CAPABILITIES_PTR: usize = 0x34;
    const PCI_BAR0: usize = 0x10;
    /// PCI status bit 4: a capability list is present.
    const PCI_STATUS_CAP_LIST: u16 = 1 << 4;
    /// A 64-bit memory BAR: bit 0 clear, bits [2:1] == 0b10.
    const BAR_TYPE_MEMORY_64: u32 = 0b100;
    const PCI_CAP_ID_VNDR: u8 = 0x09;

    /// Where this builder puts the four virtio structures inside the BAR.
    const COMMON_OFFSET: u32 = 0x100;
    const NOTIFY_OFFSET: u32 = 0x200;
    const NOTIFY_MULTIPLIER: u32 = 4;
    const DEVICE_OFFSET: u32 = 0x300;

    /// A well-formed virtio-net capability chain, as a device would present it.
    ///
    /// Built rather than committed as a blob so a demonstration below reads as
    /// the device it describes; the bytes it produces *are* the committed seed,
    /// which `every_demonstration_is_the_committed_seed_of_its_name` holds.
    fn ecam_page() -> Vec<u8> {
        ecam_page_with(NOTIFY_OFFSET, NOTIFY_MULTIPLIER)
    }

    /// The same chain with the notify structure the device's own choice, so a
    /// doorbell offset's *parity* — the one `Doorbell::new` refuses separately
    /// from its extent — is reachable.
    fn ecam_page_with(notify: u32, multiplier: u32) -> Vec<u8> {
        let mut page = vec![0u8; 0x100];
        page[PCI_STATUS..PCI_STATUS + 2].copy_from_slice(&PCI_STATUS_CAP_LIST.to_le_bytes());
        page[PCI_BAR0..PCI_BAR0 + 4].copy_from_slice(&BAR_TYPE_MEMORY_64.to_le_bytes());
        page[PCI_CAPABILITIES_PTR] = 0x40;

        // id, next, cap_len, cfg_type, bar, .., offset @8, multiplier @16
        fn cap(page: &mut [u8], at: usize, next: u8, len: u8, cfg_type: u8, offset: u32) {
            page[at] = PCI_CAP_ID_VNDR;
            page[at + 1] = next;
            page[at + 2] = len;
            page[at + 3] = cfg_type;
            page[at + 4] = 0; // every structure in BAR 0
            page[at + 8..at + 12].copy_from_slice(&offset.to_le_bytes());
        }
        cap(&mut page, 0x40, 0x60, 16, 1, COMMON_OFFSET);
        cap(&mut page, 0x60, 0x80, 20, 2, notify);
        page[0x60 + 16..0x60 + 20].copy_from_slice(&multiplier.to_le_bytes());
        cap(&mut page, 0x80, 0xA0, 16, 3, 0);
        cap(&mut page, 0xA0, 0x00, 16, 4, DEVICE_OFFSET);
        page
    }

    /// An empty device script: [`ScriptedDevice`] answers every access from a
    /// spent stream, which is the conforming answer everywhere, so this is the
    /// device that reaches `DRIVER_OK`.
    const CONFORMING: &[u8] = &[];

    /// A [`ScriptedDevice`] script, written as the fixed-width `u32` words the
    /// device reads.
    ///
    /// Every answer costs the same number of words whichever shape it takes, so
    /// a script is a flat sequence a demonstration can spell out and a
    /// libFuzzer mutation cannot desynchronise by changing one branch.
    #[derive(Default)]
    struct Script {
        words: Vec<u32>,
    }

    impl Script {
        /// A selector that takes the `shape`-th deviating answer, or the
        /// conforming one.
        fn selector(shape: Option<u32>) -> u32 {
            match shape {
                Some(shape) => shape * DEVIATION + (DEVIATION - 1),
                None => 0,
            }
        }

        fn answer(mut self, shape: Option<u32>, payload: &[u32]) -> Self {
            self.words.push(Self::selector(shape));
            self.words.extend_from_slice(payload);
            self
        }

        /// `reset`: refused with the status the device holds, or acknowledged.
        fn reset(self, refused_with: Option<u8>) -> Self {
            self.answer(
                refused_with.map(|_| 0),
                &[u32::from(refused_with.unwrap_or(0))],
            )
        }

        /// `device_features`: the two halves the device reports, independently.
        /// A conforming device has `VIRTIO_F_VERSION_1` added to whatever it
        /// names; a deviating one reports the halves verbatim.
        fn device_features(self, conforming: bool, high: u32, low: u32) -> Self {
            self.answer((!conforming).then_some(0), &[high, low])
        }

        /// `status`: the readback, either the byte the driver last wrote or one
        /// of the device's own choosing.
        fn status(self, readback: Option<u8>) -> Self {
            self.answer(readback.map(|_| 0), &[u32::from(readback.unwrap_or(0))])
        }

        /// `num_queues`: two, or a count of the device's choosing.
        fn num_queues(self, reported: Option<u16>) -> Self {
            self.answer(reported.map(|_| 0), &[u32::from(reported.unwrap_or(0))])
        }

        /// `setup_queue`: accepted with a `queue_notify_off`, or refused with
        /// an error whose own index the device picks freely.
        fn setup_queue(self, answer: Result<u16, QueueSetupError>) -> Self {
            match answer {
                Ok(notify_off) => self.answer(None, &[u32::from(notify_off), 0, 0, 0]),
                Err(QueueSetupError::QueueAbsent { index }) => {
                    self.answer(Some(0), &[0, u32::from(index), 0, 0])
                }
                Err(QueueSetupError::QueueTooSmall {
                    index,
                    device_max,
                    required,
                }) => self.answer(
                    Some(1),
                    &[0, u32::from(index), u32::from(device_max), required as u32],
                ),
            }
        }

        /// `place_doorbell`: placed, or refused for one of the two reasons
        /// `Doorbell::new` has.
        fn place_doorbell(self, answer: Result<(), NotifyError>) -> Self {
            match answer {
                Ok(()) => self.answer(None, &[0, 0]),
                Err(NotifyError::SlotMisaligned { offset }) => {
                    self.answer(Some(0), &[offset as u32, 0])
                }
                Err(NotifyError::SlotOutsideBar {
                    slot_end: Some(end),
                    bar_size,
                }) => self.answer(Some(1), &[end as u32, bar_size as u32]),
                Err(NotifyError::SlotOutsideBar {
                    slot_end: None,
                    bar_size,
                }) => self.answer(Some(2), &[0, bar_size as u32]),
            }
        }

        fn bytes(self) -> Vec<u8> {
            self.words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect()
        }
    }

    /// One harness input, so a demonstration reads as the device it drives.
    struct Input {
        bytes: Vec<u8>,
    }

    impl Input {
        /// The fixed prefix plus the three disjoint region images, in exactly
        /// the widths [`observe`] reads them in — a `u16` for `notify_off` and
        /// a `u32` for the rest.
        fn new(stamp_ids: bool, bar_paddr: u32, page: &[u8], window: &[u8], device: &[u8]) -> Self {
            let mut bytes = Vec::new();
            for value in [u32::from(stamp_ids), 0] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            bytes.extend_from_slice(&0u16.to_le_bytes()); // notify_off
            for value in [0, 0, bar_paddr] {
                bytes.extend_from_slice(&u32::to_le_bytes(value));
            }
            // `take_run` reduces the requested length modulo one more than what
            // is left, and each run is shorter than that, so the exact length
            // survives the reduction.
            for run in [page, window, device] {
                bytes.extend_from_slice(&(run.len() as u32).to_le_bytes());
            }
            for run in [page, window, device] {
                bytes.extend_from_slice(run);
            }
            Self { bytes }
        }

        fn op(mut self, op: u8) -> Self {
            self.bytes.push(op);
            self
        }

        fn u16_arg(mut self, value: u16) -> Self {
            self.bytes.extend_from_slice(&value.to_le_bytes());
            self
        }

        fn u32_arg(mut self, value: u32) -> Self {
            self.bytes.extend_from_slice(&value.to_le_bytes());
            self
        }

        /// One `setup_queue` call, with the device's answers for it.
        fn setup_queue(self, index: u16, device_max: u16, notify_off: u16, sentinel: u32) -> Self {
            self.op(0)
                .u16_arg(index)
                .u16_arg(device_max)
                .u16_arg(notify_off)
                .u32_arg(sentinel)
        }

        fn num_queues(self, offered: u16) -> Self {
            self.op(1).u16_arg(offered)
        }

        fn device_features(self, word: u32) -> Self {
            self.op(2).u32_arg(word)
        }

        fn status(self, held: u8, written: u8) -> Self {
            self.op(3)
                .u32_arg(u32::from(held))
                .u32_arg(u32::from(written))
        }

        fn reset(self, held: u8) -> Self {
            self.op(4).u32_arg(u32::from(held))
        }

        /// One `Doorbell::new` placement for a `queue_notify_off` the device
        /// reports, followed by a ring if it is placed.
        fn doorbell(self, reported: u16, queue: u16) -> Self {
            self.op(5).u16_arg(reported).u16_arg(queue)
        }

        fn bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    /// The committed seed of that name.
    fn seed(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join("find_virtio_caps")
            .join(name);
        fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    /// Finding 3, made an ordinary input: the receive queue is programmed and
    /// the transmit queue is then refused, because the device answers
    /// `queue_size` afresh for the second call instead of echoing the 16 the
    /// first call wrote. `configure_queues` reads one un-banked word for both
    /// queues, so no input to the bring-up chain can produce this.
    fn transmit_queue_refused() -> Vec<u8> {
        Input::new(true, 0x4000, &ecam_page(), &[], CONFORMING)
            .setup_queue(RX_QUEUE, 64, 0x10, 0xA5A5_A5A5)
            .setup_queue(TX_QUEUE, 0, 0x11, 0xA5A5_A5A5)
            .setup_queue(TX_QUEUE, 8, 0x12, 0xA5A5_A5A5)
            .bytes()
    }

    /// The permanent regression seed for the closed misalignment finding: a
    /// device whose common-configuration offset fits the window perfectly and
    /// is odd. `identify` must refuse it before any `CommonCfg` exists.
    fn unaligned_common_cfg_offset() -> Vec<u8> {
        let mut page = ecam_page();
        page[0x40 + 8..0x40 + 12].copy_from_slice(&(COMMON_OFFSET + 1).to_le_bytes());
        Input::new(true, 0x4000, &page, &[], CONFORMING).bytes()
    }

    /// A chain the walk resolves, driven all the way to `DRIVER_OK`: the
    /// device offers virtio 1.0 in both feature halves, two virtqueues, a queue
    /// size above the driver's, and an in-window doorbell slot.
    fn handshake_to_driver_ok() -> Vec<u8> {
        let mut window = vec![0u8; 0x140];
        let common = COMMON_OFFSET as usize;
        // Both selector windows read the same word, so bit 0 set makes
        // `device_features` report VIRTIO_F_VERSION_1 (feature bit 32).
        window[common + offsets::DEVICE_FEATURE..common + offsets::DEVICE_FEATURE + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        window[common + offsets::NUM_QUEUES..common + offsets::NUM_QUEUES + 2]
            .copy_from_slice(&2u16.to_le_bytes());
        window[common + offsets::QUEUE_SIZE..common + offsets::QUEUE_SIZE + 2]
            .copy_from_slice(&64u16.to_le_bytes());
        window[common + offsets::QUEUE_NOTIFY_OFF..common + offsets::QUEUE_NOTIFY_OFF + 2]
            .copy_from_slice(&8u16.to_le_bytes());
        Input::new(true, 0x4000, &ecam_page(), &window, CONFORMING).bytes()
    }

    /// A chain the walk resolves over a page carrying some other device's ids:
    /// `find_virtio_caps` succeeds and `identify` refuses with `NotVirtioNet`,
    /// so the register stage is exercised on a device bring-up will not touch.
    fn chain_without_ids() -> Vec<u8> {
        Input::new(false, 0x4000, &ecam_page(), &[], CONFORMING)
            .setup_queue(RX_QUEUE, 64, 0x10, 0)
            .bytes()
    }

    /// Only the common-configuration capability: the walk must refuse the whole
    /// device rather than resolve three of the four structures.
    fn common_only() -> Vec<u8> {
        let mut page = ecam_page();
        page[0x40 + 1] = 0; // terminate the chain after the common cap
        Input::new(true, 0x4000, &page, &[], CONFORMING).bytes()
    }

    /// The whole register op table, so the seed corpus covers every access the
    /// device answers rather than only `setup_queue`: an offered queue count, a
    /// feature bitmap, a status byte the driver did not write, a reset, an
    /// in-window doorbell, one past the end of the window, and one at an odd
    /// offset. `notify = 0x200` with `multiplier = 4` puts slot `n` at
    /// `0x200 + 4n`, so `0xF80` is the last that fits a `0x4000` window and
    /// `0xFFF` is far outside it.
    fn device_answers_each_register() -> Vec<u8> {
        Input::new(true, 0x4000, &ecam_page(), &[], CONFORMING)
            .num_queues(0xBEEF)
            .device_features(0x8000_0001)
            .status(0x5A, 0xA5)
            .reset(0xFF)
            .doorbell(1, 7)
            .doorbell(0xF7F, 3)
            .doorbell(0xFFF, 9)
            .bytes()
    }

    /// A conforming device up to the point a demonstration takes over: reset
    /// acknowledged, virtio 1.0 offered, `FEATURES_OK` kept, two virtqueues.
    fn negotiated() -> Script {
        Script::default()
            .reset(None)
            .device_features(true, 0, 0)
            .status(None)
            .num_queues(None)
    }

    /// The whole input for a device script, over a chain that resolves — so a
    /// failure names the seam rather than leaving the walk as a suspect.
    fn seam_input(script: Script) -> Vec<u8> {
        Input::new(true, 0x4000, &ecam_page(), &[], &script.bytes()).bytes()
    }

    /// A device that never acknowledges its reset, holding `0x42` throughout.
    /// `CommonCfg::reset` polls the byte it just zeroed, so over a mapped
    /// window this branch cannot be produced at all.
    fn reset_never_acknowledged() -> Vec<u8> {
        seam_input(Script::default().reset(Some(0x42)))
    }

    /// A device that clears `FEATURES_OK` when the driver reads the status back
    /// inside the same call that set it — the refusal virtio 1.0 section 3.1.1
    /// requires initialization to stop on, and the one the readback exists to
    /// catch.
    fn features_ok_cleared_on_readback() -> Vec<u8> {
        seam_input(
            Script::default()
                .reset(None)
                .device_features(true, 0, 0)
                .status(Some(STATUS_ACKNOWLEDGE | STATUS_DRIVER)),
        )
    }

    /// A feature bitmap whose high 32 bits differ from its low 32, and which
    /// omits virtio 1.0. `CommonCfg::device_features` reads one un-banked word
    /// under both selector settings, so only `high == low` exists there.
    fn feature_halves_disagree() -> Vec<u8> {
        seam_input(
            Script::default()
                .reset(None)
                .device_features(false, 0xF000_0000, 0xFFFF_FFFF),
        )
    }

    /// A device that takes the receive queue and refuses the transmit one. The
    /// index inside its error is `0xBEEF`, which is neither queue: the driver
    /// must name the queue *it* was programming.
    fn transmit_queue_refused_by_the_device() -> Vec<u8> {
        seam_input(
            negotiated()
                .setup_queue(Ok(0x10))
                .place_doorbell(Ok(()))
                .setup_queue(Err(QueueSetupError::QueueTooSmall {
                    index: 0xBEEF,
                    device_max: 4,
                    required: 16,
                })),
        )
    }

    /// A device that programmes both queues and then names a transmit doorbell
    /// slot at an odd offset. Reached only after the receive doorbell was
    /// placed, which is the ordering `configure_queues` fixes.
    fn transmit_doorbell_refused() -> Vec<u8> {
        seam_input(
            negotiated()
                .setup_queue(Ok(0x10))
                .place_doorbell(Ok(()))
                .setup_queue(Ok(0x11))
                .place_doorbell(Err(NotifyError::SlotMisaligned { offset: 0x3001 })),
        )
    }

    /// A notify structure at an odd offset with a multiplier of one: slot `n`
    /// sits at `0x201 + n`, so the device can name a doorbell that fits the
    /// window perfectly and is still an unaligned `u16` write — the parity
    /// refusal, which no multiple-of-four notify structure can reach.
    fn odd_doorbell_slot() -> Vec<u8> {
        Input::new(true, 0x4000, &ecam_page_with(0x201, 1), &[], CONFORMING)
            .doorbell(0, 1)
            .doorbell(1, 2)
            .bytes()
    }

    #[test]
    fn the_device_answers_every_register_the_driver_reads() {
        let observed = observe(&device_answers_each_register());
        assert!(observed.caps_found);
        assert_eq!(
            observed.doorbells_placed, 2,
            "an in-window doorbell was not placed: {observed:?}"
        );
        assert_eq!(
            observed.doorbells_refused, 1,
            "an out-of-window doorbell was not refused: {observed:?}"
        );
    }

    #[test]
    fn an_odd_doorbell_offset_is_refused_separately_from_an_out_of_window_one() {
        let observed = observe(&odd_doorbell_slot());
        assert_eq!(
            observed.doorbells_refused, 1,
            "the odd doorbell slot was not refused: {observed:?}"
        );
        assert_eq!(
            observed.doorbells_placed, 1,
            "the even doorbell slot was not placed: {observed:?}"
        );
    }

    #[test]
    fn a_chain_missing_a_structure_resolves_to_nothing() {
        let observed = observe(&common_only());
        assert!(
            !observed.caps_found,
            "three of four structures resolved a device: {observed:?}"
        );
    }

    #[test]
    fn a_resolved_chain_on_a_foreign_device_still_drives_the_registers() {
        let observed = observe(&chain_without_ids());
        assert!(observed.caps_found);
        assert!(
            !observed.identified,
            "a device that is not virtio-net was identified: {observed:?}"
        );
        assert_eq!(observed.queues_programmed, 1);
    }

    #[test]
    fn the_transmit_queue_can_be_refused_while_the_receive_queue_is_programmed() {
        let observed = observe(&transmit_queue_refused());
        assert!(observed.caps_found);
        assert_eq!(
            observed.queues_programmed, 1,
            "the receive queue was not programmed: {observed:?}"
        );
        assert_eq!(
            observed.transmit_queue_refused, 2,
            "the transmit queue was not refused: {observed:?}"
        );
        assert_eq!(observed.receive_queue_refused, 0);
    }

    #[test]
    fn a_misaligned_common_offset_is_refused_before_any_common_cfg_exists() {
        let observed = observe(&unaligned_common_cfg_offset());
        assert!(observed.caps_found, "the chain no longer parses");
        assert!(
            !observed.identified,
            "an odd common-configuration offset was identified: {observed:?}"
        );
    }

    #[test]
    fn a_conforming_device_reaches_driver_ok() {
        let observed = observe(&handshake_to_driver_ok());
        assert!(
            observed.reached_driver_ok,
            "the handshake stalled: {observed:?}"
        );
    }

    /// The seam's outcome for one demonstration.
    fn seam(input: &[u8]) -> SeamObserved {
        observe(input).seam
    }

    #[test]
    fn a_device_that_never_acknowledges_its_reset_is_refused() {
        let observed = seam(&reset_never_acknowledged());
        assert_eq!(
            observed.outcome,
            SeamOutcome::Refused(BringUpError::ResetRefused(ResetError::NotAcknowledged {
                status: 0x42,
            })),
            "the refused reset did not reach ResetRefused: {observed:?}"
        );
    }

    #[test]
    fn a_device_clearing_features_ok_on_readback_stops_initialization() {
        let observed = seam(&features_ok_cleared_on_readback());
        assert_eq!(
            observed.outcome,
            SeamOutcome::Refused(BringUpError::FeaturesRejected {
                status: STATUS_ACKNOWLEDGE | STATUS_DRIVER,
            }),
            "the cleared FEATURES_OK did not reach FeaturesRejected: {observed:?}"
        );
    }

    #[test]
    fn a_feature_bitmap_whose_halves_disagree_is_expressible() {
        let observed = seam(&feature_halves_disagree());
        assert!(
            observed.split_feature_halves,
            "the two feature halves came back equal: {observed:?}"
        );
        assert_eq!(
            observed.outcome,
            SeamOutcome::Refused(BringUpError::NoVirtio1 {
                offered: 0xF000_0000_FFFF_FFFF,
            }),
            "the bitmap the device offered is not the one reported: {observed:?}"
        );
    }

    #[test]
    fn the_transmit_queue_is_refused_after_the_receive_queue_was_programmed() {
        let observed = seam(&transmit_queue_refused_by_the_device());
        assert_eq!(
            observed.outcome,
            SeamOutcome::Refused(BringUpError::QueueSetupRefused {
                index: TX_QUEUE,
                error: QueueSetupError::QueueTooSmall {
                    index: 0xBEEF,
                    device_max: 4,
                    required: 16,
                },
            }),
            "the transmit queue's refusal did not name the transmit queue: {observed:?}"
        );
    }

    #[test]
    fn the_transmit_doorbell_is_refused_after_both_queues_were_programmed() {
        let observed = seam(&transmit_doorbell_refused());
        assert_eq!(
            observed.outcome,
            SeamOutcome::Refused(BringUpError::DoorbellRefused {
                index: TX_QUEUE,
                error: NotifyError::SlotMisaligned { offset: 0x3001 },
            }),
            "the transmit doorbell's refusal did not name the transmit queue: {observed:?}"
        );
    }

    #[test]
    fn a_spent_device_script_is_a_conforming_device_that_reaches_driver_ok() {
        // The bias's other half: `any_u32` yields zero once the input is spent
        // and zero is the conforming answer everywhere, so a short input drives
        // the deep states instead of dying at the reset. Every seed built with
        // `CONFORMING` rests on this.
        let observed = seam(&handshake_to_driver_ok());
        assert_eq!(
            observed.outcome,
            SeamOutcome::Live,
            "a spent script did not reach DRIVER_OK: {observed:?}"
        );
    }

    /// The offsets [`drive_registers`] arms are the ones the crate's own
    /// accessors read and write. Without this the register stage could arm a
    /// byte no accessor looks at, and every "the device answered" assertion
    /// would be comparing the harness with itself.
    #[test]
    fn the_register_offsets_are_the_ones_virtio_1_0_fixes() {
        let window = ZeroedRegion::<BarWindow>::new();
        let base = window.as_ptr().cast::<u8>();
        // SAFETY: a live, zeroed, page-aligned `BAR_WINDOW_SIZE` region, with
        // the structure at offset 0 — trivially within it and four-byte
        // aligned, which is `CommonCfg::new`'s contract.
        let common = unsafe { CommonCfg::new(base) };
        // SAFETY: the same region and the same offset.
        let registers = unsafe { Registers::new(base, 0) };
        let caps = VirtioCaps {
            bar: 0,
            common: 0,
            notify: 0x200,
            notify_multiplier: 4,
            device: 0x300,
        };

        registers.arm8(offsets::DEVICE_STATUS, 0xA5);
        assert_eq!(common.status(), 0xA5);
        common.set_status(0x5A);
        assert_eq!(registers.read8(offsets::DEVICE_STATUS), 0x5A);

        registers.arm16(offsets::NUM_QUEUES, 0x1234);
        assert_eq!(common.num_queues(), 0x1234);

        registers.arm32(offsets::DEVICE_FEATURE, 0xDEAD_BEEF);
        assert_eq!(common.device_features(), 0xDEAD_BEEF_DEAD_BEEF);

        let layout = &DriverVirtqueue::LAYOUT;
        registers.arm16(offsets::QUEUE_SIZE, 0);
        assert_eq!(
            common.setup_queue(7, layout, RING_PADDR),
            Err(QueueSetupError::QueueAbsent { index: 7 })
        );
        assert_eq!(registers.read16(offsets::QUEUE_SELECT), 7);

        registers.arm16(offsets::QUEUE_SIZE, 4);
        assert_eq!(
            common.setup_queue(1, layout, RING_PADDR),
            Err(QueueSetupError::QueueTooSmall {
                index: 1,
                device_max: 4,
                required: layout.size,
            })
        );

        registers.arm16(offsets::QUEUE_SIZE, 32);
        registers.arm16(offsets::QUEUE_NOTIFY_OFF, 0x99);
        assert_eq!(common.setup_queue(1, layout, RING_PADDR), Ok(0x99));
        assert_eq!(registers.read16(offsets::QUEUE_ENABLE), 1);
        assert_eq!(
            registers.read64(offsets::QUEUE_DESC),
            RING_PADDR + layout.descriptor_offset as u64
        );
        assert_eq!(
            registers.read64(offsets::QUEUE_DRIVER),
            RING_PADDR + layout.driver_offset as u64
        );
        assert_eq!(
            registers.read64(offsets::QUEUE_DEVICE),
            RING_PADDR + layout.device_offset as u64
        );

        // SAFETY: a live, page-aligned window of exactly `BAR_WINDOW_SIZE`
        // bytes; the device offsets in `caps` are bounded by `Doorbell::new`.
        let doorbell = unsafe { Doorbell::new(base, BAR_WINDOW_SIZE, &caps, 1) }
            .expect("0x200 + 1 * 4 is inside the window and even");
        doorbell.ring(3);
        // SAFETY: the slot just proved in bounds and two-byte aligned.
        assert_eq!(unsafe { base.add(0x204).cast::<u16>().read_volatile() }, 3);
    }

    fn seed_table() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("transmit_queue_refused", transmit_queue_refused()),
            ("unaligned_common_cfg_offset", unaligned_common_cfg_offset()),
            ("handshake_to_driver_ok", handshake_to_driver_ok()),
            ("chain_without_ids", chain_without_ids()),
            ("common_only", common_only()),
            (
                "device_answers_each_register",
                device_answers_each_register(),
            ),
            ("odd_doorbell_slot", odd_doorbell_slot()),
            ("reset_never_acknowledged", reset_never_acknowledged()),
            (
                "features_ok_cleared_on_readback",
                features_ok_cleared_on_readback(),
            ),
            ("feature_halves_disagree", feature_halves_disagree()),
            (
                "transmit_queue_refused_by_the_device",
                transmit_queue_refused_by_the_device(),
            ),
            ("transmit_doorbell_refused", transmit_doorbell_refused()),
        ]
    }

    #[test]
    fn every_demonstration_is_the_committed_seed_of_its_name() {
        for (name, built) in seed_table() {
            assert_eq!(
                seed(name),
                built,
                "seed {name} is not the input it stands for"
            );
        }
    }
}
