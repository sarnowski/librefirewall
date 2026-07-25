//! `virtio::pci` and the bring-up chain that consumes it, under a hostile or
//! malfunctioning device.
//!
//! # The adversary and the surface
//!
//! Every byte of a PCI function's 4 KiB configuration space is the device's
//! (CONCEPT §7.1, hostile or malfunctioning device). The capability chain the
//! driver walks to find the virtio structures is therefore attacker-controlled
//! in its entirety: the chain pointers, the capability lengths and types, the
//! BAR index, and all four structure offsets. So is the BAR window the driver
//! then maps, which is where the common-configuration registers and the
//! doorbells live.
//!
//! # What the adversary may express here
//!
//! The whole page, verbatim, plus — chosen freely by the fuzzer — the
//! `queue_notify_off` a device would report, the BAR-window sizes the offsets
//! are bounded against, the BAR index a caller probes, and the physical address
//! the BAR is relocated to. One input bit stamps the virtio-net `(vendor,
//! device)` id pair into the page. That bit only makes the deep chain
//! *reachable often*: the unstamped page is still fully generated, and the ids
//! are two bytes the fuzzer could always have produced itself, so nothing is
//! excluded — it converts a 1-in-2^32 coin flip into a coverage plateau the
//! fuzzer can build on.
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
//!   The previous harness called `within` and threw the answer away as
//!   "intentionally unasserted", which tested nothing at all.
//! * **The typed BAR-index boundary.** `bar_is_64bit` refuses exactly the
//!   indices above 5, and `reprogram_bar64` additionally refuses BAR 5.
//! * **The precondition chain `PlacedBar::map` rests on, in full.** `map`'s
//!   safety comment names `identify` as the component that established *two*
//!   independent facts about a device-chosen offset — `within(BAR_WINDOW_SIZE)`
//!   for the extent and `common_is_aligned()` for the alignment. Both are
//!   asserted here on every successful `identify`, so the named guarantor is
//!   checked rather than believed (AGENTS.md DOC-6, DOC-7). Asserting only the
//!   extent would leave the half that was actually missing unchecked, which is
//!   how the finding below came to exist.
//! * **The handshake is driven to `DRIVER_OK`** over a fuzzer-filled BAR
//!   window, so the device's `device_features`, `num_queues`, `queue_size` and
//!   `queue_notify_off` answers all come from the adversary.
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
//! delegation chain terminated nowhere, which is the DOC-7 failure mode, and
//! `map`'s safety comment named `identify` as the guarantor of something
//! `identify` did not guarantee (DOC-6).
//!
//! **What closed it.** The fix is in the crates that own the fault, not here:
//! `virtio::pci::VirtioCaps::common_is_aligned` is the predicate, and
//! `nic_driver_core::bringup::identify` now refuses a device that fails it with
//! `BringUpError::CommonCfgMisaligned` before any `CommonCfg` is constructed.
//! Per TEST-10 the finding is a regression test in each owning crate's own
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
//! the reach that found the defect, which is the TEST-8 failure mode.

use arbitrary::Unstructured;
use nic_driver_core::bringup::{ACCEPTED_FEATURES, BAR_WINDOW_SIZE, identify};
use virtio::pci::{BarError, PciConfig, find_virtio_caps};

use crate::region::{ECAM_PAGE_BYTES, EcamPage, ZeroedRegion};
use crate::{any_u16, any_u32};

/// Offset of the `vendor_id`/`device_id` pair in configuration space.
const PCI_IDS_OFFSET: usize = 0;
/// The `(vendor, device)` pair `nic_driver_core::bringup::identify` insists on.
const VIRTIO_NET_IDS: [u8; 4] = [0xF4, 0x1A, 0x41, 0x10];

/// The BAR window the driver maps, as its own over-aligned type.
///
/// Page-aligned for the same reason [`EcamPage`] is: `Doorbell::new`'s contract
/// requires the window to be at least two-byte aligned, and `PlacedBar::map`
/// forms the common-configuration pointer by adding a device-supplied offset to
/// this base. A harness that supplied an under-aligned base would be
/// manufacturing its own misalignment and could not tell the device's apart.
#[repr(C, align(4096))]
struct BarWindow([u8; BAR_WINDOW_SIZE]);

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

/// Drive the capability walk, the bounds predicates, and the bring-up chain
/// over a device-controlled configuration space and BAR window.
pub fn find_virtio_caps_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let stamp_ids = (any_u32(&mut unstructured) & 1) == 1;
    let probe_bar = any_u32(&mut unstructured) as u8;
    let notify_off = any_u16(&mut unstructured);
    let window_a = any_u32(&mut unstructured) as usize;
    let window_b = any_u32(&mut unstructured) as usize;
    let bar_paddr = any_u32(&mut unstructured) as usize;
    let page_bytes = unstructured.take_rest();

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
        return;
    };
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

    let Ok(identified) = identify(&config) else {
        return;
    };
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
        return;
    };

    let window = ZeroedRegion::<BarWindow>::new();
    let window_base = window.as_ptr().cast::<u8>();
    // SAFETY: `window` is a live, zeroed, page-aligned `BarWindow` of exactly
    // `BAR_WINDOW_SIZE` bytes with no outstanding reference into it.
    unsafe { overwrite(window_base, BAR_WINDOW_SIZE, page_bytes) };

    // SAFETY: `window_base` names a live, page-aligned mapping of exactly
    // `BAR_WINDOW_SIZE` bytes that outlives every value derived from it here —
    // `map`'s contract verbatim. `map` requires nothing of the caller about the
    // device's own offsets: `identify` bounded them, which was asserted above.
    let offered = unsafe { placed.map(window_base) };

    let Ok(acknowledged) = offered.acknowledge() else {
        return;
    };
    let Ok(negotiated) = acknowledged.negotiate_features() else {
        return;
    };
    assert_eq!(
        negotiated.features() & !ACCEPTED_FEATURES,
        0,
        "the driver accepted a feature bit it does not implement"
    );
    // The virtqueue region address is build data in production; here it is
    // simply a plausible page-aligned value, because what is under test is the
    // device's answers to `setup_queue`, not this number.
    let Ok(configured) = negotiated.configure_queues(0x3100_0000) else {
        return;
    };
    // Both doorbells were placed inside the mapped window or `configure_queues`
    // would have refused; ringing them writes only within it.
    let live = configured.go_live();
    live.ring_receive();
    live.ring_transmit();
}
