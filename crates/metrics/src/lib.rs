//! The appliance's metric surface: the shared-memory counter shards protection
//! domains publish into, the catalogue that says what every slot means, and the
//! Prometheus exposition renderer that turns a set of shards into the bytes
//! `GET /metrics` answers with.
//!
//! # Adversary
//!
//! The **byzantine neighbour protection domain**, and through the
//! endpoint that serves the rendered bytes, its **management-plane attacker**.
//! Every word this crate reads out of a shard was stored by another domain, so
//! nothing here judges a value: a counter is a `u64` and every bit pattern of
//! one is a number an operator may read. What the adversary must not be able to
//! do is make the *renderer* misbehave, so [`Snapshot::render`] is total over
//! arbitrary values and arbitrary output lengths, allocates nothing, and refuses
//! rather than truncating.
//!
//! # Why the region layout lives here and not in `wire`
//!
//! `wire` owns the region ABIs whose layout cannot be expressed in terms of the
//! crate that reads them. A stats shard is the opposite case: its bytes are a
//! flat array of `u64`, and everything that makes it *mean* anything — which
//! slot is which series, under which name and labels — is the catalogue below.
//! Splitting the array from the catalogue would put the two halves of one ABI in
//! two crates and reintroduce exactly the drift a fixed layout exists to
//! prevent, so both are here and one table ([`ShardSpec::series`]) is what the
//! writer indexes and the reader renders.
//!
//! # One writer, no lock, and no seqlock either
//!
//! Each shard is written by exactly one protection domain and read by the
//! management domain alone, so an increment is a relaxed load, an add and a
//! relaxed store — plain `mov`/`add`/`mov` with no `lock` prefix — and on x86_64
//! an aligned 64-bit access cannot tear.
//!
//! [`ClockCalibration`](wire::ClockCalibration) needs a seqlock and this does
//! not, which is worth stating because the two regions sit beside each other: a
//! calibration's three words are meaningful only *together*, and a counter has
//! no such partner. A scrape is never atomic against a running system in any
//! case, and Prometheus differences successive samples rather than reading a
//! consistent cut, so one word of sequencing would buy nothing and would put a
//! retry loop on the path of a management request.
//!
//! # The hot path pays for none of it
//!
//! A domain accumulates in the in-memory counters it already keeps and calls
//! [`StatsShard::publish`] **once per drain**, not once per frame — so the whole
//! surface costs one bounded run of relaxed stores per batch of up to
//! `DRAIN_LIMIT` descriptors: no measurable dataplane cost.
//!
//! # Nothing is summed here
//!
//! Every series carries the `domain` label of the protection domain that
//! produced it and no total is computed anywhere in the node. A summed total is
//! corrupted by a domain restart — one shard resets, the sum goes backwards, and
//! a scraper forges an enormous rate — whereas a labelled series resets alone,
//! which Prometheus handles by design.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod catalog;
mod interfaces;
mod render;
mod sample;

use core::sync::atomic::{AtomicU64, Ordering};

use wire::MAPPING_ALIGN;

pub use catalog::{
    ALL_METRICS, FORWARDER_SHARD, INTERFACE_INFO, Kind, Label, MANAGEMENT_SHARD, Metric,
    SHARD_COUNT, SHARDS, Series, ShardSpec, metric,
};
pub use interfaces::{
    InterfaceInfo, InterfaceInventory, InventoryFull, MANAGEMENT_PORT_DOMAIN, MAX_INTERFACE_SERIES,
    PORT_DOMAINS, Role, port_domain,
};
pub use render::{MAX_EXPOSITION_LEN, RenderError, Snapshot};
pub use sample::{
    CLOCK_SLOTS, CONFIG_SLOTS, CONSOLE_SLOTS, ClockSample, ConfigSample, ConsoleSample,
    DRIVER_SLOTS, DriverSample, EndpointSample, FORWARDER_SLOTS, ForwarderSample, HTTP_STATUSES,
    HttpSample, LogSample, MANAGEMENT_SLOTS, ManagementSample, PIPELINES, PipelineSample,
    PoolSample, RECORDER_SLOTS, ROUTE_DROP_REASONS, ROUTE_STAGE_DROP_REASONS, RecorderSample,
    SINKS, SinkSample, TapSample, TcpSample, UartSample,
};

/// Slots left free above the largest domain's table, so a new counter is a table
/// entry rather than a region resize — which would be a capability change. Two
/// cache lines: room for a subsystem's counters, and the shard still one page.
const STATS_HEADROOM: usize = 16;

/// Counter slots one shard carries.
///
/// Derived rather than chosen: the largest table — the management endpoint's,
/// whose transport alone keeps twenty-seven — plus [`STATS_HEADROOM`], rounded to
/// a whole cache line so no shard's last slot shares one with what follows it.
/// The assertions in [`sample`] hold every other table to the management
/// endpoint's, so one that outgrew it is a build error and not a dropped counter.
pub const STATS_SLOTS: usize = (sample::MANAGEMENT_SLOTS + STATS_HEADROOM).next_multiple_of(8);

/// One protection domain's counters, as the shared region lays them out.
///
/// Every field is private and the only ways in are [`publish`](Self::publish)
/// and [`sample`](Self::sample), so "one writer, relaxed, whole slots" is a
/// property of the type rather than a convention its two domains are asked to
/// keep.
///
/// `align(64)` is a cache line: two domains' counters sharing one would put the
/// coherence traffic sharding exists to avoid back on the dataplane's hot path.
/// Each shard is its own region and so its own page in practice, and the
/// alignment is what says that is required rather than incidental.
#[repr(C, align(64))]
pub struct StatsShard {
    slots: [AtomicU64; STATS_SLOTS],
}

impl StatsShard {
    /// A zeroed shard, which is what the kernel hands a domain that maps one:
    /// every counter at zero is the state a domain that has done nothing is in.
    ///
    /// A function rather than a `const` for
    /// [`ClockCalibration::zero`](wire::ClockCalibration::zero)'s reason: a
    /// `const` holding an atomic is copied at every mention.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            slots: [const { AtomicU64::new(0) }; STATS_SLOTS],
        }
    }

    /// Write one domain's whole counter set, slot for slot.
    ///
    /// `Relaxed`, and that is the whole ordering: there is one writer, each slot
    /// is meaningful alone, and no reader draws a conclusion from two slots
    /// having moved together. A `values` longer than the shard is truncated at
    /// the shard rather than refused — the assertions in [`sample`] make that
    /// unreachable from first-party code, and a bound that cannot be violated is
    /// better spent on the array than on an error nobody can produce.
    pub fn publish(&self, values: &[u64]) {
        for (slot, value) in self.slots.iter().zip(values) {
            slot.store(*value, Ordering::Relaxed);
        }
    }

    /// Read every slot. Whatever the writer has stored, with no attempt to catch
    /// a consistent cut across slots; see the crate header on why there is
    /// nothing to catch.
    #[must_use]
    pub fn sample(&self) -> [u64; STATS_SLOTS] {
        let mut values = [0u64; STATS_SLOTS];
        for (value, slot) in values.iter_mut().zip(&self.slots) {
            *value = slot.load(Ordering::Relaxed);
        }
        values
    }
}

/// Bytes the system description reserves for one shard's region, derived rather
/// than chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const STATS_REGION_SIZE: usize = size_of::<StatsShard>().next_multiple_of(MAPPING_ALIGN);

// The layout two protection domains agree on, fixed at build time. One
// maps this region read-write and the other read-only, and neither can see the
// other's view of it, so a width change or a stray field must be a compile error
// here rather than a reader attributing one domain's counter to another series.
const _: () = {
    assert!(size_of::<StatsShard>() == STATS_SLOTS * 8);
    assert!(size_of::<StatsShard>() == 768);
    assert!(align_of::<StatsShard>() == 64);
    // Every slot naturally aligned, which is what makes each store and load a
    // single access rather than two a reader could tear across.
    assert!(size_of::<StatsShard>().is_multiple_of(align_of::<u64>()));
    // A whole number of cache lines, so no shard's last slot shares a line with
    // anything that follows it in a region.
    assert!(size_of::<StatsShard>().is_multiple_of(64));

    assert!(STATS_REGION_SIZE >= size_of::<StatsShard>());
    assert!(STATS_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
    assert!(STATS_REGION_SIZE == 0x1000);
};

#[cfg(test)]
mod tests;
