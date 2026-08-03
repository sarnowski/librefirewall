//! What a table has seen, one field per distinct cause.
//!
//! # Why one field per cause and not one total
//!
//! Attribution is what makes a number actionable, and three classes must never
//! merge: what a **peer sent** that the tracker refused, what a **device** got
//! wrong about its own protocol, and what **we** got wrong. A single `dropped`
//! would collapse a port scan, a corrupted link and a defect in this crate into
//! one number an operator cannot act on.
//!
//! The middle class is empty here, and that is worth stating rather than leaving
//! to be inferred: no device register is read in this crate, so nothing in it can
//! observe a device misbehaving. A corrupted segment arrives as something *the
//! peer sent* — from here a bit flipped by a NIC and a bit flipped by an attacker
//! are the same observation, and the driver's own counters are where a device's
//! protocol faults are attributed.
//!
//! The third class is one field, [`FlowCounters::internal_slot_desync`], which is
//! expected to read zero forever: it counts the table finding no slot to allocate
//! while holding slots it believes are vacant. That is an alert about this crate,
//! not a traffic statistic — and it is a count rather than an assertion because
//! the path it sits on is reached by a peer's traffic.
//!
//! # Saturating, never reset
//!
//! A scrape differences successive samples, so a reset would forge a negative rate
//! and a wrap would turn a sustained flood back into a small number — which is
//! exactly the signal a counter of attacker-driven events exists to carry.

use crate::{Classification, RefusalKind};

/// Every outcome one table has produced.
///
/// Public fields rather than accessors: this is a value a metrics endpoint reads
/// out whole, and thirty accessors returning one `u64` each would carry no
/// information the field name does not. `#[repr(C)]` because it sits inside the
/// table, which is placed in a shared memory region with a declared layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowCounters {
    /// Packets offered to the table, whatever became of them. What a caller
    /// compares against the packets its pipeline classified.
    pub packets_seen: u64,
    /// Packets that opened a flow.
    pub flows_created: u64,
    /// Packets that advanced a flow the table already held.
    pub packets_established: u64,
    /// ICMP errors related to a flow they quoted.
    pub packets_related: u64,

    /// Flows whose slot was taken back because their state's timeout elapsed.
    pub flows_expired: u64,
    /// Flows destroyed to make room for a new one. Never an assured flow; see
    /// [`crate::FlowState::is_assured`].
    pub flows_evicted: u64,
    /// Flows that reached `Closed` or `TimeWait` through the state machine —
    /// closed by their own endpoints rather than by this table.
    pub flows_closed: u64,
    /// Flows given back because whatever asked for the classification then
    /// refused the packet that opened them. On a default-deny appliance this
    /// tracks refused connection attempts, so a number climbing beside
    /// `flows_created` is a policy turning traffic away rather than a fault.
    pub flows_withdrawn: u64,
    /// Flows taken back because the caller re-decided on them and no longer admits
    /// them. Its own field because it accuses the opposite of `flows_withdrawn`: a
    /// withdrawal is a connection attempt turned away as it arrived, and this is a
    /// conversation a policy *had* admitted and has stopped admitting.
    pub flows_revoked: u64,

    /// Packets of a protocol this tracker holds no state for.
    pub refused_unsupported_protocol: u64,
    /// Non-initial fragments, which carry no transport header to key a flow by.
    pub refused_fragment: u64,
    /// Datagrams too short for the transport header they claim, or claiming a
    /// header longer than they carry.
    pub refused_malformed: u64,
    /// TCP segments whose flag combination no exchange produces: a `SYN` with a
    /// `FIN`, a `RST` with either, a `FIN` with no `ACK`, or none of the four.
    pub refused_invalid_flags: u64,
    /// TCP segments for a five-tuple with no flow that were not a `SYN`. The
    /// count of attempts to walk around default-deny by starting mid-stream.
    pub refused_mid_stream: u64,
    /// Packets a flow's own state does not admit, `SYN`s on a synchronized flow
    /// among them.
    pub refused_invalid_state: u64,
    /// Segments outside the window the peer authorised. One field for all four
    /// edges; which edge refused it is in the typed refusal the caller gets.
    pub refused_out_of_window: u64,
    /// ICMP echo replies, and errors, naming a flow the table does not hold.
    pub refused_no_flow: u64,
    /// ICMP errors whose quoted datagram did not corroborate its own claim. A
    /// number that moves is somebody probing the `Related` classification.
    pub refused_quoted_invalid: u64,
    /// ICMP messages of a type this tracker neither tracks nor relates.
    pub refused_unsupported_icmp: u64,
    /// New flows refused because every slot the eviction scan reached held a flow
    /// that may not be evicted. This is the fail-closed answer to a flood, and a
    /// number that moves means legitimate new connections are being turned away.
    pub refused_table_full: u64,
    /// New flows refused because every bucket within the probe bound was taken.
    /// Its own field because it accuses something different from a full table: a
    /// run of keys that hashed together rather than a table with no room.
    pub refused_bucket_full: u64,

    /// Probes that matched a bucket's tag and then not the flow's tuple. Not a
    /// refusal — the probe simply continued — and exposed because the ratio
    /// against `packets_seen` is what says whether the tag is doing its job.
    pub probe_tag_collisions: u64,

    /// The table found no slot while believing it held vacant ones. **Ours**, not
    /// the peer's, and expected to read zero forever.
    pub internal_slot_desync: u64,
}

impl FlowCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packets_seen: 0,
            flows_created: 0,
            packets_established: 0,
            packets_related: 0,
            flows_expired: 0,
            flows_evicted: 0,
            flows_closed: 0,
            flows_withdrawn: 0,
            flows_revoked: 0,
            refused_unsupported_protocol: 0,
            refused_fragment: 0,
            refused_malformed: 0,
            refused_invalid_flags: 0,
            refused_mid_stream: 0,
            refused_invalid_state: 0,
            refused_out_of_window: 0,
            refused_no_flow: 0,
            refused_quoted_invalid: 0,
            refused_unsupported_icmp: 0,
            refused_table_full: 0,
            refused_bucket_full: 0,
            probe_tag_collisions: 0,
            internal_slot_desync: 0,
        }
    }

    /// Every packet turned away, which is what a scrape compares against
    /// `packets_seen` to see how much of a link's traffic the tracker refuses.
    #[must_use]
    pub const fn refused_total(&self) -> u64 {
        self.refused_unsupported_protocol
            .saturating_add(self.refused_fragment)
            .saturating_add(self.refused_malformed)
            .saturating_add(self.refused_invalid_flags)
            .saturating_add(self.refused_mid_stream)
            .saturating_add(self.refused_invalid_state)
            .saturating_add(self.refused_out_of_window)
            .saturating_add(self.refused_no_flow)
            .saturating_add(self.refused_quoted_invalid)
            .saturating_add(self.refused_unsupported_icmp)
            .saturating_add(self.refused_table_full)
            .saturating_add(self.refused_bucket_full)
    }

    /// Every packet the table classified rather than refused.
    #[must_use]
    pub const fn classified_total(&self) -> u64 {
        self.flows_created
            .saturating_add(self.packets_established)
            .saturating_add(self.packets_related)
    }

    /// What one classification has accounted for.
    ///
    /// The one place a [`Classification`] and a field of this struct are
    /// related, so a metric enumerating the vocabulary reads the same numbers
    /// [`crate::FlowTable::classify`] wrote rather than a second table of them.
    /// `New` reads `flows_created`, because a flow is created by exactly the
    /// packet that opens it — one counter, not two.
    #[must_use]
    pub const fn classified(&self, classification: Classification) -> u64 {
        match classification {
            Classification::New => self.flows_created,
            Classification::Established => self.packets_established,
            Classification::Related => self.packets_related,
        }
    }

    /// What one refusal kind has turned away.
    ///
    /// The one place a [`RefusalKind`] and a field of this struct are related,
    /// so a metric enumerating the vocabulary reads the same numbers
    /// [`crate::FlowTable::classify`] wrote rather than a second table of them.
    #[must_use]
    pub const fn refused(&self, kind: RefusalKind) -> u64 {
        match kind {
            RefusalKind::UnsupportedProtocol => self.refused_unsupported_protocol,
            RefusalKind::Fragment => self.refused_fragment,
            RefusalKind::Malformed => self.refused_malformed,
            RefusalKind::InvalidFlags => self.refused_invalid_flags,
            RefusalKind::MidStream => self.refused_mid_stream,
            RefusalKind::InvalidState => self.refused_invalid_state,
            RefusalKind::OutOfWindow => self.refused_out_of_window,
            RefusalKind::NoSuchFlow => self.refused_no_flow,
            RefusalKind::QuotedInvalid => self.refused_quoted_invalid,
            RefusalKind::UnsupportedIcmp => self.refused_unsupported_icmp,
            RefusalKind::TableFull => self.refused_table_full,
            RefusalKind::BucketFull => self.refused_bucket_full,
        }
    }

    /// Bump one count, saturating. A method rather than `+= 1` at forty call
    /// sites, so the saturation is stated once.
    pub(crate) fn bump(count: &mut u64) {
        *count = count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests;
