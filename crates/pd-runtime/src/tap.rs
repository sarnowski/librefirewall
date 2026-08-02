//! The dataplane's end of the recording tap: what the forwarder has to say
//! about a frame it decided on, published to the recorder.
//!
//! # Adversary
//!
//! A **byzantine neighbour protection domain**, on the far side of
//! the ring, and **untrusted network traffic** in the payload this side copies
//! in. Neither can reach anything here: the ring refuses rather than waits, the
//! payload is bytes and never a value that steers an access, and the recorder's
//! published cursor decides only whether a record is offered or counted as
//! lost.
//!
//! # Constraints
//!
//! **A tap may never backpressure forwarding.** A traffic generator that could
//! stall the dataplane by outrunning the recorder's medium would turn an
//! observability feature into a remote outage, so a full ring costs the newest
//! observation and the forwarder treats that as ordinary operation rather than
//! as an error (`wire::tap`).
//!
//! The conversion from `routing::DropReason` lives here rather than in either
//! endpoint: `wire` is the crate every region's layout is expressed in and may
//! not depend on `routing`, and `routing` describes a decision without knowing
//! it is recorded. This crate is where both are visible.

use routing::DropReason;
use wire::{
    TapAnnotation, TapConsume, TapDirection, TapDropReason, TapOutcome, TapRecords, TapWriteError,
    TapWriter,
};

/// One drop reason as the tap ABI encodes it.
///
/// Total, and exhaustive over `DropReason` so a reason added upstream fails the
/// build here rather than being silently recorded as another one. The two enums
/// are declared in the same order, which `wire::tap` states and
/// [`tests::every_drop_reason_maps_to_its_own_tap_reason`] holds them to.
#[must_use]
pub const fn tap_drop_reason(reason: DropReason) -> TapDropReason {
    match reason {
        DropReason::UnconfiguredIngressPort => TapDropReason::UnconfiguredIngressPort,
        DropReason::InterfaceDisabled => TapDropReason::InterfaceDisabled,
        DropReason::NotAddressedToUs => TapDropReason::NotAddressedToUs,
        DropReason::VlanTagged => TapDropReason::VlanTagged,
        DropReason::MartianSource => TapDropReason::MartianSource,
        DropReason::UnroutableDestination => TapDropReason::UnroutableDestination,
        DropReason::AddressedToThisRouter => TapDropReason::AddressedToThisRouter,
        DropReason::TtlExpired => TapDropReason::TtlExpired,
        DropReason::NoRoute => TapDropReason::NoRoute,
        DropReason::EgressIsIngress => TapDropReason::EgressIsIngress,
        DropReason::NoNeighbour => TapDropReason::NoNeighbour,
    }
}

/// Saturating, monotone counts for the operator-facing metrics contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TapCounters {
    /// Observations published to the recorder.
    pub observed: u64,
    /// Observations the ring had no slot for. The recorder states this number
    /// in the recording itself as `epb_dropcount`, so a capture says how much
    /// it omitted.
    pub dropped: u64,
    /// Observations the ring refused as inconsistent — more bytes offered than
    /// the frame was said to have carried. A first-party defect rather than a
    /// peer's, and expected to stay zero forever.
    pub refused: u64,
}

/// The forwarder's handle on the tap: the ring, and the packet identity every
/// observation is numbered with.
///
/// The counter is held here rather than per pipeline because it is
/// per-appliance: pcapng's `epb_packetid` relates the ingress and the egress
/// observation of one forwarded frame, so two pipelines numbering
/// independently would make the relation unreadable. One [`Tap`] serves every
/// stage in the domain.
pub struct Tap<'ring> {
    writer: TapWriter<'ring>,
    next_packet_id: u64,
    observed: u64,
    refused: u64,
}

impl<'ring> Tap<'ring> {
    /// Take the producing side of the ring — once per protection domain; a
    /// second handle would restart at slot zero and overwrite what the first
    /// published (`wire::TapRecords::writer`).
    #[must_use]
    pub const fn attach(records: &'ring TapRecords, consume: &'ring TapConsume) -> Self {
        Self {
            writer: records.writer(consume),
            next_packet_id: 0,
            observed: 0,
            refused: 0,
        }
    }

    #[must_use]
    pub fn counters(&self) -> TapCounters {
        TapCounters {
            observed: self.observed,
            dropped: u64::from(self.writer.dropped()),
            refused: self.refused,
        }
    }

    /// Publish one observation, and never fail: a refusal is counted and the
    /// caller carries on. That is the whole of the no-backpressure rule as a
    /// signature — there is no error for a forwarding path to handle,
    /// so none can be handled wrongly.
    pub fn observe(&mut self, observation: Observation<'_>) {
        let Observation {
            timestamp,
            interface_id,
            outcome,
            direction,
            generation,
            frame,
        } = observation;
        // Saturating: a `u64` of packets at the 10 Gbit/s target line rate outlives the
        // appliance by geological margins, and a wrap would make two frames
        // share an identity a reader relates them by.
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.saturating_add(1);
        // Clamped rather than refused: the length is this domain's own
        // snapshot, bounded by `BUFFER_SIZE`, so the clamp is unreachable and
        // is written as a value so no path here can panic.
        let original_len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        let annotation = TapAnnotation::new(
            packet_id,
            timestamp,
            interface_id,
            outcome,
            direction,
            generation,
        );
        match self.writer.write(&annotation, original_len, frame) {
            Ok(_) => self.observed = self.observed.saturating_add(1),
            // Already counted by the writer, and read back through
            // `TapWriter::dropped` rather than tallied twice.
            Err(TapWriteError::Full(_)) => {}
            Err(TapWriteError::FrameExceedsWireLength { .. }) => {
                self.refused = self.refused.saturating_add(1);
            }
        }
    }
}

/// One frame observation, as the stage that made it describes it.
///
/// A struct rather than six arguments because five of the six are integers and
/// an argument order slipped between two of them would put one port's traffic
/// under another's interface, in an artifact meant to be evidence.
pub struct Observation<'frame> {
    /// The raw timestamp-counter reading. The recorder converts it, holding the
    /// calibration; converting here would put the read of another domain's
    /// region on the path of every frame.
    pub timestamp: u64,
    /// The interface the observation belongs to, which is the ingress port.
    pub interface_id: u8,
    pub outcome: TapOutcome,
    pub direction: TapDirection,
    /// The configuration generation the decision was taken under.
    pub generation: u32,
    /// The frame as the stage snapshotted it, before any rewrite.
    pub frame: &'frame [u8],
}

#[cfg(test)]
mod tests;
