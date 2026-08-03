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
//! The conversion from `pipeline::DropReason` lives here rather than in either
//! endpoint: `wire` is the crate every region's layout is expressed in and may
//! not depend on `pipeline`, and `pipeline` reaches a verdict without knowing
//! it is recorded. This crate is where both are visible.

use lfw_flow::{Classification, FlowState};
use pipeline::{DropReason, FlowObservation, FlowTransition, Inspection, Verdict};
use wire::{
    TapAnnotation, TapClassification, TapConsume, TapDecision, TapDirection, TapDropReason,
    TapEvent, TapFlow, TapFlowState, TapOutcome, TapRecords, TapRule, TapWriteError, TapWriter,
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
        DropReason::FlowUnsupportedProtocol => TapDropReason::FlowUnsupportedProtocol,
        DropReason::FlowFragment => TapDropReason::FlowFragment,
        DropReason::FlowMalformed => TapDropReason::FlowMalformed,
        DropReason::FlowInvalidFlags => TapDropReason::FlowInvalidFlags,
        DropReason::FlowMidStream => TapDropReason::FlowMidStream,
        DropReason::FlowInvalidState => TapDropReason::FlowInvalidState,
        DropReason::FlowOutOfWindow => TapDropReason::FlowOutOfWindow,
        DropReason::FlowNoSuchFlow => TapDropReason::FlowNoSuchFlow,
        DropReason::FlowQuotedInvalid => TapDropReason::FlowQuotedInvalid,
        DropReason::FlowUnsupportedIcmp => TapDropReason::FlowUnsupportedIcmp,
        DropReason::FlowTableFull => TapDropReason::FlowTableFull,
        DropReason::FlowBucketFull => TapDropReason::FlowBucketFull,
        DropReason::PolicyDenied => TapDropReason::PolicyDenied,
        DropReason::NoPolicyMatch => TapDropReason::NoPolicyMatch,
    }
}

/// One classification as the tap ABI encodes it, exhaustive on
/// [`tap_drop_reason`]'s terms.
#[must_use]
pub const fn tap_classification(classification: Classification) -> TapClassification {
    match classification {
        Classification::New => TapClassification::New,
        Classification::Established => TapClassification::Established,
        Classification::Related => TapClassification::Related,
    }
}

/// One flow state as the tap ABI encodes it, or `None` for the vacant slot the
/// ABI deliberately has no encoding for — a classification is never reached
/// against one, so the absence is a state no observation carries rather than one
/// this conversion loses.
#[must_use]
pub const fn tap_flow_state(state: FlowState) -> Option<TapFlowState> {
    match state {
        FlowState::Vacant => None,
        FlowState::SynSent => Some(TapFlowState::SynSent),
        FlowState::SynReceived => Some(TapFlowState::SynReceived),
        FlowState::Established => Some(TapFlowState::Established),
        FlowState::FinWait => Some(TapFlowState::FinWait),
        FlowState::CloseWait => Some(TapFlowState::CloseWait),
        FlowState::Closing => Some(TapFlowState::Closing),
        FlowState::TimeWait => Some(TapFlowState::TimeWait),
        FlowState::Closed => Some(TapFlowState::Closed),
        FlowState::UdpUnreplied => Some(TapFlowState::UdpUnreplied),
        FlowState::UdpAssured => Some(TapFlowState::UdpAssured),
        FlowState::IcmpUnreplied => Some(TapFlowState::IcmpUnreplied),
        FlowState::IcmpReplied => Some(TapFlowState::IcmpReplied),
    }
}

/// One flow observation as the tap ABI carries it, or `None` where the state has
/// no encoding.
#[must_use]
pub const fn tap_flow(observation: FlowObservation) -> Option<TapFlow> {
    match tap_flow_state(observation.state) {
        Some(state) => Some(TapFlow {
            slot: observation.id.slot(),
            generation: observation.id.generation(),
            classification: tap_classification(observation.classification),
            state,
        }),
        None => None,
    }
}

/// Everything the tap records about one evaluation, composed out of the verdict
/// and the facts the chain attached to the [`Inspection`].
///
/// This is where the two vocabularies meet, which is why it is here rather than
/// in either endpoint: `wire` may not depend on `pipeline`, and `pipeline`
/// reaches a verdict without knowing it is recorded.
///
/// The event is derived from the *facts* and never from the drop reason, and the
/// difference matters: an admission or routing refusal and a tracker refusal both
/// leave no flow, and only [`Inspection::refusal`] says the tracker was reached
/// and answered. Deriving it from the reason instead would put a fact about which
/// stage refused into the operator-facing vocabulary, which is flat on purpose.
#[must_use]
pub fn tap_decision(
    inspection: &Inspection<'_>,
    verdict: Verdict,
    direction: TapDirection,
    generation: u32,
) -> TapDecision {
    let flow = inspection.flow();
    let rule = inspection.matched().and_then(TapRule::new);
    let event = match (verdict, flow.map(|flow| flow.transition)) {
        // A conversation was admitted, and the rule that admitted it is the one
        // the filter matched — the filter's only accepting outcome.
        (Verdict::Forward { .. }, Some(FlowTransition::Opened)) => Some(TapEvent::FlowOpened),
        (Verdict::Forward { .. }, Some(FlowTransition::Advanced)) => {
            match flow.map(|flow| flow.state) {
                Some(FlowState::TimeWait | FlowState::Closed) => Some(TapEvent::FlowClosed),
                _ => Some(TapEvent::FlowAdvanced),
            }
        }
        // Traffic on a conversation already accounted for: no transition, so
        // nothing the connection history is about.
        (Verdict::Forward { .. }, Some(FlowTransition::Held) | None) => None,
        // The tracker refused it, so it never reached the filter and the drop
        // reason is the refusal.
        (Verdict::Drop(_), _) if inspection.refusal().is_some() => Some(TapEvent::FlowRefused),
        // Every frame the filter sees has just opened a flow, so a drop with one
        // attached is the filter's — with a rule where one matched, and the
        // default deny where none did. The flow it opened has been withdrawn by
        // the half of the tracker behind the filter.
        (Verdict::Drop(_), Some(FlowTransition::Opened)) => Some(match rule {
            Some(_) => TapEvent::PolicyDenied,
            None => TapEvent::PolicyNoMatch,
        }),
        // Admission or routing refused it in front of the tracker: no
        // conversation was involved and no policy was consulted.
        (Verdict::Drop(_), _) => None,
    };
    TapDecision {
        outcome: tap_outcome(verdict),
        direction,
        generation,
        flow: flow.and_then(tap_flow),
        // Only the two filter decisions may carry one, which is what the ring
        // refuses an annotation for — so a rule reaching a record it does not
        // belong on would be a record the recorder never writes rather than one
        // it writes wrongly.
        rule: event.filter(|event| event.names_a_rule()).and(rule),
        event,
    }
}

/// The verdict as the tap ABI encodes it.
#[must_use]
pub const fn tap_outcome(verdict: Verdict) -> TapOutcome {
    match verdict {
        Verdict::Forward { .. } => TapOutcome::Forwarded,
        Verdict::Drop(reason) => TapOutcome::Dropped(tap_drop_reason(reason)),
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
            decision,
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
        let annotation = TapAnnotation::new(packet_id, timestamp, interface_id, decision);
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
/// A struct rather than four arguments because two of them are integers and an
/// argument order slipped between them would put one port's traffic under
/// another's interface, in an artifact meant to be evidence.
pub struct Observation<'frame> {
    /// The raw timestamp-counter reading. The recorder converts it, holding the
    /// calibration; converting here would put the read of another domain's
    /// region on the path of every frame.
    pub timestamp: u64,
    /// The interface the observation belongs to, which is the ingress port.
    pub interface_id: u8,
    /// What the appliance concluded, composed by [`tap_decision`].
    pub decision: TapDecision,
    /// The frame as the stage snapshotted it, before any rewrite.
    pub frame: &'frame [u8],
}

#[cfg(test)]
mod tests;
