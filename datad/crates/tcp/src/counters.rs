//! What a stack has seen, one field per distinct cause.
//!
//! # Why one field per cause and not one total
//!
//! Attribution is binding and it is the reason this
//! module is as long as it is: three classes must never merge — what a **peer
//! sent** that a layer refused, what a **device** got wrong about its own
//! protocol, and what **we** got wrong. A single `dropped` would collapse a port
//! scan, a corrupted link and a bug in this crate into one number an operator
//! cannot act on.
//!
//! The middle class is empty here and that is worth stating rather than leaving
//! to be inferred: no device register is read in this crate, so nothing in it can
//! observe a device misbehaving. A corrupted segment reaches
//! [`TcpCounters::refused_bad_checksum`] as something *the peer sent*, because
//! from here a bit flipped by a NIC and a bit flipped by an attacker are the same
//! observation — the driver's own counters are where a device's protocol faults
//! are attributed.
//!
//! The third class is [`TcpCounters::write_refused`], which is expected to read
//! zero forever: it counts a segment this stack decided to send and could not fit
//! in the storage its caller offered. That is an alert rather than a traffic
//! statistic.
//!
//! # Saturating, never reset
//!
//! `pipeline::DropCounters`' terms, and for its reason: a consumer differences
//! successive readings, so a reset would forge a negative rate and a wrap would
//! turn a sustained flood back into a small number — which is exactly the signal
//! a counter of attacker-driven events exists to carry.

/// Every outcome one stack has produced.
///
/// Public fields rather than accessors: this is a value a metrics endpoint reads
/// out whole, and thirty accessors returning one `u64` each would carry no
/// information the field name does not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpCounters {
    /// Segments handed to the stack, whatever became of them. What a caller
    /// compares against the segments it took off its pipeline.
    pub segments_received: u64,
    /// Segments the stack composed, whatever they carried.
    pub segments_sent: u64,
    /// Connections that reached `SYN_RECEIVED` — a handshake begun by a peer.
    pub connections_accepted: u64,
    /// Connections that reached `SYN_SENT` — a handshake begun by this end. Its
    /// own field rather than part of `connections_accepted`, because the two
    /// accuse nothing alike: one is traffic arriving and the other is this node
    /// deciding to reach out, and a rising count of dials beside a flat
    /// `connections_established` is a node that cannot reach where it is trying
    /// to go.
    pub connections_dialled: u64,
    /// Connections that reached `ESTABLISHED` — a handshake completed. The gap
    /// between this and the count above is the half-open population, which is
    /// what a `SYN` flood produces.
    pub connections_established: u64,
    /// Connections that reached `CLOSED` through the state machine, however they
    /// got there.
    pub connections_closed: u64,
    /// Connections destroyed to make room for a new one, oldest reapable first.
    pub connections_evicted: u64,
    /// Connections destroyed because a timer expired: `TIME_WAIT` elapsed, or a
    /// connection sat idle past its limit.
    pub connections_reaped: u64,
    /// Connections abandoned because the retransmission limit was reached. A
    /// `RST` is sent where the peer might still be listening.
    pub connections_abandoned: u64,

    /// Payload bytes delivered in order to the caller.
    pub bytes_received: u64,
    /// Payload bytes handed to the stack to send.
    pub bytes_sent: u64,
    /// Payload bytes re-sent because a timeout expired. Counted apart from
    /// `bytes_sent`, which is what makes a lossy path visible as a ratio.
    pub bytes_retransmitted: u64,
    /// Segments re-sent, data and control alike.
    pub retransmits: u64,

    /// Segments that are not a TCP segment: a header shorter than one, a data
    /// offset naming more header than there is, a malformed option.
    pub refused_malformed: u64,
    /// Segments whose pseudo-header checksum did not verify. Its own field
    /// rather than part of `refused_malformed`, because the two accuse different
    /// things: a bad checksum is a corrupted or forged segment, and a bad data
    /// offset is a sender that cannot compose one.
    pub refused_bad_checksum: u64,
    /// Segments outside the receive window, answered with an acknowledgement per
    /// RFC 793 p.69 unless they carried `RST`.
    pub refused_out_of_window: u64,
    /// `SYN`s refused because the table was full and nothing in it was reapable.
    pub refused_table_full: u64,
    /// Segments for a port this stack does not listen on.
    pub refused_not_listening: u64,
    /// Segments for a 4-tuple with no connection, which are answered with a
    /// `RST` unless they carried one.
    pub refused_no_connection: u64,
    /// Acknowledgements of something never sent, which RFC 793 answers with a
    /// `RST` from `SYN_RECEIVED` and with an acknowledgement once synchronized.
    pub refused_unacceptable_ack: u64,
    /// Segments carrying no `ACK` at all on a connection past its handshake,
    /// which RFC 793 p.72 drops without answering. Its own field because it
    /// accuses something different from a *wrong* acknowledgement: a peer that
    /// is not running TCP, or a probe.
    pub refused_no_acknowledgement: u64,
    /// Segments reaching a dial that carried neither `SYN` nor `RST`, which
    /// RFC 793 p.68 drops without answering. Its own field because a connection
    /// this end has only dialled has no window for a segment to be outside of:
    /// the refusal is that the segment says nothing about the handshake being
    /// waited for.
    pub refused_not_a_handshake: u64,
    /// In-window payload that was not the next byte expected. This stack holds
    /// no reassembly queue (see the crate header), so it is dropped and
    /// re-requested by the acknowledgement that follows.
    pub refused_out_of_order: u64,
    /// Segments carrying `URG`. The urgent pointer is ignored and the data
    /// delivered in band; the count is what makes that visible rather than
    /// silent.
    pub urgent_ignored: u64,

    /// Segments challenged rather than acted on: RFC 5961's answer to a blind
    /// in-window `RST` (section 3.2) or a `SYN` on a synchronized connection
    /// (section 4). It counts the *decision* to challenge; whether the
    /// acknowledgement left is the per-second budget's answer, and what that
    /// withheld is `challenges_suppressed`.
    pub challenge_acks: u64,
    /// Unsolicited replies withheld by RFC 5961 section 7's per-second budget,
    /// whichever kind: a challenge acknowledgement — including the ones RFC 793
    /// owes an out-of-window segment or an unacceptable acknowledgement — or the
    /// reset a segment naming no connection would have drawn. A number that moves
    /// at all is a peer provoking replies faster than any exchange needs to.
    pub challenges_suppressed: u64,
    /// `RST`s accepted, each of which destroyed a connection.
    pub resets_received: u64,
    /// `RST`s sent, for any of the reasons RFC 793 section 3.4 lists.
    pub resets_sent: u64,

    /// Segments this stack decided to send and could not: the caller's storage
    /// was too small. **Our** fault, not the peer's, and expected to read zero
    /// forever.
    pub write_refused: u64,
}

impl TcpCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            segments_received: 0,
            segments_sent: 0,
            connections_accepted: 0,
            connections_dialled: 0,
            connections_established: 0,
            connections_closed: 0,
            connections_evicted: 0,
            connections_reaped: 0,
            connections_abandoned: 0,
            bytes_received: 0,
            bytes_sent: 0,
            bytes_retransmitted: 0,
            retransmits: 0,
            refused_malformed: 0,
            refused_bad_checksum: 0,
            refused_out_of_window: 0,
            refused_table_full: 0,
            refused_not_listening: 0,
            refused_no_connection: 0,
            refused_unacceptable_ack: 0,
            refused_no_acknowledgement: 0,
            refused_not_a_handshake: 0,
            refused_out_of_order: 0,
            urgent_ignored: 0,
            challenge_acks: 0,
            challenges_suppressed: 0,
            resets_received: 0,
            resets_sent: 0,
            write_refused: 0,
        }
    }

    /// Every segment refused before it could affect a connection, which is what
    /// a reading compares against `segments_received` to see how much of a port's
    /// traffic is being turned away.
    #[must_use]
    pub const fn refused_total(&self) -> u64 {
        self.refused_malformed
            .saturating_add(self.refused_bad_checksum)
            .saturating_add(self.refused_out_of_window)
            .saturating_add(self.refused_table_full)
            .saturating_add(self.refused_not_listening)
            .saturating_add(self.refused_no_connection)
            .saturating_add(self.refused_unacceptable_ack)
            .saturating_add(self.refused_no_acknowledgement)
            .saturating_add(self.refused_not_a_handshake)
            .saturating_add(self.refused_out_of_order)
    }

    /// Bump one count, saturating. A method rather than `+= 1` at forty call
    /// sites, so the saturation is stated once.
    pub(crate) fn bump(count: &mut u64) {
        *count = count.saturating_add(1);
    }

    /// Add to one total, saturating.
    pub(crate) fn add(total: &mut u64, amount: u64) {
        *total = total.saturating_add(amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_set_is_zero_everywhere_and_matches_the_derived_default() {
        let counters = TcpCounters::new();
        assert_eq!(counters, TcpCounters::default());
        assert_eq!(counters.refused_total(), 0);
    }

    /// The refusal total spans every refusal field and nothing else: a field
    /// added without being folded in would silently leave a class of turned-away
    /// traffic out of the number an operator reads.
    #[test]
    fn the_refusal_total_spans_every_refusal_field() {
        let mut counters = TcpCounters::new();
        counters.refused_malformed = 1;
        counters.refused_bad_checksum = 2;
        counters.refused_out_of_window = 4;
        counters.refused_table_full = 8;
        counters.refused_not_listening = 16;
        counters.refused_no_connection = 32;
        counters.refused_unacceptable_ack = 64;
        counters.refused_out_of_order = 128;
        counters.refused_no_acknowledgement = 256;
        counters.refused_not_a_handshake = 512;
        assert_eq!(counters.refused_total(), 1023);
        // A count that is not a refusal stays out of it.
        counters.segments_received = 1_000;
        counters.write_refused = 1_000;
        counters.connections_dialled = 1_000;
        assert_eq!(counters.refused_total(), 1023);
    }

    #[test]
    fn every_count_saturates_rather_than_wrapping() {
        let mut count = u64::MAX;
        TcpCounters::bump(&mut count);
        assert_eq!(count, u64::MAX);
        TcpCounters::add(&mut count, 12);
        assert_eq!(count, u64::MAX);

        let mut counters = TcpCounters::new();
        counters.refused_malformed = u64::MAX;
        counters.refused_bad_checksum = u64::MAX;
        assert_eq!(counters.refused_total(), u64::MAX);
    }

    #[test]
    fn adding_moves_a_total_by_the_amount() {
        let mut total = 7;
        TcpCounters::add(&mut total, 5);
        assert_eq!(total, 12);
    }
}
