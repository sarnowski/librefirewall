//! The management channel's end of the relay: a TLS client out of this
//! appliance, the protocol's framing over it, and the greeting the two ends
//! agree before anything else crosses.
//!
//! # Where this sits, and why it is here rather than beside the network
//!
//! It is the onboarding server's sibling and it runs in the same place for the
//! same reason: **TLS terminates where the keys are**. The domain that owns the
//! management port carries the bytes and reads none of them; this domain holds
//! the device key's delegation, the delivered anchor, the arena the library
//! needs, and now the framing above the record layer. What crosses the relay in
//! either direction is ciphertext.
//!
//! # Adversary
//!
//! A **management-plane attacker up to and including a compromised management
//! server**, and behind the relay a **byzantine neighbour protection domain**.
//! Every byte handed to [`ManagementChannel::advance`] came off the wire and so did the
//! pacing. That the peer is *authenticated* is not a reason to relax anything: a
//! compromised management server holds a valid certificate, and what bounds it
//! is `lfw_tls`'s arena and held-bytes limits under the record layer and
//! `lfw_channel`'s arithmetic above it.
//!
//! Nothing here parses a handshake message, a certificate or a frame field. The
//! record layer is the adopted library's through `lfw_tls`, the framing is
//! `lfw_channel`'s, and what is written here is which of their answers reaches
//! the console and when the greeting has been agreed.
//!
//! # What this build says, and what composes it
//!
//! The greeting, and the two upstream frames that carry the recording rings.
//! The greeting is the exchange that makes a session worth anything: this end
//! sends it the moment the record layer will carry one, and the server's is what
//! sets [`ManagementChannel::agreed`] — the single fact the redial schedule in
//! the domain that owns the network may start afresh on.
//!
//! **The frames are composed here and the ring bytes come from elsewhere.** The
//! domain that owns the network reads the recorder's window and has no
//! vocabulary for a frame, so what crosses the relay is the recording, the
//! position and the bytes, and the header goes on here — where the framing's
//! refusals belong. Were a length stated over there, a defect at that end would
//! print on this appliance's own console as the management server breaking the
//! protocol, and send an operator to the far end of a wire they cannot reach.
//!
//! What that does not buy is honesty about content: the bytes and the position
//! are still that domain's. What the split bounds is the frame **type**.
//!
//! **A frame that is not the greeting is counted and dropped.** It is not a
//! violation: a server that speaks the rest of the protocol to an appliance that
//! has not shipped its half yet is a server running ahead of this build, and
//! refusing it would make an upgrade of one end an outage of the pair. What
//! bounds it is the decoder, which holds one frame's worth and never two.
//!
//! # No key, no traffic secret, no plaintext and no peer certificate leaves
//!
//! The console records here carry a discriminant out of a closed vocabulary, a
//! registry code point, a frame tally and a protocol version. The bytes of a
//! frame are a customer's recording or a management server's instruction; the
//! bytes of a certificate are a peer's. None of them reaches a surface.

use alloc::sync::Arc;

use lfw_channel::{
    Decoded, Frame, FrameDecoder, Hello, MAX_FRAME_LEN, Ring, Side, VERSION, Violation, encode,
    encoded_len,
};
use lfw_log::{DomainDetail, Refusal, RefusalDetail};
use lfw_tls::{Bump, CHANNEL_OUTCOME_RECORDS, ChannelClient, CryptoProvider, Turn};
use pd_runtime::{Answered, SHIPPED_RING_BYTES};

use crate::delegate::{HeldAnchor, HeldCertificate};

/// The most console records one channel session owes.
///
/// Two outcomes' worth — the handshake's, and how a session that came up then
/// ended — plus the framing's account at each of the two states it has, the one
/// rule a peer may have broken, and the one shipment this end may have refused
/// to compose. A sum and not a bound anybody guesses at, and none of its terms a
/// peer's to multiply: there is no third outcome, whatever a server does on the
/// wire, the framing has no third state, and a refused shipment ends the session
/// that carried it.
pub const CHANNEL_RECORDS: usize = CHANNEL_OUTCOME_RECORDS * 2 + 4;

/// Bytes of plaintext this end composes for its own greeting.
///
/// A named constant rather than a call, because it is what the array below is
/// sized by and a mismatch would be an encode this end refuses on a path with
/// nothing to refuse it to.
const APPLIANCE_GREETING_LEN: usize = lfw_channel::HEADER_LEN + lfw_channel::APPLIANCE_HELLO_LEN;

const _: () = assert!(APPLIANCE_GREETING_LEN == 10);

/// Bytes of plaintext one upstream frame occupies, and the ring position in
/// front of its ring bytes. Sized by the relay's bound rather than the framing's
/// megabyte: what decides one frame's size is the answer buffer's room.
const UPSTREAM_FRAME_LEN: usize = lfw_channel::HEADER_LEN + RING_POSITION_LEN + SHIPPED_RING_BYTES;
const RING_POSITION_LEN: usize = 8;

const _: () = {
    // A maximal shipment composes into the array below, so the encoder has
    // nothing to refuse for want of room on any shipment this end accepts.
    assert!(UPSTREAM_FRAME_LEN <= lfw_channel::MAX_FRAME_LEN);
    assert!(SHIPPED_RING_BYTES <= lfw_channel::MAX_PAYLOAD_LEN - RING_POSITION_LEN);
};

/// One recording's bytes to put on the wire, as the relay handed them over.
///
/// A value rather than three parameters because the three are one fact: bytes
/// without the ring name no frame, and either without the position is a run of
/// pcapng an ingest cannot place.
pub struct Shipment<'bytes> {
    pub ring: Ring,
    pub position: u64,
    pub bytes: &'bytes [u8],
}

/// Everything this domain needs to open one channel session.
///
/// A value rather than four parameters, because the four are only worth
/// anything together: a certificate without the key it binds authenticates
/// nothing, an anchor without the address it was delivered for validates the
/// wrong thing, and either without the provider is a session that cannot start.
pub struct ChannelIdentity {
    pub provider: Arc<CryptoProvider>,
    /// The device certificate this appliance presents.
    pub certificate: HeldCertificate,
    pub operation: Arc<dyn lfw_tls::SignOperation>,
    /// The trust anchor the management plane that owns this appliance delivered.
    pub anchor: HeldAnchor,
    /// The address literal the store domain published and the transport dialled,
    /// which is what the server's certificate is held to.
    ///
    /// **Read by this domain from the region the store domain publishes**, and
    /// never handed over by the domain that owns the network. That is the whole
    /// of why it is here: the address is half of the trust decision, and a
    /// network-facing domain that could choose it could point this end's
    /// validation at a name a server it controls holds a certificate for.
    pub endpoint: [u8; 4],
}

/// One channel session: the record layer, the framing over it, and what the two
/// have agreed.
///
/// The client and the decoder are one value because they are one session: the
/// decoder's reassembly buffer is handed on from session to session, and a
/// decoder that outlived its client would be reading the next server's bytes
/// against the last one's greeting state.
struct Dialogue<'arena> {
    client: ChannelClient<'arena>,
    decoder: FrameDecoder<'arena>,
    /// Whether this end's own greeting has been handed to the record layer. Once
    /// and never again: the greeting is the first frame in each direction, so a
    /// second would be a frame the far end refuses.
    greeted: bool,
    /// Whether the server's greeting has been read. **The one fact the redial
    /// schedule is reset on**, latched for the life of the session.
    agreed: bool,
    /// Frames each way, the greetings included. Counts and never contents.
    sent: u64,
    received: u64,
    /// The rule the server broke, where it broke one.
    violation: Option<Violation>,
    /// Whether the handshake's outcome, the ending of a session that came up,
    /// and the framing's account have each been put on the console.
    ///
    /// **Reported when they settle rather than when the session ends**, and that
    /// is the difference between this protocol and the onboarding server's: an
    /// onboarding session is a request and an answer and is over in a moment,
    /// while the channel is a connection an appliance holds open for as long as
    /// it is up. A channel that reported at the close would say nothing at all
    /// about the one state an operator most wants to see, and would say it only
    /// once the thing they were looking for had already gone wrong.
    ///
    /// Each latches on its own, so a session says each of them once and a peer
    /// cannot make it say any of them twice.
    reported_outcome: bool,
    reported_ending: bool,
    reported_framing: bool,
    /// Whether the framing's account has been said a second time, for the state
    /// the first cannot show: this appliance has begun shipping its recordings.
    ///
    /// **Two states and not a record per frame.** A greeted channel and a
    /// shipping channel are different things to look for, and a node that greets
    /// and never ships is the fault worth seeing. It stays bounded by being a
    /// state: the second record is owed once, whatever the wire does after.
    reported_shipping: bool,
}

/// The channel as the relay drives it: the identity a session is opened with,
/// the session running now, and what the last one left for the console.
pub struct ManagementChannel {
    arena: &'static Bump,
    mark: usize,
    /// The instant a certificate chain is judged against, refreshed at each open
    /// from the domain's own clock.
    now: u64,
    /// What a session is opened with, or `None` on an appliance nobody owns —
    /// which is the ordinary state of a node that has never been onboarded, and
    /// a state in which the relay carries the onboarding server instead.
    identity: Option<ChannelIdentity>,
    /// The reassembly buffer, when no session holds it. One megabyte, allocated
    /// once at bring-up and handed from session to session for the domain's
    /// life: a buffer per session would be a megabyte of the arena a peer
    /// decides how often is claimed.
    spare: Option<&'static mut [u8; MAX_FRAME_LEN]>,
    session: Option<Dialogue<'static>>,
    /// Where one upstream frame is composed before the record layer takes it. A
    /// field because it is one frame's worth and a protection domain's stack is
    /// not where that belongs.
    composed: [u8; UPSTREAM_FRAME_LEN],
    /// What the last pass left for the console, taken by the domain after the
    /// pass that produced it.
    staged: [Option<DomainDetail>; CHANNEL_RECORDS],
}

impl ManagementChannel {
    /// A channel with nowhere to dial and no session, holding the buffer every
    /// session it ever opens will reassemble into.
    pub const fn new(
        arena: &'static Bump,
        mark: usize,
        held: Option<&'static mut [u8; MAX_FRAME_LEN]>,
    ) -> Self {
        Self {
            arena,
            mark,
            now: 0,
            identity: None,
            spare: held,
            session: None,
            composed: [0; UPSTREAM_FRAME_LEN],
            staged: [None; CHANNEL_RECORDS],
        }
    }

    /// Take the identity a session is opened with, which arrives once the
    /// delegation has answered and this appliance turns out to have an owner.
    pub fn adopted(&mut self, identity: ChannelIdentity) {
        self.identity = Some(identity);
    }

    /// Whether this appliance holds what a channel session needs.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.identity.is_some()
    }

    /// The instant a chain is judged against on the next open.
    pub const fn at(&mut self, now: u64) {
        self.now = now;
    }

    /// Whether the greeting has been agreed in the session running now.
    #[must_use]
    pub fn agreed(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|dialogue| dialogue.agreed)
    }

    /// What the last pass left for the console, cleared as it is taken.
    pub fn take_records(&mut self) -> [Option<DomainDetail>; CHANNEL_RECORDS] {
        core::mem::replace(&mut self.staged, [None; CHANNEL_RECORDS])
    }

    /// Begin a session, giving up whatever the last one held.
    ///
    /// The arena is wound back **before** the session as well as after it, on the
    /// onboarding server's terms: a session that ended by faulting its way out of
    /// this domain would otherwise leave the region short for the next attempt,
    /// and a schedule that never gives up is exactly the caller that would meet
    /// it.
    pub fn opened(&mut self) {
        // Before the reset, so the buffer's borrow is given back while the
        // allocation behind it is still accounted for. It is not the arena's —
        // it was taken before the mark — but the decoder that holds it is.
        self.recover();
        self.arena.reset_to(self.mark);
        self.staged = [None; CHANNEL_RECORDS];
        let Some(identity) = self.identity.as_ref() else {
            // A session on the channel with nothing to open one with. Its own
            // token rather than silence: an appliance whose store published a
            // destination and whose key holder produced no anchor is holding
            // half of what an owner delivered, and the two halves disagreeing is
            // a thing to go and look at.
            self.stage([DomainDetail::Refusal(refusal("channel-identity-absent"))]);
            return;
        };
        let Some(held) = self.spare.take() else {
            // Unreachable: the buffer is recovered above on every path, so it is
            // either in `spare` or in a session this pass has just taken it out
            // of. Named rather than asserted, no fault being admissible on a
            // path a peer paces.
            self.stage([DomainDetail::Refusal(refusal("channel-buffer-unavailable"))]);
            return;
        };
        let opened = ChannelClient::open(
            Arc::clone(&identity.provider),
            self.arena,
            self.now,
            identity.endpoint,
            identity.certificate.as_bytes(),
            Arc::clone(&identity.operation),
            identity.anchor.as_bytes(),
        );
        match opened {
            Ok(client) => {
                self.session = Some(Dialogue {
                    client,
                    decoder: FrameDecoder::new(Side::Server, held),
                    greeted: false,
                    agreed: false,
                    sent: 0,
                    received: 0,
                    violation: None,
                    reported_outcome: false,
                    reported_ending: false,
                    reported_framing: false,
                    reported_shipping: false,
                });
            }
            Err(outcome) => {
                // The buffer goes straight back: no session took it, and a
                // buffer lost here is every later attempt refused for want of
                // one.
                self.spare = Some(held);
                self.stage(outcome.records().into_iter().flatten());
            }
        }
    }

    /// One turn: give the record layer what arrived, read what it decrypted as
    /// frames, and put back what this end owes.
    pub fn advance(&mut self, received: &[u8], answer: &mut [u8]) -> Answered {
        self.turn(received, None, answer)
    }

    /// One turn that also composes an upstream frame out of `shipment`.
    ///
    /// A shipment this end will not compose **ends the session**, and the token
    /// beside it says which rule stopped it. It cannot be dropped instead: the
    /// domain that handed it over moves its ring cursor on the answer, so one
    /// that went nowhere quietly would be a hole nothing can notice.
    pub fn ship(&mut self, shipment: Shipment<'_>, answer: &mut [u8]) -> Answered {
        self.turn(&[], Some(shipment), answer)
    }

    fn turn(
        &mut self,
        received: &[u8],
        shipment: Option<Shipment<'_>>,
        answer: &mut [u8],
    ) -> Answered {
        let Self {
            session, composed, ..
        } = self;
        let Some(dialogue) = session.as_mut() else {
            // Nothing opened, so there is nothing to say and nothing to wait
            // for. Finished rather than silent, on the onboarding server's
            // terms: a session this domain cannot carry is one the transport
            // should stop holding a connection for.
            return Answered {
                sent: 0,
                finished: true,
                agreed: false,
            };
        };
        let first = dialogue.client.advance(received, answer);
        dialogue.read_frames();
        dialogue.greet();
        let refused = shipment.and_then(|shipment| dialogue.compose(shipment, composed));
        // A second turn, which is what encrypts anything the frame reading just
        // pushed and takes it toward the wire. The room is what the first turn
        // left. A single call would answer every greeting one delivery late,
        // because the library produces bytes only when it is asked.
        let second = drive_again(&mut dialogue.client, answer, first.sent);
        let agreed = dialogue.agreed;
        let settled = dialogue.settled();
        self.stage(settled.into_iter().flatten());
        if let Some(cause) = refused {
            self.stage([DomainDetail::Refusal(refusal(cause))]);
        }
        Answered {
            sent: second.sent,
            finished: second.finished || refused.is_some(),
            agreed,
        }
    }

    /// End the session, take what it came to, and give the region back.
    pub fn closed(&mut self) {
        // Read into plain values while the session's allocations are still live
        // and the borrow of it has ended: an outcome may hold the library's own
        // error, which may hold an allocation out of this arena, and the reset
        // below is what would take it away underneath a record.
        let closing = self.session.as_mut().map(|dialogue| {
            // The transport went away, so whatever the session had not settled
            // for itself is settled as that — and a session that already has an
            // account keeps it, the transport's end saying nothing about a peer
            // that refused this appliance.
            dialogue.client.ended();
            // Whatever has not already been said. A session that came up and was
            // then dropped said both of these while it was up, and repeating
            // them here would put the same fact on the console twice under two
            // sets of tallies.
            let settled = dialogue.settled();
            let framing = (!dialogue.reported_framing).then(|| dialogue.framing());
            (settled, framing, dialogue.violation)
        });
        if let Some((settled, framing, violation)) = closing {
            self.stage(settled.into_iter().flatten());
            self.stage(framing);
            if let Some(violation) = violation {
                self.stage([DomainDetail::Refusal(refusal(violated(violation)))]);
            }
        }
        self.recover();
        self.arena.reset_to(self.mark);
    }

    /// Take the reassembly buffer back off whatever session held it.
    fn recover(&mut self) {
        if let Some(dialogue) = self.session.take() {
            self.spare = Some(dialogue.decoder.release());
        }
    }

    /// Put `records` in the free slots, in order.
    ///
    /// Total by construction: [`CHANNEL_RECORDS`] is the sum of what one session
    /// can produce, so the iterator runs out before the slots do — and a record
    /// that found none is dropped rather than panicking, no fault being
    /// admissible on a path a peer paces.
    fn stage(&mut self, records: impl IntoIterator<Item = DomainDetail>) {
        let mut free = self.staged.iter_mut().filter(|slot| slot.is_none());
        for record in records {
            let Some(slot) = free.next() else {
                return;
            };
            *slot = Some(record);
        }
    }
}

impl Dialogue<'_> {
    /// Hand this end's greeting to the record layer, once.
    ///
    /// Composed into a fixed array of exactly one greeting's length, so the
    /// encoder has nothing to refuse for want of room and the only refusal it
    /// can raise is one this appliance's own code would have to have caused.
    fn greet(&mut self) {
        if self.greeted || self.violation.is_some() {
            return;
        }
        let frame = Frame::Hello(Hello::Appliance);
        let mut composed = [0_u8; APPLIANCE_GREETING_LEN];
        let written = match encode(Side::Appliance, &frame, &mut composed) {
            Ok(written) => written,
            // Unreachable while the array above is `encoded_len`'s answer for
            // this frame, which the assertion at the head of this file holds it
            // to. Answered rather than asserted: this runs on a path a peer
            // paces, and the session simply says nothing.
            Err(_) => return,
        };
        debug_assert_eq!(written, encoded_len(&frame));
        // The record layer takes what it has room for. It has room: the greeting
        // is ten bytes and this end has pushed nothing else, so a short push
        // here would be the library's held-bytes bound reached by a session that
        // has sent nothing.
        if self
            .client
            .push(composed.get(..written).unwrap_or_default())
            == written
        {
            self.greeted = true;
            self.sent = self.sent.saturating_add(1);
        }
    }

    /// Compose one upstream frame and hand it to the record layer, answering the
    /// token of the rule that stopped it where one did.
    ///
    /// Three rules with a token each, because each sends an operator somewhere
    /// different: a shipment past what one frame carries is the reading domain
    /// asking for more than the relay's bound; one before the greeting is that
    /// domain speaking out of turn; and a record layer that will not take a
    /// frame whole is a session already holding too much.
    fn compose(
        &mut self,
        shipment: Shipment<'_>,
        composed: &mut [u8; UPSTREAM_FRAME_LEN],
    ) -> Option<&'static str> {
        let Shipment {
            ring,
            position,
            bytes,
        } = shipment;
        if bytes.len() > SHIPPED_RING_BYTES {
            return Some("channel-shipment-too-long");
        }
        if !self.agreed || !self.greeted || self.violation.is_some() {
            return Some("channel-shipment-before-greeting");
        }
        let frame = match ring {
            Ring::Log => Frame::UpRecords { position, bytes },
            Ring::Capture => Frame::UpCapture { position, bytes },
        };
        // Settled before a byte is pushed: `push` takes what it has room for and
        // says how much, which for a length-prefixed frame is a shortfall found
        // with the front of it already queued.
        if !self.client.drained() {
            return Some("channel-shipment-not-taken");
        }
        let written = match encode(Side::Appliance, &frame, composed) {
            Ok(written) => written,
            // Unreachable while the array is sized by the bound checked above,
            // which the assertions at the head of this file hold it to.
            // Answered rather than asserted: this runs on a path a peer paces.
            Err(_) => return Some("channel-shipment-too-long"),
        };
        debug_assert_eq!(written, encoded_len(&frame));
        if self
            .client
            .push(composed.get(..written).unwrap_or_default())
            != written
        {
            return Some("channel-shipment-not-taken");
        }
        self.sent = self.sent.saturating_add(1);
        None
    }

    /// Read everything the record layer decrypted as frames.
    ///
    /// Bounded by the plaintext in hand rather than by a count: the decoder takes
    /// no byte past the end of the frame it is assembling, so the loop consumes
    /// at least one byte per turn and ends when there are none left.
    fn read_frames(&mut self) {
        if self.violation.is_some() {
            // A stream whose framing is wrong has no next frame — where the
            // following header starts is exactly what has been lost — so nothing
            // more is read from it and the plaintext is left where it is.
            return;
        }
        loop {
            let taken = {
                let plaintext = self.client.received();
                if plaintext.is_empty() {
                    return;
                }
                self.decoder.absorb(plaintext)
            };
            self.client.consumed(taken);
            loop {
                match self.decoder.next_frame() {
                    Decoded::Partial => break,
                    Decoded::Violated(violation) => {
                        self.violation = Some(violation);
                        // The peer is owed a goodbye: a byte stream with a
                        // delimiter at both ends is what keeps a truncated
                        // session from passing for a complete one.
                        self.client.close();
                        return;
                    }
                    Decoded::Frame(frame) => {
                        if let Frame::Hello(Hello::Server { .. }) = frame {
                            self.agreed = true;
                        }
                        self.received = self.received.saturating_add(1);
                    }
                }
            }
            if taken == 0 {
                // The decoder took nothing and produced nothing whole, which is
                // a peer that has already broken the protocol — handled above —
                // or a frame the buffer is mid-way through. Either way there is
                // no progress to be had this turn.
                return;
            }
        }
    }

    /// The records this session owes that it has not yet said, taken once each.
    ///
    /// Three things settle: the handshake's outcome, how a session that came up
    /// then ended, and the framing's account. **The ending never precedes the
    /// outcome it belongs to**, in this pass or an earlier one — a server may
    /// greet this appliance and refuse it in one delivery, and an operator
    /// reading the refusal above the session would be reading two sessions.
    fn settled(&mut self) -> [Option<DomainDetail>; CHANNEL_RECORDS] {
        let mut taken = [None; CHANNEL_RECORDS];
        let mut at = 0;
        if !self.reported_outcome
            && let Some(outcome) = self.client.outcome()
        {
            self.reported_outcome = true;
            at = fill(&mut taken, at, outcome.records());
        }
        if self.reported_outcome
            && !self.reported_ending
            && let Some(ending) = self.client.ending()
        {
            self.reported_ending = true;
            at = fill(&mut taken, at, ending.records());
        }
        if !self.reported_framing && self.agreed {
            self.reported_framing = true;
            if let Some(slot) = taken.get_mut(at) {
                *slot = Some(self.framing());
                at = at.saturating_add(1);
            }
        }
        // The greeting is one frame each way, so a tally past it is this
        // appliance's own statement that a recording has left it.
        if self.reported_framing && !self.reported_shipping && self.sent > 1 {
            self.reported_shipping = true;
            if let Some(slot) = taken.get_mut(at) {
                *slot = Some(self.framing());
            }
        }
        taken
    }

    /// What the framing above this session carried.
    fn framing(&self) -> DomainDetail {
        DomainDetail::ChannelFrames {
            agreed: self.agreed,
            // This end's own constant once agreed, and zero where nothing was: a
            // greeting naming any other version never becomes a frame at all, so
            // the number says which build the pair settled on rather than what
            // the peer claimed.
            version: if self.agreed { VERSION } else { 0 },
            sent: self.sent,
            received: self.received,
        }
    }
}

/// Put one outcome's records in `taken` from `at`, answering where the next one
/// goes. Total by construction, [`CHANNEL_RECORDS`] being the sum of what one
/// session produces; a record that found no slot is dropped rather than
/// panicking, no fault being admissible on a path a peer paces.
fn fill(
    taken: &mut [Option<DomainDetail>; CHANNEL_RECORDS],
    at: usize,
    records: [Option<DomainDetail>; CHANNEL_OUTCOME_RECORDS],
) -> usize {
    let mut at = at;
    for record in records.into_iter().flatten() {
        let Some(slot) = taken.get_mut(at) else {
            return at;
        };
        *slot = Some(record);
        at = at.saturating_add(1);
    }
    at
}

/// Drive the session once more into whatever room the first turn left, and
/// answer for the pair.
///
/// The onboarding server's shape and its reasoning: the library produces bytes
/// only when it is asked, so plaintext pushed after a turn sits unencrypted
/// until the next one.
fn drive_again(client: &mut ChannelClient<'_>, answer: &mut [u8], already: usize) -> Turn {
    let Some(room) = answer.get_mut(already..) else {
        return Turn {
            sent: already,
            finished: false,
        };
    };
    let Turn { sent, finished } = client.advance(&[], room);
    Turn {
        sent: already.saturating_add(sent),
        finished,
    }
}

/// A refusal this domain raises about its channel. `signalled` is `false` on
/// every one: there is no device here to be told anything.
const fn refusal(cause: &'static str) -> Refusal {
    Refusal {
        cause,
        detail: RefusalDetail::None,
        signalled: false,
    }
}

/// The rule a management server broke, as a console token.
///
/// **One token per rule and no token covering two**, which is the whole
/// obligation this function carries: a deployed node has no shell, and a server
/// sending a header of a protocol this is not, a frame its own end may not send,
/// a document past its bound and a range answer that contradicts itself are four
/// different things to go and look at.
///
/// **The discriminant and never the context.** Every variant of the framing's
/// own vocabulary carries the byte, the length or the type that broke it — a
/// peer's own bytes, and a console line is not a place to repeat them.
const fn violated(violation: Violation) -> &'static str {
    match violation {
        Violation::ReservedNonZero { .. } => "channel-reserved-non-zero",
        Violation::UnknownType { .. } => "channel-unknown-frame-type",
        Violation::PayloadTooLong { .. } => "channel-payload-too-long",
        Violation::WrongDirection { .. } => "channel-wrong-direction",
        Violation::FirstFrameNotHello { .. } => "channel-first-frame-not-hello",
        Violation::VersionMismatch { .. } => "channel-version-mismatch",
        Violation::PayloadLength { .. } => "channel-payload-length",
        Violation::UnknownRing { .. } => "channel-unknown-ring",
        Violation::UnknownRangeStatus { .. } => "channel-unknown-range-status",
        Violation::BytesOnEndedRange { .. } => "channel-bytes-on-ended-range",
        Violation::ConfigDocumentTooLong { .. } => "channel-document-too-long",
        Violation::ResultLineNotPrintable { .. } => "channel-result-line-not-printable",
    }
}
