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
//! The greeting, the two upstream frames that carry the recording rings, and the
//! configuration operations the server pushes down. The greeting is the exchange
//! that makes a session worth anything: this end sends it the moment the record
//! layer will carry one, and the server's is what sets
//! [`ManagementChannel::agreed`] — the single fact the redial schedule in the
//! domain that owns the network may start afresh on.
//!
//! **A configuration operation is carried out here and decided elsewhere.** A
//! staged document crosses to the domain that owns the datastore and comes back as
//! a result line this end frames; a commit is made provisionally and **ends the
//! session**, because the confirmation must arrive on a connection opened after
//! it; a confirmation on a later session keeps it, and a deadline this appliance
//! armed from its own clock puts the previous configuration back where none does.
//! Nothing about a document is read here — [`crate::configuration`] carries the
//! delegation and the deadline, and the reader of an attacker's XML is a domain
//! that holds no network region at all.
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
//! **A frame this build does not act on is counted and dropped.** It is not a
//! violation: a server that speaks a part of the protocol an appliance has not
//! shipped yet is a server running ahead of this build, and refusing it would make
//! an upgrade of one end an outage of the pair. What bounds it is the decoder,
//! which holds one frame's worth and never two. No frame a server may send is in
//! that case today — every one of the six is acted on — so the tolerance is kept
//! for the next frame the protocol grows.
//!
//! # No key, no traffic secret, no plaintext and no peer certificate leaves
//!
//! The console records here carry a discriminant out of a closed vocabulary, a
//! registry code point, a frame tally and a protocol version. The bytes of a
//! frame are a customer's recording or a management server's instruction; the
//! bytes of a certificate are a peer's. None of them reaches a surface.

use alloc::sync::Arc;

use lfw_channel::{
    Decoded, Frame, FrameDecoder, Hello, MAX_FRAME_LEN, RangeStatus, Ring, Side, VERSION,
    Violation, encode, encoded_len,
};
use lfw_log::{DomainDetail, Refusal, RefusalDetail};
use lfw_tls::{Bump, CHANNEL_OUTCOME_RECORDS, ChannelClient, CryptoProvider, Turn};
use pd_runtime::{
    Acknowledged, Answered, MAX_ANSWER_LEN, RANGE_ANSWER_BYTES, RangeRequest, SHIPPED_RING_BYTES,
};
use wire::{DownloadSink, RangeOutcome, RangeWant};

use crate::configuration::{ChannelConfig, ConfigFailure, StageResult};
use crate::delegate::{HeldAnchor, HeldCertificate};

/// The most console records one pass leaves.
///
/// Two outcomes' worth — the handshake's and the ending — plus the framing's
/// account at each of its two states, the delivery account at each of *its* two,
/// the clamped acknowledgement, the range answer that ended for a reason of its
/// own, the one frame this end refused to compose, and the two a configuration
/// pass may owe: the operation that failed and the deadline that reverted.
///
/// A sum and not a bound anybody guesses at, and no term of it a peer's to
/// multiply: one pass carries out one configuration operation and reads one
/// deadline, a refused shipment and a refused range read share the one refusal
/// slot, and the clamp is latched so a thousand impossible acknowledgements buy
/// one line. The pass that ends a session owes fewer, the rule a peer broke
/// standing in for what a running one settles.
pub const CHANNEL_RECORDS: usize = CHANNEL_OUTCOME_RECORDS * 2 + 9;

/// The recordings, in the order this file indexes its per-ring state by.
const RINGS: [Ring; 2] = [Ring::Log, Ring::Capture];

/// Which slot of that state a recording is.
const fn ring_index(ring: Ring) -> usize {
    match ring {
        Ring::Log => 0,
        Ring::Capture => 1,
    }
}

/// Bytes of plaintext this end composes for its own greeting.
///
/// A named constant rather than a call, because it is what the array below is
/// sized by and a mismatch would be an encode this end refuses on a path with
/// nothing to refuse it to.
const APPLIANCE_GREETING_LEN: usize = lfw_channel::HEADER_LEN + lfw_channel::APPLIANCE_HELLO_LEN;

const _: () = assert!(APPLIANCE_GREETING_LEN == 10);

/// Bytes of plaintext one validate-result frame occupies at most: the header and
/// the longest line the configuration vocabulary can compose.
///
/// A named constant rather than a call, on the greeting's terms: it is what the
/// array is sized by, and a mismatch would be an encode this end refuses on a path
/// with nothing to refuse it to.
const RESULT_FRAME_LEN: usize = lfw_channel::HEADER_LEN + MAX_ANSWER_LEN;

const _: () = assert!(RESULT_FRAME_LEN <= lfw_channel::MAX_FRAME_LEN);

/// Bytes of plaintext one upstream frame occupies, and the ring position in
/// front of its ring bytes. Sized by the relay's bound rather than the framing's
/// megabyte: what decides one frame's size is the answer buffer's room.
const UPSTREAM_FRAME_LEN: usize = lfw_channel::HEADER_LEN + RING_POSITION_LEN + SHIPPED_RING_BYTES;
const RING_POSITION_LEN: usize = 8;

/// Bytes of plaintext one frame of a range answer occupies: the header, the ring,
/// the status and the position, then the extent's bytes.
///
/// Exactly [`UPSTREAM_FRAME_LEN`], the two bytes a range answer's prefix carries
/// over a shipment's being exactly the two the extent is narrower by — which is
/// what lets one array compose either frame.
const RANGE_FRAME_LEN: usize = lfw_channel::HEADER_LEN + RANGE_PREFIX_LEN + RANGE_ANSWER_BYTES;
const RANGE_PREFIX_LEN: usize = 1 + 1 + 8;

const _: () = {
    // A maximal shipment composes into the array below, so the encoder has
    // nothing to refuse for want of room on any shipment this end accepts.
    assert!(UPSTREAM_FRAME_LEN <= lfw_channel::MAX_FRAME_LEN);
    assert!(SHIPPED_RING_BYTES <= lfw_channel::MAX_PAYLOAD_LEN - RING_POSITION_LEN);
    // And so does a maximal answer frame, into the same one.
    assert!(RANGE_FRAME_LEN == UPSTREAM_FRAME_LEN);
    assert!(RANGE_ANSWER_BYTES <= lfw_channel::MAX_PAYLOAD_LEN - RANGE_PREFIX_LEN);
};

/// Which recording a ring selector names, and back.
///
/// Two functions rather than one type, because the two vocabularies belong to two
/// crates that must not depend on each other: the framing's ring is the wire's and
/// the recording is the relay's, and this domain is the one place both are
/// visible.
const fn recording_of(ring: Ring) -> DownloadSink {
    match ring {
        Ring::Log => DownloadSink::Log,
        Ring::Capture => DownloadSink::Capture,
    }
}

const fn ring_of(recording: DownloadSink) -> Ring {
    match recording {
        DownloadSink::Log => Ring::Log,
        DownloadSink::Capture => Ring::Capture,
    }
}

const fn status_of(outcome: RangeOutcome) -> RangeStatus {
    match outcome {
        RangeOutcome::Data => RangeStatus::Data,
        RangeOutcome::Overwritten => RangeStatus::Overwritten,
        RangeOutcome::MediumRefused => RangeStatus::MediumRefused,
    }
}

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

/// What the reader made of one read for a range answer, as the relay handed it
/// over.
///
/// The recording is deliberately absent: the ring an answer names is this end's,
/// held with the request it decoded, so a neighbour naming one here could answer a
/// question that was never put.
struct RangeChunk<'bytes> {
    outcome: RangeOutcome,
    position: u64,
    bytes: &'bytes [u8],
}

/// Everything this domain needs to open one channel session.
///
/// A value rather than four parameters, because the four are only worth
/// anything together: a certificate without the key it binds authenticates
/// nothing, an anchor without the address it was delivered for validates the
/// wrong thing, and either without the provider is a session that cannot start.
pub struct ChannelIdentity {
    pub provider: Arc<CryptoProvider>,
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
    /// One past the last ring byte this end has composed into a frame, per
    /// recording. **The bound every acknowledgement is judged against**, and it
    /// is judged here rather than where the cursors are kept because this is the
    /// only place that knows: this domain composes every frame, so `position`
    /// plus the bytes behind it is exactly what has left the appliance.
    sent_to: [u64; RINGS.len()],
    /// How far the server says it has durably taken each recording, as this end
    /// will let itself believe.
    ///
    /// Seeded by the greeting, which is a **resume point** and deliberately not
    /// bounded by [`Self::sent_to`]: a session that has sent nothing has sent
    /// nothing to be acknowledged, and the number the server opens with is where
    /// it wants the appliance to start rather than a claim about this session.
    /// Every later acknowledgement is clamped to what has been sent and may only
    /// move forward.
    held: [u64; RINGS.len()],
    /// Whether the greeting's resume point and the first acknowledgement past it
    /// have each been put on the console.
    ///
    /// **Two states rather than a record per acknowledgement.** A server chooses
    /// how often it acknowledges, so a record apiece would be a console line at
    /// a peer's chosen rate. What an operator needs is the pair of facts a
    /// session has: where it was told to start, and whether anything it shipped
    /// has since been taken.
    reported_resume: bool,
    reported_acked: bool,
    /// An acknowledgement past what this end has sent, kept for the console and
    /// said **once** per session, for the reason above: a peer sending a
    /// thousand impossible claims buys one line.
    clamped: Option<(u64, u64)>,
    reported_clamp: bool,
    /// The rule a range read broke, where the server broke one. It ends the
    /// session, on a violation's terms: what the peer asked for is past a bound of
    /// this appliance's, and the connection is over.
    refused_range: Option<&'static str>,
    /// Why the last range answer ended, where it ended for a reason other than
    /// being served whole, and not yet said.
    ///
    /// Separate from a refusal because it does not end the session: the answer
    /// ended and the connection did not. Taken once by the pass that produced it,
    /// so it is bounded by the answers a peer asks for and not by the frames one
    /// spends.
    range_ended: Option<&'static str>,
    /// The range read being answered, or `None` where none is.
    ///
    /// **One at a time, and that is a bound on the peer rather than a
    /// simplification.** A server that could have several answers in flight could
    /// have this appliance reading its own medium in as many places at once as it
    /// cared to name, so a second request arriving while one is in progress ends
    /// the session instead. The composing end holds the state because it is the
    /// end that decoded the request: it knows which ring was asked for, so no
    /// neighbour can answer a question that was never put.
    range: Option<RangeRequest>,
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
    /// The delegation to the domain that owns the datastore, and the one commit
    /// that may be awaiting confirmation. **Outside the session**, which is the
    /// whole of how the fresh-connection rule is kept: a commit made on one
    /// session is confirmed on a later one, so what remembers it cannot be a value
    /// the close of a session takes with it.
    config: ChannelConfig,
    /// Which session is running, counted from the first this domain ever opened —
    /// a number this appliance assigns, so the fresh-connection check is a
    /// comparison rather than a claim the peer could restate.
    serial: u64,
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
        config: ChannelConfig,
    ) -> Self {
        Self {
            arena,
            mark,
            now: 0,
            identity: None,
            spare: held,
            session: None,
            config,
            serial: 0,
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

    /// The instant a chain is judged against on the next open, and the reading a
    /// confirmation deadline is measured against on this pass.
    ///
    /// Refreshed on every pass rather than only at the open, because the deadline
    /// is what it drives: a reading taken once per session would leave an appliance
    /// whose server greeted it and then went quiet holding an unconfirmed
    /// configuration for as long as the session stayed up.
    pub const fn at(&mut self, now: u64) {
        self.now = now;
    }

    /// How far the server has taken each recording in the session running now,
    /// as this end judged the claim. Nothing, between sessions.
    #[must_use]
    pub fn acknowledged(&self) -> Acknowledged {
        self.session
            .as_ref()
            .map_or(Acknowledged::NONE, Dialogue::acknowledged)
    }

    /// The extent the session running now is waiting for, or `None` for none.
    ///
    /// Read off the request rather than kept beside it, so what the reader is told
    /// is always the remainder: one fact, one home.
    #[must_use]
    pub fn wanted(&self) -> Option<RangeWant> {
        self.session
            .as_ref()?
            .range
            .as_ref()
            .map(RangeRequest::wanted)
    }

    /// One turn that also composes one frame of a range answer out of what the
    /// reader read.
    ///
    /// A frame this end will not compose **ends the session**, on the shipment's
    /// terms and for its reason: the reader retires the frame on the answer, so
    /// one that went nowhere quietly would be a hole in an extent nothing can
    /// notice.
    pub fn answer_range(
        &mut self,
        outcome: RangeOutcome,
        position: u64,
        bytes: &[u8],
        answer: &mut [u8],
    ) -> Answered {
        self.turn(
            &[],
            None,
            Some(RangeChunk {
                outcome,
                position,
                bytes,
            }),
            answer,
        )
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
        // A fresh session is a fresh connection, so the serial moves before
        // anything else can compare against it.
        self.serial = self.serial.saturating_add(1);
        // And before a session exists, so a deadline that passed while this
        // appliance had no connection at all is honoured on the dial rather than
        // on the first byte the new server happens to send: a commit nobody came
        // back to confirm is reverted whether or not anybody ever speaks again.
        self.revert_if_expired();
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
                    sent_to: [0; RINGS.len()],
                    held: [0; RINGS.len()],
                    reported_resume: false,
                    reported_acked: false,
                    clamped: None,
                    reported_clamp: false,
                    refused_range: None,
                    range_ended: None,
                    range: None,
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
        self.turn(received, None, None, answer)
    }

    /// One turn that also composes an upstream frame out of `shipment`.
    ///
    /// A shipment this end will not compose **ends the session**, and the token
    /// beside it says which rule stopped it. It cannot be dropped instead: the
    /// domain that handed it over moves its ring cursor on the answer, so one
    /// that went nowhere quietly would be a hole nothing can notice.
    pub fn ship(&mut self, shipment: Shipment<'_>, answer: &mut [u8]) -> Answered {
        self.turn(&[], Some(shipment), None, answer)
    }

    fn turn(
        &mut self,
        received: &[u8],
        shipment: Option<Shipment<'_>>,
        chunk: Option<RangeChunk<'_>>,
        answer: &mut [u8],
    ) -> Answered {
        let Self {
            session,
            composed,
            config,
            serial,
            now,
            ..
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
        let carried = dialogue.read_frames(config, *now, *serial);
        dialogue.greet();
        let refused = shipment
            .and_then(|shipment| dialogue.compose(shipment, composed))
            .or_else(|| chunk.and_then(|chunk| dialogue.compose_range(chunk, composed)));
        // A second turn, which is what encrypts anything the frame reading just
        // pushed and takes it toward the wire. The room is what the first turn
        // left. A single call would answer every greeting one delivery late,
        // because the library produces bytes only when it is asked.
        let second = drive_again(&mut dialogue.client, answer, first.sent);
        let agreed = dialogue.agreed;
        let ended = dialogue.range_ended.take();
        // Read out of the session and folded in with a refused frame below: both
        // are this end refusing to go on, and a session ends once whichever of
        // them happened.
        let asked = dialogue.refused_range.take();
        let settled = dialogue.settled();
        self.stage(settled.into_iter().flatten());
        if let Some(cause) = ended {
            self.stage([DomainDetail::Refusal(refusal(cause))]);
        }
        let refused = refused.or(asked);
        if let Some(cause) = refused {
            self.stage([DomainDetail::Refusal(refusal(cause))]);
        }
        if let Some(failure) = carried.failure {
            self.stage([DomainDetail::Refusal(failure.refusal())]);
        }
        // The deadline, read against this pass's own instant. After the frames,
        // so a confirmation that arrived in this delivery is honoured before the
        // deadline it beat is judged.
        let reverted = self.revert_if_expired();
        Answered {
            sent: second.sent,
            // A commit ends the session, and that **is** the fresh-connection
            // rule: closing makes a later connection the only place a
            // confirmation can arrive. A revert ends it because the
            // configuration under the session just changed.
            finished: second.finished || refused.is_some() || carried.committed || reverted,
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

    /// Put the previous configuration back where the confirmation deadline has
    /// passed, answering whether one happened — which a caller inside a session
    /// turns into ending it, the server being owed a dial under what is in force.
    fn revert_if_expired(&mut self) -> bool {
        let Some(outcome) = self.config.expired(self.now) else {
            return false;
        };
        // A revert that happened says so through the domain that did it: the
        // datastore's own generation record carries the generation and the
        // outcome. A second here would restate a fact this domain did not decide.
        match outcome {
            Ok(_) => true,
            Err(failure) => {
                self.stage([DomainDetail::Refusal(failure.refusal())]);
                false
            }
        }
    }

    /// Take the reassembly buffer back off whatever session held it.
    fn recover(&mut self) {
        if let Some(dialogue) = self.session.take() {
            self.spare = Some(dialogue.decoder.release());
        }
    }

    /// Put `records` in the free slots, in order.
    ///
    /// Total by construction: [`CHANNEL_RECORDS`] is the sum of what one pass can
    /// produce, so the iterator runs out before the slots do — and a record that
    /// found none is dropped rather than panicking, no fault being admissible on
    /// a path a peer paces.
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
        // Moved only once the record layer has taken the whole frame, which is
        // what makes this "what has been sent" rather than "what was offered":
        // a bound that counted a frame the session refused would let a server
        // acknowledge bytes that never left.
        if let Some(slot) = self.sent_to.get_mut(ring_index(ring)) {
            *slot = (*slot).max(position.saturating_add(bytes.len() as u64));
        }
        None
    }

    /// Take a range read the server asked for, answering the token of the rule it
    /// broke where it broke one.
    ///
    /// **One answer in flight**, which is the bound on how many places at once a
    /// peer can have this appliance reading its own medium. A request arriving
    /// while one is in progress is that bound being broken, and every other cause
    /// is one of the request's three numbers past a constant of this appliance's.
    /// None of them is answered with a status: the statuses say how a read went,
    /// and none of these is a read.
    fn asked(&mut self, ring: Ring, start: u64, length: u64) -> Option<&'static str> {
        if !self.agreed {
            // A request in front of the greeting. The far end has not said who it
            // is in this protocol's terms yet, and an appliance reading its medium
            // for an unopened session is a read nobody asked for.
            return Some("channel-range-before-greeting");
        }
        if self.range.is_some() {
            return Some("channel-range-already-answering");
        }
        match RangeRequest::accept(recording_of(ring), start, length) {
            Ok(request) => {
                self.range = Some(request);
                None
            }
            Err(refusal) => Some(refusal.token()),
        }
    }

    /// Compose one frame of a range answer and hand it to the record layer,
    /// answering the token of the rule that stopped it where one did.
    ///
    /// **The request decides, not the chunk.** The outcome and the bytes come from
    /// a neighbour, so what they are allowed to say is what the request in hand
    /// can be advanced by: the ring is the request's, the length is cut to what
    /// the request still owes and to what one frame carries, and a position that
    /// is not the one this end asked at is a neighbour answering a different
    /// question and ends the session rather than being framed.
    fn compose_range(
        &mut self,
        chunk: RangeChunk<'_>,
        composed: &mut [u8; UPSTREAM_FRAME_LEN],
    ) -> Option<&'static str> {
        let RangeChunk {
            outcome,
            position,
            bytes,
        } = chunk;
        let Some(request) = self.range.as_mut() else {
            // A frame of an answer to a request this end is not holding. The
            // neighbour is answering something nobody asked, and there is no
            // request to advance by it.
            return Some("channel-range-unasked");
        };
        if position != request.wanted().start {
            // The reader read somewhere other than where the request stands. A
            // frame composed from it would place a run of a recording at a
            // position it never came from, which is the one error an ingest
            // cannot detect.
            return Some("channel-range-position-moved");
        }
        if bytes.len() > RANGE_ANSWER_BYTES {
            return Some("channel-range-chunk-too-long");
        }
        if !self.agreed || !self.greeted || self.violation.is_some() {
            return Some("channel-range-before-greeting");
        }
        if !self.client.drained() {
            return Some("channel-range-not-taken");
        }
        let ring = ring_of(request.recording());
        let taken = request.took(outcome, bytes.len());
        // Cut to what the request allowed, which is at most what arrived: the
        // request's own arithmetic is the bound, and a slice of the chunk shorter
        // than the chunk is the whole of how a neighbour's length is refused
        // without a panic.
        let carried = bytes.get(..taken.len).unwrap_or_default();
        let frame = Frame::UpRangeData {
            ring,
            status: status_of(taken.status),
            position: taken.position,
            bytes: carried,
        };
        let written = match encode(Side::Appliance, &frame, composed) {
            Ok(written) => written,
            // Unreachable while the array is sized by the bound checked above.
            // Answered rather than asserted: this runs on a path a peer paces.
            Err(_) => return Some("channel-range-chunk-too-long"),
        };
        debug_assert_eq!(written, encoded_len(&frame));
        if self
            .client
            .push(composed.get(..written).unwrap_or_default())
            != written
        {
            return Some("channel-range-not-taken");
        }
        self.sent = self.sent.saturating_add(1);
        if taken.finished {
            // Retired only once the record layer has taken the whole frame, so an
            // answer that could not be put on the wire is still owed rather than
            // quietly complete.
            self.range = None;
        }
        // A token where the answer ended for a reason: the wire carried the only
        // status that fits and the console carries the cause. It does not end the
        // session — the answer ended, the connection did not — so it is staged
        // beside the frame rather than returned as a refusal.
        self.range_ended = taken.token;
        None
    }

    /// Take an acknowledgement, bounded by what this end has actually sent.
    ///
    /// **The clamp is a safety property and not tidiness.** These numbers become
    /// a reader cursor in a recording's superblock, and a ring refuses a reader
    /// cursor ahead of its writer — refusing the whole checkpoint with it. So an
    /// acknowledgement believed past what was written would not corrupt a
    /// recording; it would stop the appliance making any recording durable at
    /// all, at a management server's choosing. It is cut off here, at the one
    /// place that knows the bound, and the fact that a peer reached for it is
    /// said on the console rather than swallowed.
    ///
    /// Forward only, for the same reason it is forward only everywhere else: a
    /// server that could walk this back could walk the appliance's own record of
    /// what has been delivered back with it.
    fn acknowledge(&mut self, log: u64, capture: u64) {
        for (at, claimed) in [log, capture].into_iter().enumerate() {
            let bound = self.sent_to.get(at).copied().unwrap_or(0);
            if claimed > bound && self.clamped.is_none() {
                self.clamped = Some((claimed, bound));
            }
            if let Some(slot) = self.held.get_mut(at) {
                *slot = (*slot).max(claimed.min(bound));
            }
        }
    }

    /// How far the server has taken each recording, as this end judged it.
    fn acknowledged(&self) -> Acknowledged {
        Acknowledged {
            log: self.held.first().copied().unwrap_or(0),
            capture: self.held.get(1).copied().unwrap_or(0),
        }
    }

    /// Where the two recordings stand between the two ends: taken, and sent.
    fn delivery(&self) -> DomainDetail {
        DomainDetail::ChannelAcked {
            log_acked: self.held.first().copied().unwrap_or(0),
            log_sent: self.sent_to.first().copied().unwrap_or(0),
            capture_acked: self.held.get(1).copied().unwrap_or(0),
            capture_sent: self.sent_to.get(1).copied().unwrap_or(0),
        }
    }

    /// Read everything the record layer decrypted as frames, carrying out what
    /// each one asks for.
    ///
    /// Bounded by the plaintext in hand rather than by a count: the decoder takes
    /// no byte past the end of the frame it is assembling, so the loop consumes
    /// at least one byte per turn and ends when there are none left.
    ///
    /// **A configuration operation ends the reading**, whichever way it went: each
    /// costs a notification and a bounded read at a priority above this one, so a
    /// peer that could multiply them inside one pass would be choosing how long
    /// this domain spends away from the session it carries. The frames behind it
    /// stay in the decoder, so stopping is a pause and not a loss.
    fn read_frames(&mut self, config: &mut ChannelConfig, now: u64, serial: u64) -> Carried {
        let mut carried = Carried::default();
        if self.violation.is_some() {
            // A stream whose framing is wrong has no next frame — where the
            // following header starts is exactly what has been lost — so nothing
            // more is read from it and the plaintext is left where it is.
            return carried;
        }
        loop {
            let taken = {
                let plaintext = self.client.received();
                if plaintext.is_empty() {
                    return carried;
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
                        return carried;
                    }
                    Decoded::Frame(frame) => {
                        self.received = self.received.saturating_add(1);
                        let acted = act(frame, config, now, serial, &mut carried);
                        match acted {
                            Acted::Greeted { log, capture } => {
                                self.agreed = true;
                                // Taken whole, and behind where this appliance
                                // last shipped if that is what it says: the
                                // greeting is where the end that will ingest the
                                // bytes wants them from, and re-shipping a run
                                // costs an ingest nothing because every frame
                                // carries its own position.
                                self.held = [log, capture];
                            }
                            Acted::Acknowledged { log, capture } => {
                                self.acknowledge(log, capture);
                            }
                            Acted::RangeRead {
                                ring,
                                start,
                                length,
                            } => {
                                if let Some(cause) = self.asked(ring, start, length) {
                                    // A request this appliance will not serve. The
                                    // session ends rather than the request being
                                    // answered with a status that would misname
                                    // it: every one of these is the peer past a
                                    // bound of this appliance's, which is a
                                    // protocol violation and not a read that went
                                    // badly.
                                    self.refused_range = Some(cause);
                                    self.client.close();
                                    carried.done = true;
                                }
                            }
                            Acted::Result { line, len } => {
                                self.answer_stage(&line, len, &mut carried);
                            }
                            Acted::Nothing => {}
                        }
                        if carried.done {
                            return carried;
                        }
                    }
                }
            }
            if taken == 0 {
                // The decoder took nothing and produced nothing whole, which is
                // a peer that has already broken the protocol — handled above —
                // or a frame the buffer is mid-way through. Either way there is
                // no progress to be had this turn.
                return carried;
            }
        }
    }

    /// Frame the result line a staging produced and hand it to the record layer,
    /// into an array of exactly one result frame's length — so the only refusal the
    /// encoder can raise is one this appliance's own composer caused.
    fn answer_stage(&mut self, line: &[u8; MAX_ANSWER_LEN], len: usize, carried: &mut Carried) {
        let Some(line) = line.get(..len) else {
            // Unreachable: the length is the composer's own count into the array
            // this borrows. Answered rather than asserted, on every other
            // unreachable branch in this file's terms.
            carried.failure = Some(ConfigFailure::Faulted);
            return;
        };
        let frame = Frame::UpConfigValidateResult { line };
        let mut composed = [0_u8; RESULT_FRAME_LEN];
        let Ok(written) = encode(Side::Appliance, &frame, &mut composed) else {
            carried.failure = Some(ConfigFailure::Faulted);
            return;
        };
        debug_assert_eq!(written, encoded_len(&frame));
        if self
            .client
            .push(composed.get(..written).unwrap_or_default())
            == written
        {
            self.sent = self.sent.saturating_add(1);
        } else {
            // The record layer would not take the whole frame, so half of it is
            // queued or none is. Its own token: a session already holding too much
            // is a different thing to look at from a document this appliance could
            // not decide about.
            carried.failure = Some(ConfigFailure::Faulted);
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
                at = at.saturating_add(1);
            }
        }
        // Where the greeting said to start, said once the greeting has been
        // read. It is the record that makes a resumed channel legible: without
        // it, an appliance told to start at a position it has already passed and
        // one told to start where it left off are the same two lines.
        if self.agreed && !self.reported_resume {
            self.reported_resume = true;
            if let Some(slot) = taken.get_mut(at) {
                *slot = Some(self.delivery());
                at = at.saturating_add(1);
            }
        }
        // And once anything shipped on this session has been taken. Two states
        // and not a line per acknowledgement: a server chooses how often it
        // acknowledges, and a record per one would be a console rate a peer sets.
        if self.reported_resume
            && !self.reported_acked
            && self
                .held
                .iter()
                .zip(&self.sent_to)
                .any(|(held, sent)| *sent > 0 && *held >= *sent)
        {
            self.reported_acked = true;
            if let Some(slot) = taken.get_mut(at) {
                *slot = Some(self.delivery());
                at = at.saturating_add(1);
            }
        }
        if !self.reported_clamp
            && let Some((claimed, bound)) = self.clamped
        {
            self.reported_clamp = true;
            if let Some(slot) = taken.get_mut(at) {
                *slot = Some(DomainDetail::Refusal(Refusal {
                    cause: "channel-ack-past-sent",
                    detail: RefusalDetail::Two(claimed, bound),
                    signalled: false,
                }));
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

/// What reading a delivery's frames left for the pass that called it.
#[derive(Clone, Copy, Debug, Default)]
struct Carried {
    /// The one configuration operation that did not happen, where one did not.
    failure: Option<ConfigFailure>,
    /// Whether a commit was made, which ends the session.
    committed: bool,
    /// Whether the reading is over for this pass.
    done: bool,
}

/// What acting on one frame produced.
enum Acted {
    /// The server's greeting, and where it says each recording is to resume.
    Greeted {
        log: u64,
        capture: u64,
    },
    /// How far the server says it has durably taken each recording, for the
    /// session to bound against what it actually sent.
    Acknowledged {
        log: u64,
        capture: u64,
    },
    /// An extent the server asked for, taken by the end that holds the one
    /// request in flight because that request bounds every frame of the answer.
    RangeRead {
        ring: Ring,
        start: u64,
        length: u64,
    },
    /// A result line owed back, framed by the caller.
    Result {
        line: [u8; MAX_ANSWER_LEN],
        len: usize,
    },
    Nothing,
}

/// Carry out what one frame asks for.
///
/// A free function because of the borrow: a decoded frame borrows the decoder
/// inside the session, so a method on the session could not also take the
/// delegation that lives outside it. Every frame is named rather than folded into
/// a wildcard, so one added to the protocol is a compile error here.
fn act(
    frame: Frame<'_>,
    config: &mut ChannelConfig,
    now: u64,
    serial: u64,
    carried: &mut Carried,
) -> Acted {
    match frame {
        Frame::Hello(Hello::Server { log, capture }) => Acted::Greeted { log, capture },
        Frame::DownConfigStage { document } => {
            let (StageResult { line, len }, failure) = config.stage(document);
            carried.failure = failure;
            carried.done = true;
            Acted::Result { line, len }
        }
        Frame::DownConfigCommit {
            generation,
            confirm_deadline_secs,
        } => {
            match config.commit(generation, confirm_deadline_secs, now, serial) {
                Ok(_) => carried.committed = true,
                Err(failure) => carried.failure = Some(failure),
            }
            carried.done = true;
            Acted::Nothing
        }
        Frame::DownCommitConfirm { generation } => {
            if let Err(failure) = config.confirm(generation, serial) {
                carried.failure = Some(failure);
            }
            carried.done = true;
            Acted::Nothing
        }
        // The acknowledgement's cursors are the session's own state — it is the
        // end that knows what it sent, and so the only end that can bound a
        // claim against it — so they go back to it rather than being taken here.
        Frame::Ack { log, capture } => Acted::Acknowledged { log, capture },
        // The request is the session's own state, for the acknowledgement's
        // reason: it is the end that decoded it, and so the only end that can
        // hold a neighbour's later frames to what was actually asked for.
        Frame::DownRangeRead {
            ring,
            start,
            length,
        } => Acted::RangeRead {
            ring,
            start,
            length,
        },
        // Frames this end sends. A server that sent one is refused by the
        // decoder's own direction check before it becomes a value, so these arms
        // exist to keep the match total rather than to be reached.
        Frame::Hello(Hello::Appliance)
        | Frame::UpRecords { .. }
        | Frame::UpCapture { .. }
        | Frame::UpConfigValidateResult { .. }
        | Frame::UpRangeData { .. } => Acted::Nothing,
    }
}

/// Put one outcome's records in `taken` from `at`, answering where the next one
/// goes. Total by construction, [`CHANNEL_RECORDS`] being the sum of what one
/// pass produces; a record that found no slot is dropped rather than panicking,
/// no fault being admissible on a path a peer paces.
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
