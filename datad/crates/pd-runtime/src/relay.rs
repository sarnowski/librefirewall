//! The network end of the TLS relay: moving a management connection's bytes to
//! the domain that terminates the session, and that domain's answers back onto
//! the wire.
//!
//! # One relay, two connections, never both at once
//!
//! The domain that owns the management port has two TLS connections in its life
//! and exactly one of them exists at a time: the **onboarding** connection an
//! administrator opens to an appliance nobody owns, and the **channel** this
//! appliance dials once it has an owner. An accepted onboarding package shuts
//! the first for good and publishes where to dial, so the two are the two halves
//! of one appliance's life rather than two things to carry side by side.
//!
//! So there is one relay and one window, and [`Relayed`] is the seam: it
//! presents whichever half is live, and its session identity carries **which**
//! half it is. That last part is load-bearing rather than tidy — the two
//! transports number their connections independently, so the same connection id
//! can name one of each, and a relay that compared only the number could carry
//! an onboarding session's account straight into a channel session.
//!
//! # Adversary
//!
//! An **unauthenticated management-plane attacker** in front and a **byzantine
//! neighbour protection domain** behind, and this module is the seam between
//! them. The attacker chooses every byte that crosses and chooses when; nothing
//! here reads one, nothing allocates on their account, and every quantity they
//! can drive is bounded by a constant of this file. The terminating domain
//! chooses every word of the answer: `wire::relay` refuses a reply that is not
//! this item's, one whose status or operation is outside its set, one answering
//! a different question, one claiming more bytes than the region holds, and one
//! whose closed word is neither of its two values. What survives that is a byte
//! count and a run of bytes handed to a transport unread.
//!
//! # The trust boundary is this module, and nothing here understands the bytes
//!
//! This domain **carries** ciphertext and **decides nothing about it**. It never
//! parses a record, never judges a handshake, and never sees a plaintext: the
//! whole of what it does is take what arrived, hand it over, and put back what
//! comes out. That is the reason the split exists — the domain that runs a TLS
//! implementation over an unauthenticated peer's bytes holds no device, no pool
//! and no dataplane ring, and the domain that owns the network holds no key.
//!
//! # One item in flight, which is the ABI's rule and not this module's
//!
//! `wire::RelayRequester` refuses a second request while one is outstanding, so
//! a pass here issues **at most one** and comes back. The far end is at the same
//! priority and is not scheduled while this domain runs, so an answer never
//! arrives inside the pass that asked for it: a pass writes its direction,
//! reports that a wakeup is owed, and returns to the event loop.
//!
//! # Why a quiet session does not ping-pong
//!
//! `RelayOperation::Poll` is how the terminating end gets to speak without
//! having been handed anything, and a pass that issued one on every wakeup would
//! answer its own answer forever: each reply wakes this domain, which polls
//! again, which wakes the far end. So **at most one `Poll` stands between two
//! events** — a delivery, an answer carrying records, a close. A session with
//! nothing happening in it costs one round and then silence, and the next thing
//! the peer sends starts it again.
//!
//! # Every bound is first-party
//!
//! A far end that never answers is [`ANSWER_TIMEOUT`] and then a refusal, on the
//! configuration channel's terms: without it one unanswered item would be the
//! last onboarding session this domain ever carried. A far end that answers with
//! nonsense is refused by the ABI and ends the session here. And a session that
//! failed is closed at the far end **once** — a second attempt after a fault
//! would be a loop against a domain that is already answering rubbish.

use lfw_clock::{Duration, Monotonic};
use lfw_ip_endpoint::{ConnectionId, onboard::Ended};
use lfw_log::{OnboardEnd, RefusalDetail};
pub use wire::{Acknowledged, Half};
use wire::{
    DownloadSink, MAX_RELAY_PAYLOAD, PendingRelay, RelayDemand, RelayEnding, RelayFault,
    RelayOperation, RelayPoll, RelayRefusal, RelayReply, RelayRequest, RelayRequester,
    RelayResponder,
};

use crate::endpoint::EndpointStage;

/// The room the onboarding stream keeps for what arrives, and the payload one
/// item may carry, held to each other where both are visible.
///
/// A stream that could hold more than one item carries would need this module
/// to split a run across two handovers and the far end to know that it had
/// been split; a stream that held less would waste the region. Neither crate
/// depends on the other's number, so this is the one place that can hold them
/// equal.
const _: () = {
    assert!(lfw_ip_endpoint::onboard::INBOUND_CAPACITY <= MAX_RELAY_PAYLOAD);
    assert!(MAX_RELAY_PAYLOAD > 0);
};

/// How long the terminating domain may take to answer one item before it is
/// given up on and the session ended.
///
/// The configuration channel's constant and its reasoning: the slot for an
/// outstanding item is single, so one item nobody answers would otherwise be
/// the last onboarding session this domain carried. Generous, because the
/// answer crosses a scheduling boundary and a handshake step may involve real
/// cryptography at the other end — and finite, because a peer holding a
/// connection open against a domain that has stopped answering is a peer this
/// node has to be able to let go of.
pub const ANSWER_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Why an onboarding session was ended by this appliance rather than by either
/// end of it.
///
/// Every variant is a **distinct thing to go and look at**, and each is given
/// its own console token by the protection domain that emits it: a single token
/// covering several of these would send an operator after the wrong domain,
/// which is the whole reason the list is this long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayFailure {
    /// The terminating end refused the item, saying why. Its own refusal
    /// vocabulary travels whole rather than being folded: `AlreadyOpen` is this
    /// end having asked for a second session, `NoConnection` is it having asked
    /// about one that was never opened, and `SessionFailed` is the far end
    /// giving up on the protocol — three different places to look.
    Refused(RelayRefusal),
    /// The reply could not be believed. The ABI's own fault vocabulary, whole
    /// for `Refused`'s reason.
    Faulted(RelayFault),
    /// Nothing answered within [`ANSWER_TIMEOUT`]. The far end is wedged,
    /// faulted, or was never woken.
    Unanswered,
    /// The window was taken while this end tried to issue an item. **This
    /// appliance's own defect**: a pass claims the answer before it asks, so
    /// this is reachable only if that order were broken, and it is reported
    /// rather than asserted because no panic is admissible on a path a peer
    /// paces.
    Busy,
    /// The records the terminating end answered with outgrew the room the
    /// stream had for what goes on the wire, so the session cannot be carried
    /// on without a hole in the middle of it. **Ours** rather than the peer's.
    ///
    /// A wire merely full is not this: what reaches here outgrew a half's one
    /// buffer, or is a far end answering past what it was offered.
    AnswerTooLong { refused: usize, room: usize },
}

/// What one onboarding session carried, for the domain that reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayReport {
    /// Items the two ends exchanged over the relay for this session.
    pub relayed: u64,
    /// Bytes taken off the network and handed over.
    pub received: u64,
    /// Bytes taken back and put on the network.
    pub sent: u64,
    /// Which end finished it.
    pub ended: OnboardEnd,
    /// Why this appliance ended it, where it did.
    pub failure: Option<RelayFailure>,
}

/// What one pass did, as the two things its caller must act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RelayPass {
    /// An item was written into the region, so the terminating domain owes a
    /// wakeup. Reported rather than signalled here, on the configuration
    /// channel's terms: the capability belongs to the protection domain.
    pub notify: bool,
    /// A session finished and owes the console its account.
    pub report: Option<RelayReport>,
    /// The protocol behind the terminating end agreed a greeting with the peer
    /// **on this pass**, which is the one event that starts the redial schedule
    /// afresh. An edge and not the latch: a level would reset the schedule on
    /// every pass of a healthy channel, which is the same thing said many times
    /// and one more thing for a caller to remember not to act on twice.
    pub agreed: bool,
}

/// One session's identity: which [`Half`] it is on, and which connection of that
/// half.
///
/// The half is part of the identity rather than a parameter beside it, which is
/// what makes carrying one into the other unrepresentable: the two transports
/// number their connections independently, so comparing connection ids alone
/// would read a channel that opened as the onboarding session that closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelaySession {
    pub half: Half,
    pub connection: ConnectionId,
}

/// The live half of an endpoint, as this module needs it.
///
/// A trait rather than the concrete stage on the configuration channel's terms:
/// driving a real endpoint to a session with bytes in it is a handshake and
/// several frames away there, and one call away against a fake.
pub trait Relayed {
    /// The session running now, or `None` where there is none.
    fn session(&self) -> Option<RelaySession>;
    /// Bytes the peer sent that have not been handed over.
    fn received(&self) -> &[u8];
    /// Drop the first `bytes`, which have been handed over.
    fn consumed(&mut self, bytes: usize);
    /// Whether the peer has closed its half.
    fn peer_closed(&self) -> bool;
    /// Put `bytes` on the wire, answering how many there was room for.
    fn push(&mut self, bytes: &[u8]) -> usize;
    /// Whether the wire has room for a whole answer — as *offered* — so an item
    /// may be issued at all: the answer is claimed out of the region whether or
    /// not the wire can take it, and a run taken and not placed is a hole in a
    /// stream. A half whose room comes back on an acknowledgement answers `false`
    /// while it is full; one holding a single bounded exchange has none to wait
    /// for and answers `true`.
    fn room_for_an_answer(&self) -> bool;
    /// End the session running on `session`, answering whether that was still
    /// the session this stream held.
    fn end_session(&mut self, session: RelaySession) -> bool;
    /// How the last session ended, taken once.
    fn take_ending(&mut self) -> Option<Ended>;
    /// How the session running now would end if it ended at this instant.
    fn ending(&self) -> Ended;
}

impl Relayed for EndpointStage<'_> {
    fn session(&self) -> Option<RelaySession> {
        Self::onboard_session(self).map(|connection| RelaySession {
            half: Half::Onboarding,
            connection,
        })
    }

    fn received(&self) -> &[u8] {
        Self::onboard_received(self)
    }

    fn consumed(&mut self, bytes: usize) {
        Self::onboard_consumed(self, bytes);
    }

    fn peer_closed(&self) -> bool {
        Self::onboard_peer_closed(self)
    }

    fn push(&mut self, bytes: &[u8]) -> usize {
        Self::onboard_push(self, bytes)
    }

    /// Always: this stream holds its answers until the session is over, so there
    /// is no release for a wait to end on.
    fn room_for_an_answer(&self) -> bool {
        true
    }

    fn end_session(&mut self, session: RelaySession) -> bool {
        session.half == Half::Onboarding && Self::onboard_end_session(self, session.connection)
    }

    fn take_ending(&mut self) -> Option<Ended> {
        Self::take_onboard_ending(self)
    }

    fn ending(&self) -> Ended {
        Self::onboard_ending(self)
    }
}

/// The **channel** half of an endpoint, as the same relay needs it.
///
/// A wrapper rather than a second set of methods on one impl, because one type
/// implements one trait once — and the two halves are the same shape seen from
/// opposite ends of a connection. What is inside is a borrow and nothing else:
/// it is constructed for one pass, so it can hold no state and there is none it
/// would want.
///
/// Only the domain that owns the management port constructs one, and it
/// constructs exactly one of the two per pass, from what the store domain has
/// published: an appliance told nowhere to dial has no channel, and one that has
/// been told has no onboarding surface left.
pub struct ChannelStream<'stage, 'ring>(pub &'stage mut EndpointStage<'ring>);

impl Relayed for ChannelStream<'_, '_> {
    fn session(&self) -> Option<RelaySession> {
        self.0.dial_connection().map(|connection| RelaySession {
            half: Half::Channel,
            connection,
        })
    }

    fn received(&self) -> &[u8] {
        self.0.dial_received()
    }

    fn consumed(&mut self, bytes: usize) {
        self.0.dial_consumed(bytes);
    }

    fn peer_closed(&self) -> bool {
        self.0.dial_peer_closed()
    }

    fn push(&mut self, bytes: &[u8]) -> usize {
        self.0.dial_push(bytes)
    }

    /// **The half the question is for.** Its window slides, so a full one is a
    /// pass to come back on rather than a session to end — which is what lets
    /// this half carry more bytes than it holds at once.
    fn room_for_an_answer(&self) -> bool {
        self.0.dial_send_room() >= ANSWER_ROOM
    }

    fn end_session(&mut self, session: RelaySession) -> bool {
        session.half == Half::Channel && self.0.end_dial_session_on(session.connection)
    }

    /// Nothing is ever taken here, and that is the difference between the two
    /// halves rather than a gap in this one.
    ///
    /// The onboarding stream is the transport's own and it forgets a connection
    /// a frame or two after the close goes out, so an ending has to be kept for
    /// the pass that asks. The channel's session is the *dialling schedule's*,
    /// and that schedule holds it until this relay has closed its account — so
    /// the live ending is answerable for as long as anybody asks for it, and a
    /// second copy kept here would be a second answer to drift from it.
    fn take_ending(&mut self) -> Option<Ended> {
        None
    }

    fn ending(&self) -> Ended {
        self.0.dial_stream_ending()
    }
}

/// Whether the terminating end holds a session for this connection.
///
/// Two states and not three: an item in flight is [`Relay::outstanding`], and
/// folding "asking" into this would make the two the same fact recorded twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Far {
    /// No session at the far end: nothing has been opened, or what was is over.
    Closed,
    /// A session is open there, and this end owes it a close.
    Open,
}

/// What one look at the reply found, with every borrow of the region already
/// given up: a length, a length, and a flag.
enum Claimed {
    Outstanding(PendingRelay),
    Answered {
        offered: usize,
        kept: usize,
        closed: bool,
        agreed: bool,
        acked: Acknowledged,
    },
    Refused(RelayRefusal),
    Faulted(RelayFault),
}

/// One item issued and not yet answered, with the instant it stops being worth
/// waiting for.
struct Outstanding {
    pending: PendingRelay,
    deadline: Option<Monotonic>,
}

/// The network end of the relay: the channel handle, the session it is carrying,
/// and what that session has cost so far.
pub struct Relay<'chan> {
    requester: RelayRequester<'chan>,
    outstanding: Option<Outstanding>,
    far: Far,
    /// The session this end is carrying, so a connection replaced between two
    /// passes is noticed rather than carried on as though it were the same one —
    /// and so a session that has been finished is not opened again on the
    /// connection it was finished on. It carries which half it is on, which is
    /// what makes the onboarding connection closing and the channel opening two
    /// sessions rather than one that changed underneath the account.
    carried: Option<RelaySession>,
    /// A `Poll` has been issued and nothing has happened since. See the module
    /// header on why this is what keeps a quiet session from answering itself
    /// forever.
    polled: bool,
    /// The protocol behind the terminating end has agreed a greeting with the
    /// peer at some point in this session. Latched from the answers that carry
    /// it, and the **one** thing the redial schedule may be started afresh on:
    /// a peer that accepts a connection and closes it must not be able to
    /// shorten the wait, and a transport that came up is exactly that peer.
    agreed: bool,
    /// A close issued *because* the session failed. It is attempted once: a
    /// second against a far end that is already answering rubbish is a loop.
    closing_after_failure: bool,
    /// The transport's own account of how this session ended, kept from the pass
    /// that first needed it. The stream answers it **once**, and the close this
    /// end composes needs it before the report does — so a pass that read it and
    /// did not keep it would leave the next session's report carrying this one's
    /// ending.
    ended: Option<Ended>,
    relayed: u64,
    received: u64,
    sent: u64,
    failure: Option<RelayFailure>,
    /// Where an answer's records are copied before the stream takes them. A
    /// field because it is one maximal record and a protection domain's stack is
    /// not where that belongs.
    records: [u8; MAX_RELAY_PAYLOAD],
}

impl<'chan> Relay<'chan> {
    /// Take the asking side of the channel — once per domain; a second would
    /// restart at sequence zero and reuse numbers the first has outstanding
    /// (`wire::RelayRequest::requester`).
    #[must_use]
    pub const fn attach(request: &'chan RelayRequest, reply: &'chan RelayReply) -> Self {
        Self {
            requester: request.requester(reply),
            outstanding: None,
            far: Far::Closed,
            carried: None,
            agreed: false,
            polled: false,
            closing_after_failure: false,
            ended: None,
            relayed: 0,
            received: 0,
            sent: 0,
            failure: None,
            records: [0; MAX_RELAY_PAYLOAD],
        }
    }

    /// Replies this end refused, which is the terminating domain misbehaving.
    #[must_use]
    pub const fn faults(&self) -> u32 {
        self.requester.faults()
    }

    /// Whether an item is in flight, which is the whole of this channel's
    /// window.
    #[must_use]
    pub const fn outstanding(&self) -> bool {
        self.outstanding.is_some()
    }

    /// The half whose session's account is still open here, and `None` between
    /// sessions. Two callers read the two halves of one fact.
    ///
    /// *Whether* there is one is the dialled channel's schedule, and the reason is
    /// identity rather than tidiness: a transport numbers its connections
    /// independently of this relay's life, so an attempt opened before the last
    /// one's account was closed could carry the same connection id — and the relay
    /// would read the new session as the old one continuing. The schedule holds
    /// off until this answers `None`, bounded by [`ANSWER_TIMEOUT`] whatever the
    /// far end does. *Which* pins the stream a pass may hand to [`Self::poll`], so
    /// a half chosen afresh cannot offer an outstanding answer to the other one.
    #[must_use]
    pub const fn carrying(&self) -> Option<Half> {
        match self.carried {
            Some(session) => Some(session.half),
            None => None,
        }
    }

    /// Whether ring bytes are worth reading for this relay to ship: the session
    /// running now is the dialled channel, and a greeting has been agreed on it.
    ///
    /// Both halves of the condition the shipping arm applies, answered where
    /// they are known. The reader that fills the shipment buffer asks rather
    /// than guessing, a guess being a read of the medium for a channel that is
    /// not there.
    #[must_use]
    pub const fn shipping(&self) -> bool {
        matches!(self.carrying(), Some(Half::Channel)) && self.agreed
    }

    /// One bounded pass: claim the answer if one has arrived, then issue at most
    /// one item.
    ///
    /// Never blocks and never spins. A pass with nothing to do returns a
    /// [`RelayPass`] that asks for nothing, which is the whole of the contract
    /// with the event loop.
    pub fn poll(
        &mut self,
        now: Option<Monotonic>,
        stream: &mut impl Relayed,
        upstream: &mut impl Upstream,
    ) -> RelayPass {
        let agreed = self.claim(now, stream, upstream);
        let (notify, report) = self.issue(now, stream, upstream);
        RelayPass {
            notify,
            report,
            agreed,
        }
    }

    /// Look **once** for the answer to the outstanding item, giving up on one
    /// that has outlived [`ANSWER_TIMEOUT`].
    ///
    /// Answers whether this claim is the one on which the protocol above first
    /// agreed a greeting.
    fn claim(
        &mut self,
        now: Option<Monotonic>,
        stream: &mut impl Relayed,
        upstream: &mut impl Upstream,
    ) -> bool {
        let Some(Outstanding { pending, deadline }) = self.outstanding.take() else {
            return false;
        };
        let asked = pending.operation();
        // The answer is turned into plain values inside this block, because the
        // records it carries borrow the region this end reads through and
        // nothing else about this session can be touched while they do. The
        // stream is not borrowed from here, so the copy onto the wire happens
        // where the bytes are still in hand.
        let claimed = {
            let Self {
                requester, records, ..
            } = self;
            match requester.poll(pending, records) {
                RelayPoll::Outstanding(pending) => Claimed::Outstanding(pending),
                RelayPoll::Answered {
                    records,
                    closed,
                    agreed,
                    answered: _,
                    acked,
                } => Claimed::Answered {
                    offered: records.len(),
                    kept: stream.push(records),
                    closed,
                    agreed,
                    acked,
                },
                RelayPoll::Refused(reason) => Claimed::Refused(reason),
                RelayPoll::Faulted(fault) => Claimed::Faulted(fault),
            }
        };
        match claimed {
            Claimed::Outstanding(pending) => {
                if !expired(now, deadline) {
                    self.outstanding = Some(Outstanding { pending, deadline });
                    return false;
                }
                // Given up on rather than re-parked, which frees this end's one
                // slot: `wire::RelayRequester::abandon` is what makes that a
                // fact rather than a comment, and dropping the handle instead
                // would leave the window taken for the life of the domain and
                // refuse every later session for it. A reply that lands
                // afterwards answers a sequence no item is held against, and
                // `RelayRequester::poll` reads such a reply as no answer at all
                // — so a late answer cannot be mistaken for the next item's.
                self.requester.abandon(pending);
                self.far = Far::Closed;
                self.fail(stream, RelayFailure::Unanswered);
                false
            }
            Claimed::Answered {
                offered,
                kept,
                closed,
                agreed,
                acked,
            } => {
                self.relayed = self.relayed.saturating_add(1);
                self.sent = self.sent.saturating_add(kept as u64);
                if offered > 0 {
                    self.polled = false;
                }
                // The edge, taken before anything below can end the session: a
                // greeting agreed on the very answer that also carried the last
                // bytes of a session is still a greeting agreed, and the
                // schedule is owed its reset for it.
                let first = agreed && !self.agreed;
                self.agreed |= agreed;
                // The resume point **before** the acknowledgement, and only on
                // the pass that first agreed.
                if first {
                    upstream.resume_from(acked);
                }
                upstream.acknowledged(acked);
                if kept < offered {
                    self.far = Far::Closed;
                    // The room there was is exactly what was kept, `Relayed::push`
                    // taking every byte it has room for.
                    self.fail(
                        stream,
                        RelayFailure::AnswerTooLong {
                            refused: offered.saturating_sub(kept),
                            room: kept,
                        },
                    );
                    return first;
                }
                match asked {
                    // The far end holds a session from here on, and owes one
                    // answer to every item until it is closed.
                    RelayOperation::Open(_) => self.far = Far::Open,
                    RelayOperation::Close(_) => self.far = Far::Closed,
                    // The shipment was answered, so the bytes on it reached the
                    // end that composes the frame and the reader may move past
                    // them. Here and nowhere earlier: an item that faulted or
                    // was never answered leaves the cursor where it was.
                    RelayOperation::Ship(_) => upstream.shipped(),
                    RelayOperation::Deliver | RelayOperation::Poll => {}
                }
                if closed {
                    self.far = Far::Closed;
                    self.end_carried(stream);
                }
                first
            }
            Claimed::Refused(reason) => {
                // Every refusal publishes a closed session, so the far end holds
                // nothing to close.
                self.far = Far::Closed;
                self.fail(stream, RelayFailure::Refused(reason));
                false
            }
            Claimed::Faulted(fault) => {
                // The far end may or may not still hold a session: a reply this
                // end cannot read says nothing about what the other end did. So
                // one close is attempted, and the session ends here whatever
                // that close answers — a second attempt against an end that is
                // already answering rubbish is a loop.
                self.fail(stream, RelayFailure::Faulted(fault));
                if self.far == Far::Open && !self.closing_after_failure {
                    self.closing_after_failure = true;
                    return false;
                }
                self.far = Far::Closed;
                false
            }
        }
    }

    /// Issue whatever this session now needs, and answer whether a wakeup is
    /// owed and whether a session's account came due.
    ///
    /// **The one place a session is reported**, and the moment is the one thing
    /// that makes the account complete: a session is over when the transport
    /// has stopped holding the connection it ran on, and that is when the stream
    /// knows which end finished it. Reporting earlier — when a close was
    /// answered, or when a reply could not be believed — would name the failure
    /// correctly and the ending not at all.
    fn issue(
        &mut self,
        now: Option<Monotonic>,
        stream: &mut impl Relayed,
        upstream: &mut impl Upstream,
    ) -> (bool, Option<RelayReport>) {
        if self.outstanding.is_some() {
            return (false, None);
        }
        let session = stream.session();
        let Some(carried) = self.carried else {
            // Nothing is being carried: a connection is a session to open, and
            // no connection is nothing to do.
            let Some(session) = session else {
                return (false, None);
            };
            // The half is the stream's own, so one value reaches both ends.
            self.carried = Some(session);
            return (
                self.ask(stream, now, RelayOperation::Open(session.half), &[]),
                None,
            );
        };
        if session != Some(carried) {
            // The connection this session ran on is gone or has been replaced.
            // The far end is told before the account is made, so the next
            // session's `Open` is an open rather than an `AlreadyOpen`.
            if self.far == Far::Open {
                return (self.close(stream, now), None);
            }
            return (false, self.finish(stream));
        }
        if self.failure.is_some() {
            // The session has failed and its connection is already being taken
            // down. What is left is to give the far end its close, once.
            if self.far == Far::Open {
                return (self.close(stream, now), None);
            }
            return (false, None);
        }
        if self.far == Far::Closed {
            // Both ends are finished with the session and the connection is
            // still closing. Nothing is owed until it is gone.
            return (false, None);
        }
        // Asked once, so the two decisions below rest on one reading. A full wire
        // holds the item back rather than ending anything; the close is outside
        // it, carrying no records and having to be possible however full it is.
        let room = stream.room_for_an_answer();
        let handed = {
            let waiting = stream.received();
            let len = waiting.len().min(MAX_RELAY_PAYLOAD);
            match waiting.get(..len) {
                Some(bytes) if room && !bytes.is_empty() => {
                    let issued = self.requester.request(RelayOperation::Deliver, bytes);
                    Some((issued, len))
                }
                _ => None,
            }
        };
        if let Some((issued, len)) = handed {
            let Ok(pending) = issued else {
                self.refuse_window(stream);
                return (false, None);
            };
            self.park(now, pending);
            stream.consumed(len);
            self.received = self.received.saturating_add(len as u64);
            self.polled = false;
            return (true, None);
        }
        if stream.peer_closed() {
            return (self.close(stream, now), None);
        }
        // **After the delivery and never before it.** What arrives on the wire
        // carries the acknowledgements this appliance's cursors move on, so an
        // end that shipped whenever it had bytes would never hear how far the
        // far end had got. The window is one item, so priority here is the whole
        // of the fairness there is. Only on the dialled half and only once a
        // greeting is agreed: the onboarding half has no upstream, and a frame
        // in front of the greeting is one the far end refuses.
        if carried.half == Half::Channel
            && self.agreed
            && room
            && let Some((recording, position, bytes)) = upstream.waiting()
            && !bytes.is_empty()
        {
            let Ok(pending) = self.requester.ship(recording, position, bytes) else {
                self.refuse_window(stream);
                return (false, None);
            };
            self.park(now, pending);
            self.polled = false;
            return (true, None);
        }
        if self.polled || !room {
            return (false, None);
        }
        self.polled = true;
        (self.ask(stream, now, RelayOperation::Poll, &[]), None)
    }

    /// Write one item into the region, answering whether it went.
    ///
    /// A refused window is this appliance's own defect — a pass claims before it
    /// asks — and is recorded as a failure rather than asserted, no panic being
    /// admissible on a path a peer paces.
    fn ask(
        &mut self,
        stream: &mut impl Relayed,
        now: Option<Monotonic>,
        operation: RelayOperation,
        payload: &[u8],
    ) -> bool {
        match self.requester.request(operation, payload) {
            Ok(pending) => {
                self.park(now, pending);
                true
            }
            Err(_) => {
                self.refuse_window(stream);
                false
            }
        }
    }

    /// Hold the item and the instant it stops being worth waiting for.
    fn park(&mut self, now: Option<Monotonic>, pending: PendingRelay) {
        self.outstanding = Some(Outstanding {
            pending,
            deadline: now.map(|now| now.saturating_add(ANSWER_TIMEOUT)),
        });
    }

    /// The window was taken while this end tried to issue an item. The session
    /// ends here and the far end is given up on rather than closed: a close
    /// would need the very window that was refused.
    fn refuse_window(&mut self, stream: &mut impl Relayed) {
        self.far = Far::Closed;
        self.fail(stream, RelayFailure::Busy);
    }

    /// Record a failure and take the connection down with it, keeping the first:
    /// what went wrong first is what an operator has to look at, and a later
    /// consequence of it would displace the cause.
    fn fail(&mut self, stream: &mut impl Relayed, failure: RelayFailure) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
        self.end_carried(stream);
    }

    /// End the session this end is carrying, and **only** that one.
    ///
    /// The connection is named rather than implied, which is the whole of it: a
    /// close belongs to the session it was decided for, and a peer that resets
    /// and reconnects between two passes has a different one running by the time
    /// the close is acted on. Naming it costs a comparison and makes ending the
    /// wrong session unrepresentable — `Relayed::end_session` refuses a name
    /// it does not hold — where an unnamed close hands a peer the new session as
    /// the price of the old one.
    ///
    /// Nothing carried is nothing to end, which is the state before the first
    /// open and after the account is closed.
    fn end_carried(&self, stream: &mut impl Relayed) {
        if let Some(carried) = self.carried {
            stream.end_session(carried);
        }
    }

    /// How this session ended, in the vocabulary both domains report it in.
    ///
    /// **One source for the close and for the account**, which is what makes the
    /// two domains' records agree: the close carries this and the far end reports
    /// what it was told, so a session the transport forgot is not read there as
    /// one the peer closed.
    ///
    /// The stream answers its ending once, so it is taken on every call and kept:
    /// an ending left in the stream would be read as the next session's. Where
    /// the transport still holds the connection there is nothing to take yet and
    /// the live ending is what a close carries — a peer that hung up has already
    /// fixed it, and a session with neither end finished has nothing to close.
    fn ending(&mut self, stream: &mut impl Relayed) -> OnboardEnd {
        if let Some(taken) = stream.take_ending() {
            self.ended = Some(taken);
        }
        // A session this appliance ended is its own ending whatever the transport
        // made of the connection afterwards: what an operator goes and looks at
        // is the failure, whose cause travels on the record beside this one.
        if self.failure.is_some() {
            return OnboardEnd::Refused;
        }
        match self.ended.unwrap_or_else(|| stream.ending()) {
            Ended::ByPeer => OnboardEnd::Peer,
            Ended::ByConsumer => OnboardEnd::Consumer,
            Ended::Forgotten => OnboardEnd::Forgotten,
        }
    }

    /// Write the close for this session, carrying how it ended.
    fn close(&mut self, stream: &mut impl Relayed, now: Option<Monotonic>) -> bool {
        let ending = relay_ending(self.ending(stream));
        self.ask(stream, now, RelayOperation::Close(ending), &[])
    }

    /// Close the session's account, if there is one to close.
    fn finish(&mut self, stream: &mut impl Relayed) -> Option<RelayReport> {
        self.carried?;
        let ended = self.ending(stream);
        let report = RelayReport {
            relayed: self.relayed,
            received: self.received,
            sent: self.sent,
            ended,
            failure: self.failure,
        };
        self.carried = None;
        self.far = Far::Closed;
        self.agreed = false;
        self.polled = false;
        self.closing_after_failure = false;
        self.ended = None;
        self.relayed = 0;
        self.received = 0;
        self.sent = 0;
        self.failure = None;
        Some(report)
    }
}

/// Demands the terminating end takes per wakeup.
///
/// The channel's window is one item, so **at most one demand can exist per
/// wakeup** and the second turn is what proves there is not another rather than
/// work anybody expects to do. Two rather than one because a notification is a
/// flag rather than a queue: two writes that coalesce into one wakeup must not
/// leave an item nobody comes back for, and a take that finds nothing costs one
/// read of a word the domain already maps.
pub const DEMANDS_PER_WAKEUP: usize = 2;

/// The room one answer may carry, which is the room the wire has for it.
///
/// The relay's own item is wider — it is sized for a maximal record in the
/// other direction — but an answer past what the onboarding stream keeps for
/// what goes out is one the network end refuses and the session dies of. So the
/// protocol is offered exactly what can actually leave, and whatever it has
/// left over goes on the turn after: a bounded answer that continues is the
/// difference between a slow flight and a lost session.
///
/// It is the stream's whole room and not the room free in it, and the ABI needs
/// no word for how much is free: whether there is enough is read by the
/// **network** end off the stream it holds ([`Relayed::room_for_an_answer`]), and
/// an item is not issued until a whole answer could leave. So a full wire costs a
/// session that can drain one a pass rather than the session, and
/// [`RelayFailure::AnswerTooLong`] is what is left — typed, confined to one.
const ANSWER_ROOM: usize = lfw_ip_endpoint::onboard::OUTBOUND_CAPACITY;

const _: () = {
    assert!(ANSWER_ROOM <= MAX_RELAY_PAYLOAD);
    // The dialled window must hold a whole answer or the channel issues nothing.
    // Held here, this being where both crates' constants are visible.
    assert!(ANSWER_ROOM <= lfw_ip_endpoint::outbound::SEND_CAPACITY);
};

/// Bytes a TLS 1.3 record adds to the plaintext inside it: five of header, one
/// of inner content type, sixteen of tag — a constant of the record format
/// rather than of any implementation, which is why it can be counted with here.
const TLS_RECORD_OVERHEAD: usize = 5 + 1 + 16;

/// Bytes of channel-frame header, and of ring position, in front of an upstream
/// frame's ring bytes. Restated rather than taken from the framing crate, which
/// this one does not depend on and must not: every protection domain links this
/// crate, the dataplane ones included. What keeps the numbers together is that
/// the composing domain refuses a shipment it cannot encode.
const CHANNEL_HEADER_LEN: usize = 8;
const RING_POSITION_LEN: usize = 8;

/// Ring bytes one [`RelayOperation::Ship`] may carry.
///
/// **The bound is the answer buffer, not the item.** An item is wide enough for
/// a maximal record either way, but the answer is written into the single
/// [`ANSWER_ROOM`] buffer the terminating end holds — so the arithmetic runs
/// backwards from there: one whole frame's ciphertext must fit it.
///
/// Bounding it here rather than streaming a segment-sized frame across many
/// round trips removes partial-frame state from every domain: a frame is
/// composed only when the whole of it fits, so no half of one is ever on a
/// length-prefixed stream. What makes a small frame whole information rather
/// than a fragment is the ring position it carries.
pub const SHIPPED_RING_BYTES: usize =
    ANSWER_ROOM - (TLS_RECORD_OVERHEAD + CHANNEL_HEADER_LEN + RING_POSITION_LEN);

const _: () = {
    // The arithmetic above, read back the other way.
    assert!(
        TLS_RECORD_OVERHEAD + CHANNEL_HEADER_LEN + RING_POSITION_LEN + SHIPPED_RING_BYTES
            == ANSWER_ROOM
    );
    assert!(SHIPPED_RING_BYTES <= MAX_RELAY_PAYLOAD);
    assert!(SHIPPED_RING_BYTES > 0);
};

/// Where the ring bytes waiting to go up the channel come from.
///
/// A trait rather than the concrete reader for [`Terminator`]'s reason: what
/// holds those bytes is the download channel's other half, which this crate is
/// not where it lives. Nothing here reads one — a shipment is a length and a
/// position this crate copies into a region and counts.
pub trait Upstream {
    /// Which recording, the absolute ring position, and the bytes themselves.
    fn waiting(&self) -> Option<(DownloadSink, u64, &[u8])>;

    /// Where the far end says it will be sent from, taken **once** per session
    /// off the greeting that opened it. A resume point and not an
    /// acknowledgement: it may name a position behind where this appliance last
    /// shipped — a server asking again for what it never made durable, harmless
    /// because every frame carries its own position — so nothing bounds it here.
    fn resume_from(&mut self, acked: Acknowledged);

    /// How far the far end says it has durably taken each recording, as a level
    /// read off every answer. Bounded by what this appliance sent, never
    /// **backward**.
    fn acknowledged(&mut self, acked: Acknowledged);

    /// The far end answered the shipment those bytes were on, so the reader may
    /// move past them.
    ///
    /// Called on the **answer** and never on the issue, which keeps a hole out
    /// of the shipped stream: an item refused, faulted or never answered leaves
    /// the cursor where it was and the next session ships that position again.
    /// A frame can cross twice and never be skipped.
    fn shipped(&mut self);
}

/// What one turn of the protocol left for the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Answered {
    /// Bytes written into the front of the buffer the turn was given.
    pub sent: usize,
    /// Whether the protocol is finished with the session. The relay publishes
    /// it as a closed session, which is what takes the connection down at the
    /// end that owns it.
    pub finished: bool,
    /// Whether the protocol has **agreed a greeting** with the peer at some
    /// point in this session. A level rather than an edge: the relay publishes
    /// it on every answer after the first that sets it, so a wakeup that
    /// coalesced with another cannot lose the fact.
    ///
    /// It is the one thing the network end may start its redial schedule afresh
    /// on, which is why it is the protocol's word and not the transport's: a
    /// server that accepts a connection and closes it is exactly the peer a
    /// reset on a completed handshake would reward.
    pub agreed: bool,
}

/// The protocol that terminates an onboarding session.
///
/// A trait and not a type, and the reason is the dependency rather than
/// taste: what terminates the session is a TLS server over an allocator and a
/// private key, and this crate — which every protection domain links, the
/// dataplane ones included — holds neither and must not acquire the library
/// that needs them. So the shape is stated here and the implementation is
/// supplied by the one domain that has both.
///
/// # Adversary
///
/// Through the relay behind it, an **unauthenticated management-plane
/// attacker**: every byte handed to [`Self::advance`] is that peer's, and so is
/// the pacing. This crate reads none of them and bounds every quantity it hands
/// on.
pub trait Terminator {
    /// Begin a session on `half`, discarding whatever the last one left. The half
    /// is a parameter and never worked out here, for the reason [`Half`] carries.
    fn opened(&mut self, half: Half);

    /// Take what the peer sent — empty, where the network end is only asking
    /// whether there is anything to send — and write what goes back into
    /// `answer`.
    fn advance(&mut self, received: &[u8], answer: &mut [u8]) -> Answered;

    /// Compose a frame carrying `bytes` of `recording` from ring position
    /// `position`, and write whatever the session then owes the wire into
    /// `answer`.
    ///
    /// **The semantic fields, and the framing is this end's.** Giving the
    /// network end a vocabulary for a frame would put the framing's own refusals
    /// on the console under the name of the far end of the wire, which is the
    /// wrong end of it for anyone reading a node that has no shell.
    ///
    /// A shipment this end cannot compose whole **ends the session**, rather
    /// than being dropped: the network end moves its cursor on the answer, so a
    /// shipment that vanished here would be a hole nothing can notice.
    fn ship(
        &mut self,
        recording: DownloadSink,
        position: u64,
        bytes: &[u8],
        answer: &mut [u8],
    ) -> Answered;

    /// Whether the protocol has agreed a greeting with the peer in the session
    /// it holds now.
    ///
    /// Asked rather than remembered by this crate, so the fact has one home: the
    /// protocol is the only thing that can know it, and a copy kept here would be
    /// a second answer to drift from the first. Answered `false` by a protocol
    /// that has no greeting to agree, which is what the onboarding server is.
    fn agreed(&self) -> bool {
        false
    }

    /// How far the peer says it has durably taken each recording, as **this**
    /// end judged the claim. Asked rather than remembered here for
    /// [`Self::agreed`]'s reason: only the end composing every frame knows it.
    fn acknowledged(&self) -> Acknowledged {
        Acknowledged::NONE
    }

    /// The session is over, however it ended.
    fn closed(&mut self);
}

/// What one onboarding session carried, as the **terminating** end saw it.
///
/// Its own type rather than [`RelayReport`]: that one carries the network end's
/// failure vocabulary, and this end has no window, no deadline and no transport
/// to fail at. What the two share is the four facts a console record states, so
/// the two accounts of one session are compared field by field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminatedSession {
    /// Items this end answered for the session.
    pub relayed: u64,
    /// Bytes taken off the relay for it.
    pub received: u64,
    /// Bytes answered with and put back on the relay.
    pub sent: u64,
    /// How it ended. Told rather than inferred wherever the network end knew:
    /// this end cannot see the wire, so a session the transport forgot and one
    /// the peer closed are indistinguishable from here unless the close says
    /// which.
    pub ended: OnboardEnd,
}

/// What answering one item left the console owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TerminatingPass {
    /// The refusal this end published, with the numbers its token names. Every
    /// refusal ends the session, so a pass carrying one carries a report too.
    pub refused: Option<(RelayRefusal, RefusalDetail)>,
    /// A session that finished. **At most one**, and that is structural: one
    /// item ends at most one session, an open being the only thing that can end
    /// a session and begin another in the same breath.
    pub report: Option<TerminatedSession>,
}

/// The session the terminating end holds, and what it has carried.
///
/// A value inside an `Option` rather than an `open` flag beside the counts: the
/// two are one fact, and a flag that could disagree with the numbers under it is
/// exactly the disagreement this end is here to not have.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Held {
    relayed: u64,
    received: u64,
    sent: u64,
}

impl Held {
    const fn finished(self, ended: OnboardEnd) -> TerminatedSession {
        TerminatedSession {
            relayed: self.relayed,
            received: self.received,
            sent: self.sent,
            ended,
        }
    }
}

/// The terminating end of the relay: the session it holds, and the answer it
/// owes.
///
/// # Adversary
///
/// A **byzantine neighbour protection domain** — the network end — and behind it
/// the **unauthenticated management-plane attacker** whose bytes it carries.
/// Every word of a demand is the network end's choice and every byte of a
/// payload is the peer's. Nothing here indexes without a bound, nothing here
/// allocates, and every demand is answered exactly once: a demand taken and
/// dropped would leave the network end polling a sequence nothing will publish.
///
/// **Nothing here reads a byte either.** What is handed over is copied out of
/// the shared region, counted, and given to the [`Terminator`] whole; what goes
/// back is whatever that answered with, put on the channel unread. This module
/// owns the session's account and its bounds, and the protocol owns its
/// meaning.
pub struct Terminating<'chan, T> {
    responder: RelayResponder<'chan>,
    terminator: T,
    session: Option<Held>,
    /// Where a delivered payload is copied before it is handed on. A field
    /// because it is one maximal record and a protection domain's stack is not
    /// where that belongs.
    records: [u8; MAX_RELAY_PAYLOAD],
    /// Where the protocol writes its answer, for the same reason.
    answer: [u8; ANSWER_ROOM],
}

impl<'chan, T: Terminator> Terminating<'chan, T> {
    /// Take the answering side of the channel — once per domain, on
    /// [`Relay::attach`]'s terms — and the protocol that will terminate what
    /// crosses it.
    #[must_use]
    pub const fn attach(
        request: &'chan RelayRequest,
        reply: &'chan RelayReply,
        terminator: T,
    ) -> Self {
        Self {
            responder: reply.responder(request),
            terminator,
            session: None,
            records: [0; MAX_RELAY_PAYLOAD],
            answer: [0; ANSWER_ROOM],
        }
    }

    /// The protocol behind this end.
    ///
    /// A protocol has things to say that the relay's own account cannot — how a
    /// handshake ended, and why — and it says them to a console this crate
    /// cannot reach: a sink belongs to the protection domain, and handing one
    /// to every relay would make this module a logger. So the protocol keeps
    /// what it has to say and the domain takes it, which is what this is for.
    pub const fn terminator(&mut self) -> &mut T {
        &mut self.terminator
    }

    /// The outstanding item, if the network end has written one this end has not
    /// answered.
    pub fn take(&mut self) -> Option<RelayDemand> {
        self.responder.take()
    }

    #[must_use]
    pub const fn holds_a_session(&self) -> bool {
        self.session.is_some()
    }

    /// Answer one demand, and say what it left the console owed.
    ///
    /// Total: every operation and every state it can arrive in has an arm, and
    /// every path consumes the demand exactly once.
    pub fn answer(&mut self, demand: RelayDemand) -> TerminatingPass {
        let Some(operation) = demand.operation() else {
            // The word named no operation this end has — a close whose ending
            // could not be read among them. Refused rather than ignored: a
            // network end left waiting cannot tell a refusal from a hang.
            return self.refuse(demand, RelayRefusal::NoSuchOperation, RefusalDetail::None);
        };
        if let RelayOperation::Open(half) = operation {
            // **An open is the beginning of a session and the end of any this
            // end still held.** The network end is the only end that opens one,
            // so its open is the newer fact and whatever this end still believed
            // in is stale by construction — an answer it dropped, a wakeup it
            // never got. Superseding rather than refusing is what keeps the two
            // ends from disagreeing without an exchange to reconcile them, and
            // what it costs is the account of one session rather than every
            // session after it.
            //
            // Forgotten, because that is what happened: neither end of the
            // superseded session ever said it was over.
            let report = self
                .session
                .map(|held| held.finished(OnboardEnd::Forgotten));
            self.session = Some(Held::default());
            self.terminator.opened(half);
            // Nothing goes back with an open: a session that has heard nothing
            // from the peer has nothing to say to it, and nothing has been
            // agreed with an end that has not spoken.
            self.publish(demand, 0, false, false);
            return TerminatingPass {
                refused: None,
                report,
            };
        }
        if self.session.is_none() {
            return self.refuse(
                demand,
                RelayRefusal::NoConnection,
                RefusalDetail::One(u64::from(operation.to_bits())),
            );
        }
        match operation {
            // Handled above; an open cannot reach here. A poll is the protocol's
            // turn to speak without having been handed anything, so it is a turn
            // with nothing delivered rather than an answer of nothing.
            RelayOperation::Open(_) | RelayOperation::Poll => self.turn(demand, 0),
            RelayOperation::Deliver => self.deliver(demand),
            RelayOperation::Ship(recording) => self.ship(demand, recording),
            RelayOperation::Close(ending) => {
                // Answered as closed, which is what makes the network end stop
                // rather than wait for a session this end no longer holds. The
                // ending it was told is what the account says, so a session the
                // transport forgot is not reported here as one the peer closed.
                // Counted before the session is taken, so the item that ended it
                // is in its own account — and so the two domains' `relayed`
                // counts are the same number rather than differing by the close.
                let agreed = self.terminator.agreed();
                self.terminator.closed();
                self.publish(demand, 0, true, agreed);
                TerminatingPass {
                    refused: None,
                    report: self
                        .session
                        .take()
                        .map(|held| held.finished(onboard_end(ending))),
                }
            }
        }
    }

    /// Take a delivered payload, or refuse a length past what one item holds.
    fn deliver(&mut self, demand: RelayDemand) -> TerminatingPass {
        let stated = demand.stated_len();
        let Self {
            responder, records, ..
        } = self;
        // Copied out of the shared region before anything is made of it, and
        // `None` exactly where the stated length is past what a request can hold
        // — which is the one length this end must refuse rather than shorten.
        let Some(taken) = demand.payload(responder, records).map(<[u8]>::len) else {
            return self.refuse(
                demand,
                RelayRefusal::PayloadTooLong,
                RefusalDetail::One(u64::from(stated)),
            );
        };
        if let Some(held) = self.session.as_mut() {
            held.received = held.received.saturating_add(taken as u64);
        }
        self.turn(demand, taken)
    }

    /// Take a shipment's ring bytes and give them to the protocol to frame.
    ///
    /// Bounded by [`SHIPPED_RING_BYTES`] and not merely by what an item holds: a
    /// longer shipment composes a frame whose ciphertext does not fit the one
    /// answer buffer, leaving the remainder inside the record layer — in an
    /// arena a neighbour would then decide how much of. Refused rather than
    /// shortened, on the same terms as a payload past the region: a silently
    /// shortened run of ring bytes would look like success at both ends.
    fn ship(&mut self, demand: RelayDemand, recording: DownloadSink) -> TerminatingPass {
        let stated = demand.stated_len();
        if stated as usize > SHIPPED_RING_BYTES {
            return self.refuse(
                demand,
                RelayRefusal::PayloadTooLong,
                RefusalDetail::One(u64::from(stated)),
            );
        }
        let position = match demand.shipping() {
            Some((_, position)) => position,
            // Unreachable: this arm is reached off the very operation that
            // carries one. Answered rather than asserted, no fault being
            // admissible on a path a peer paces.
            None => {
                return self.refuse(demand, RelayRefusal::NoSuchOperation, RefusalDetail::None);
            }
        };
        let Self {
            responder, records, ..
        } = self;
        let Some(taken) = demand.payload(responder, records).map(<[u8]>::len) else {
            return self.refuse(
                demand,
                RelayRefusal::PayloadTooLong,
                RefusalDetail::One(u64::from(stated)),
            );
        };
        let Self {
            terminator,
            records,
            answer,
            ..
        } = self;
        let bytes = records.get(..taken).unwrap_or_default();
        let answered = terminator.ship(recording, position, bytes, answer);
        self.settle(demand, answered)
    }

    /// Give the protocol the first `taken` bytes of what was copied out, and put
    /// its answer on the channel.
    ///
    /// A protocol that says it is finished ends the session **here** as well as
    /// there: the closed word goes back on the same item, which is what takes
    /// the connection down at the end that owns it, and the account goes out
    /// beside it. [`OnboardEnd::Consumer`], because this end is the one that
    /// decided — the peer said nothing about it and the transport is still
    /// holding the connection.
    fn turn(&mut self, demand: RelayDemand, taken: usize) -> TerminatingPass {
        let Self {
            terminator,
            records,
            answer,
            ..
        } = self;
        let received = records.get(..taken).unwrap_or_default();
        let answered = terminator.advance(received, answer);
        self.settle(demand, answered)
    }

    /// Put what the protocol answered on the channel, and account for the
    /// session it may have ended.
    fn settle(&mut self, demand: RelayDemand, answered: Answered) -> TerminatingPass {
        let Answered {
            sent,
            finished,
            agreed,
        } = answered;
        // Clamped rather than trusted: a length past the buffer is this
        // appliance's own defect, and no panic is admissible on a path a peer
        // paces.
        let sent = sent.min(ANSWER_ROOM);
        if finished {
            self.terminator.closed();
        }
        self.publish(demand, sent, finished, agreed);
        TerminatingPass {
            refused: None,
            report: finished
                .then(|| self.session.take())
                .flatten()
                .map(|held| held.finished(OnboardEnd::Consumer)),
        }
    }

    /// Answer the demand with the first `sent` bytes of the answer buffer, and
    /// count the item against the session it belongs to.
    ///
    /// The bytes answered with are counted as the channel published them rather
    /// than as they were offered: what the account states is what crossed.
    fn publish(&mut self, demand: RelayDemand, sent: usize, closed: bool, agreed: bool) {
        // Stated on every answer, on the agreed word's terms: read as a level,
        // so a coalesced wakeup cannot lose it.
        let acked = self.terminator.acknowledged();
        self.responder.acknowledge(acked);
        let Self {
            responder, answer, ..
        } = self;
        let published = responder.answered(
            demand,
            answer.get(..sent).unwrap_or_default(),
            closed,
            agreed,
        );
        if let Some(held) = self.session.as_mut() {
            held.relayed = held.relayed.saturating_add(1);
            held.sent = held.sent.saturating_add(published as u64);
        }
    }

    /// Refuse the demand and report the session it ended.
    ///
    /// Every refusal ends the session at both ends — `wire::relay` publishes a
    /// closed word of one with each — so the account goes out beside the token
    /// rather than waiting for a close that will never come. A refusal with no
    /// session behind it reports none, there being nothing to account for.
    ///
    /// A refused item is **not** counted against the session, and that is what
    /// makes the two domains' accounts one number: the network end counts an item
    /// when it is answered and a refusal is not an answer, so an end that counted
    /// it here would report one more handover than the other saw and read as a
    /// relay that had lost something.
    fn refuse(
        &mut self,
        demand: RelayDemand,
        reason: RelayRefusal,
        detail: RefusalDetail,
    ) -> TerminatingPass {
        self.responder.refuse(demand, reason);
        let report = self
            .session
            .take()
            .map(|held| held.finished(OnboardEnd::Refused));
        if report.is_some() {
            // The protocol hears about exactly the sessions it was told to
            // open, so a refusal with none behind it tells it nothing.
            self.terminator.closed();
        }
        TerminatingPass {
            refused: Some((reason, detail)),
            report,
        }
    }
}

/// A close's ending in the console's own vocabulary.
///
/// One arm per ending and no arm covering two, [`relay_ending`]'s obligation
/// with the directions exchanged: this is where the network end's account of how
/// a session ended becomes this end's, and a fold would make the two records
/// disagree about a session they both carried.
const fn onboard_end(ending: RelayEnding) -> OnboardEnd {
    match ending {
        RelayEnding::Peer => OnboardEnd::Peer,
        RelayEnding::Consumer => OnboardEnd::Consumer,
        RelayEnding::Forgotten => OnboardEnd::Forgotten,
        RelayEnding::Refused => OnboardEnd::Refused,
    }
}

/// A session's ending as the relay's own vocabulary states it.
///
/// One arm per ending and no arm covering two, which is the obligation this
/// function carries: the far end reports what it is told, so a fold here would
/// put back into that domain's record exactly the ambiguity carrying the ending
/// exists to remove. The two sets are separate copies facing different readers —
/// one is the console's, one is the channel's — and this is the single place that
/// maps them.
const fn relay_ending(ended: OnboardEnd) -> RelayEnding {
    match ended {
        OnboardEnd::Peer => RelayEnding::Peer,
        OnboardEnd::Consumer => RelayEnding::Consumer,
        OnboardEnd::Forgotten => RelayEnding::Forgotten,
        OnboardEnd::Refused => RelayEnding::Refused,
    }
}

/// Whether `deadline` has passed. A pass with no clock has no deadline to judge
/// and lets the item stand: a node that has not established a time refuses every
/// segment in any case, so there is no session for this to be carrying.
fn expired(now: Option<Monotonic>, deadline: Option<Monotonic>) -> bool {
    match (now, deadline) {
        (Some(now), Some(deadline)) => now >= deadline,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
