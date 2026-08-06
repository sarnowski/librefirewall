//! The network end of the TLS relay: moving an onboarding connection's bytes to
//! the domain that terminates the session, and that domain's answers back onto
//! the wire.
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
use lfw_log::OnboardEnd;
use wire::{
    MAX_RELAY_PAYLOAD, PendingRelay, RelayFault, RelayOperation, RelayPoll, RelayRefusal,
    RelayReply, RelayRequest, RelayRequester,
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
    /// stream keeps for what goes on the wire, so the session cannot be carried
    /// on without a hole in the middle of it. **Ours** rather than the peer's,
    /// and the number is what there was no room for.
    AnswerTooLong { refused: usize },
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
}

/// The onboarding half of an endpoint, as this module needs it.
///
/// A trait rather than the concrete stage on the configuration channel's terms:
/// driving a real endpoint to a session with bytes in it is a handshake and
/// several frames away there, and one call away against a fake.
pub trait Onboarding {
    /// The connection a session is running on, or `None` where there is none.
    fn session(&self) -> Option<ConnectionId>;
    /// Bytes the peer sent that have not been handed over.
    fn received(&self) -> &[u8];
    /// Drop the first `bytes`, which have been handed over.
    fn consumed(&mut self, bytes: usize);
    /// Whether the peer has closed its half.
    fn peer_closed(&self) -> bool;
    /// Put `bytes` on the wire, answering how many there was room for.
    fn push(&mut self, bytes: &[u8]) -> usize;
    /// End the session: the terminating domain has finished with it.
    fn end_session(&mut self);
    /// How the last session ended, taken once.
    fn take_ending(&mut self) -> Option<Ended>;
}

impl Onboarding for EndpointStage<'_> {
    fn session(&self) -> Option<ConnectionId> {
        Self::onboard_session(self)
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

    fn end_session(&mut self) {
        Self::onboard_end_session(self);
    }

    fn take_ending(&mut self) -> Option<Ended> {
        Self::take_onboard_ending(self)
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
    /// The stream connection this end is carrying a session for, so a
    /// connection replaced between two passes is noticed rather than carried on
    /// as though it were the same one — and so a session that has been finished
    /// is not opened again on the connection it was finished on.
    carried: Option<ConnectionId>,
    /// A `Poll` has been issued and nothing has happened since. See the module
    /// header on why this is what keeps a quiet session from answering itself
    /// forever.
    polled: bool,
    /// A close issued *because* the session failed. It is attempted once: a
    /// second against a far end that is already answering rubbish is a loop.
    closing_after_failure: bool,
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
            polled: false,
            closing_after_failure: false,
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

    /// One bounded pass: claim the answer if one has arrived, then issue at most
    /// one item.
    ///
    /// Never blocks and never spins. A pass with nothing to do returns a
    /// [`RelayPass`] that asks for nothing, which is the whole of the contract
    /// with the event loop.
    pub fn poll(&mut self, now: Option<Monotonic>, stream: &mut impl Onboarding) -> RelayPass {
        self.claim(now, stream);
        let (notify, report) = self.issue(now, stream);
        RelayPass { notify, report }
    }

    /// Look **once** for the answer to the outstanding item, giving up on one
    /// that has outlived [`ANSWER_TIMEOUT`].
    fn claim(&mut self, now: Option<Monotonic>, stream: &mut impl Onboarding) {
        let Some(Outstanding { pending, deadline }) = self.outstanding.take() else {
            return;
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
                    answered: _,
                } => Claimed::Answered {
                    offered: records.len(),
                    kept: stream.push(records),
                    closed,
                },
                RelayPoll::Refused(reason) => Claimed::Refused(reason),
                RelayPoll::Faulted(fault) => Claimed::Faulted(fault),
            }
        };
        match claimed {
            Claimed::Outstanding(pending) => {
                if !expired(now, deadline) {
                    self.outstanding = Some(Outstanding { pending, deadline });
                    return;
                }
                // The handle is dropped rather than re-parked, which frees this
                // end's one slot. A reply that lands afterwards answers a
                // sequence no item is held against, and `RelayRequester::poll`
                // reads such a reply as no answer at all — so a late answer
                // cannot be mistaken for the next item's.
                self.far = Far::Closed;
                self.fail(stream, RelayFailure::Unanswered);
            }
            Claimed::Answered {
                offered,
                kept,
                closed,
            } => {
                self.relayed = self.relayed.saturating_add(1);
                self.sent = self.sent.saturating_add(kept as u64);
                if offered > 0 {
                    self.polled = false;
                }
                if kept < offered {
                    self.far = Far::Closed;
                    self.fail(
                        stream,
                        RelayFailure::AnswerTooLong {
                            refused: offered.saturating_sub(kept),
                        },
                    );
                    return;
                }
                match asked {
                    // The far end holds a session from here on, and owes one
                    // answer to every item until it is closed.
                    RelayOperation::Open => self.far = Far::Open,
                    RelayOperation::Close => self.far = Far::Closed,
                    RelayOperation::Deliver | RelayOperation::Poll => {}
                }
                if closed {
                    self.far = Far::Closed;
                    stream.end_session();
                }
            }
            Claimed::Refused(reason) => {
                // Every refusal publishes a closed session, so the far end holds
                // nothing to close.
                self.far = Far::Closed;
                self.fail(stream, RelayFailure::Refused(reason));
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
                    return;
                }
                self.far = Far::Closed;
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
        stream: &mut impl Onboarding,
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
            self.carried = Some(session);
            return (self.ask(stream, now, RelayOperation::Open, &[]), None);
        };
        if session != Some(carried) {
            // The connection this session ran on is gone or has been replaced.
            // The far end is told before the account is made, so the next
            // session's `Open` is an open rather than an `AlreadyOpen`.
            if self.far == Far::Open {
                return (self.ask(stream, now, RelayOperation::Close, &[]), None);
            }
            return (false, self.finish(stream));
        }
        if self.failure.is_some() {
            // The session has failed and its connection is already being taken
            // down. What is left is to give the far end its close, once.
            if self.far == Far::Open {
                return (self.ask(stream, now, RelayOperation::Close, &[]), None);
            }
            return (false, None);
        }
        if self.far == Far::Closed {
            // Both ends are finished with the session and the connection is
            // still closing. Nothing is owed until it is gone.
            return (false, None);
        }
        let handed = {
            let waiting = stream.received();
            let len = waiting.len().min(MAX_RELAY_PAYLOAD);
            match waiting.get(..len) {
                Some(bytes) if !bytes.is_empty() => {
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
            return (self.ask(stream, now, RelayOperation::Close, &[]), None);
        }
        if self.polled {
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
        stream: &mut impl Onboarding,
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
    fn refuse_window(&mut self, stream: &mut impl Onboarding) {
        self.far = Far::Closed;
        self.fail(stream, RelayFailure::Busy);
    }

    /// Record a failure and take the connection down with it, keeping the first:
    /// what went wrong first is what an operator has to look at, and a later
    /// consequence of it would displace the cause.
    fn fail(&mut self, stream: &mut impl Onboarding, failure: RelayFailure) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
        stream.end_session();
    }

    /// Close the session's account, if there is one to close.
    fn finish(&mut self, stream: &mut impl Onboarding) -> Option<RelayReport> {
        self.carried?;
        let ended = match (self.failure, stream.take_ending()) {
            (Some(_), _) => OnboardEnd::Refused,
            (None, Some(Ended::ByPeer)) => OnboardEnd::Peer,
            (None, Some(Ended::ByConsumer)) => OnboardEnd::Consumer,
            (None, Some(Ended::Forgotten) | None) => OnboardEnd::Forgotten,
        };
        let report = RelayReport {
            relayed: self.relayed,
            received: self.received,
            sent: self.sent,
            ended,
            failure: self.failure,
        };
        self.carried = None;
        self.far = Far::Closed;
        self.polled = false;
        self.closing_after_failure = false;
        self.relayed = 0;
        self.received = 0;
        self.sent = 0;
        self.failure = None;
        Some(report)
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
