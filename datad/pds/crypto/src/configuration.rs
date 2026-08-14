//! The management channel's configuration operations: staging a document the
//! server pushed, committing it provisionally, and the deadline that puts the
//! previous configuration back when no fresh connection confirms it.
//!
//! # Why the deadline is here and not with the store
//!
//! A **commit is confirmed over a connection opened after it**, because the
//! appliance dials out: what a committed configuration must not break is a *new*
//! dial, and a confirmation on the session that pushed the change proves nothing
//! about those — that session already exists and survives regardless.
//!
//! Which makes the deadline a fact about sessions, and sessions are this domain's.
//! The domain that owns the datastore holds the store and the two operations over
//! it and needs no clock, no wakeup and no notion of connection identity for
//! either.
//!
//! # Adversary
//!
//! A **management-plane attacker up to and including a compromised management
//! server**, and behind the delegation a **byzantine neighbour protection
//! domain**. The server chooses the document bytes, the generation each operation
//! names, the deadline it asks for, and the pacing of all of it.
//!
//! So: the deadline the server asks for is clamped to a bound of this file's
//! before it is believed, the generation it names is narrowed to the width the
//! datastore uses and refused rather than truncated where it does not fit, and
//! every exchange with the deciding domain is one request answered inside a
//! bounded read. Nothing here parses a document — the deciding domain does that,
//! against an arbitrary byte string, which is what it was written for.
//!
//! # What a compromised server achieves, and one rollback per commit
//!
//! It can push a configuration this appliance validates and commits, which is the
//! authority a management plane has by definition. What it cannot do is make one
//! permanent without opening a fresh connection, change the trust anchor or the
//! endpoint — neither is expressible in a document — or leave the appliance
//! forwarding under a configuration nobody confirmed: the deadline is armed from
//! this appliance's own clock and the rollback needs nothing from the wire. A
//! rollback consumes the commit it undoes, so an unreachable server costs one
//! reversal and then nothing however long it stays away.

use alloc::sync::Arc;

use lfw_log::{Refusal, RefusalDetail};
use pd_runtime::{MAX_ANSWER_LEN, Outcome, reject_reason_of, write_result_line};
use sel4_microkit::Channel;
use wire::{
    ConfigPoll, ConfigReply, ConfigRequest, ConfigRequester, InstallStaging, MAX_DOCUMENT_BYTES,
    PendingConfigRequest, StagedUpload,
};

use crate::delegate::Delegated;

/// Reads of the reply region before the deciding domain is given up on.
///
/// The signing delegation's constant and its reasoning: the domain that answers
/// sits **above** this one in priority, so the read below finds its answer on the
/// first iteration in practice. The budget is what happens when it does not, and
/// it is a constant of this file rather than anything a peer can lengthen.
const POLL_BUDGET: u32 = 1024;

/// The longest a commit may stay unconfirmed, whatever the server asks for.
///
/// Ten minutes, as a **clamp and not a default**: the server's number is used
/// where it is shorter, and this is the bound past which an appliance would hold a
/// configuration nobody has taken responsibility for indefinitely — the state
/// commit-confirm exists to end.
const MAX_CONFIRM_SECONDS: u64 = 600;

/// The shortest, for a server that asks for none at all.
///
/// A deadline of zero seconds would be a commit reverted before the appliance had
/// finished re-dialling, which is a commit that can never be confirmed — so it is
/// raised rather than honoured, a peer being unable to ask this appliance to
/// defeat its own mechanism.
const MIN_CONFIRM_SECONDS: u64 = 5;

// The two bounds are in the order `clamp` requires, which is what makes the clamp
// below total: its one panic is `min > max`, and these are constants of this file
// that no peer reaches.
const _: () = assert!(MIN_CONFIRM_SECONDS < MAX_CONFIRM_SECONDS);

/// What staging a document produced, as the result line needs it.
pub struct StageResult {
    /// The line to put in the up frame, without a line ending.
    pub line: [u8; MAX_ANSWER_LEN],
    pub len: usize,
}

/// Why a configuration operation over the channel did not happen, as a console
/// token.
///
/// One per cause and none covering two, on the framing's terms: a deployed node
/// is diagnosed from its console alone, and a server naming the wrong generation,
/// a server confirming a commit nobody made, and a deciding domain that stopped
/// answering are three different things to go and look at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigFailure {
    /// The deciding domain did not answer within [`POLL_BUDGET`] reads.
    Unanswered,
    /// It answered something this request cannot be answered with — a status the
    /// ABI's own cross-field rule refuses, or one belonging to another operation.
    /// Reaching it means that rule and this domain's reading of it disagree, which
    /// should never appear.
    Faulted,
    /// It does not have the operation that was asked for.
    NoSuchOperation,
    /// The generation the server named is not the one the operation acts on.
    GenerationMismatch,
    /// A commit with nothing staged.
    NoCandidate,
    /// A confirmation or a revert with no provisional commit outstanding.
    NotProvisional,
    /// The generation counter has no successor to assign.
    Exhausted,
    /// The generation the server named does not fit the width a configuration
    /// generation has. Refused rather than narrowed: a truncated number would
    /// name a different commit.
    GenerationTooWide,
    /// A confirmation on the very session that made the commit, which proves
    /// nothing about a configuration that breaks new connections.
    NotAFreshConnection,
    /// The configuration is in force and the holder of the medium would not make
    /// it durable, so it will not survive a reboot. **Reported, not reverted**:
    /// undoing a commit would leave two domains disagreeing.
    NotDurable,
    /// A commit whose document this domain never staged where the holder reads:
    /// unreachable, and its own token rather than [`Self::Faulted`].
    NothingStaged,
}

impl ConfigFailure {
    /// The console token, one per cause.
    pub const fn cause(self) -> &'static str {
        match self {
            Self::Unanswered => "channel-config-unanswered",
            Self::Faulted => "channel-config-faulted",
            Self::NoSuchOperation => "channel-config-no-such-operation",
            Self::GenerationMismatch => "channel-config-generation-mismatch",
            Self::NoCandidate => "channel-config-no-candidate",
            Self::NotProvisional => "channel-config-not-provisional",
            Self::Exhausted => "channel-config-generations-exhausted",
            Self::GenerationTooWide => "channel-config-generation-too-wide",
            Self::NotAFreshConnection => "channel-config-confirm-not-fresh",
            Self::NotDurable => "channel-config-not-durable",
            Self::NothingStaged => "channel-config-nothing-staged",
        }
    }

    /// This failure as a refusal for the console. `signalled` is `false`: there is
    /// no device here to be told anything.
    pub const fn refusal(self) -> Refusal {
        Refusal {
            cause: self.cause(),
            detail: RefusalDetail::None,
            signalled: false,
        }
    }
}

/// The commit awaiting a confirmation over a connection opened after it.
///
/// **Which generation it is is not here**, and that is deliberate: the store holds
/// that and matches a confirmation against it, so a copy in this domain would be a
/// second statement of one fact — and the one that goes stale the moment a plain
/// commit settles the provisional one underneath it.
#[derive(Clone, Copy)]
struct Awaiting {
    /// The wall-clock second by which a confirmation must have arrived.
    deadline: u64,
    /// Which session made the commit, so a confirmation on that same session can
    /// be told apart from one on a fresh connection. **The whole enforcement of
    /// the fresh-connection rule**, and it is a number this appliance assigns
    /// rather than anything the peer can restate.
    session: u64,
}

/// The channel's end of the configuration delegation: the requester, and the one
/// commit that may be awaiting confirmation.
pub struct ChannelConfig {
    requester: ConfigRequester<'static>,
    /// Where an answer is copied to. One document's worth, allocated once for the
    /// domain's life, because the ABI's poll takes a whole region-length array and
    /// a protection domain's stack is not where 64 KiB belongs. The `None` refuses
    /// every operation under its own token rather than faulting.
    answer: Option<&'static mut [u8; MAX_DOCUMENT_BYTES]>,
    /// The domain that decides. Notified after a request is published and never
    /// before: the notification is what makes it look, and a signal ahead of the
    /// sequence would be a wakeup for a request that is not there yet.
    decider: Channel,
    // What each operation did is counted by the domain that decided it, in that
    // domain's own submission shard, under the same outcome vocabulary an operator
    // reads on the console. A tally here would be a second count of one event, and
    // the two would come to disagree.
    awaiting: Option<Awaiting>,
    /// The region the holder of the medium reads a document out of, which this
    /// domain maps read-write and that one read-only.
    ///
    /// **The document bytes are kept here and nowhere else in this domain.** The
    /// deciding domain does not keep them, so the write falls to the domain that
    /// had them last — at staging time, a commit frame carrying none.
    staging: &'static InstallStaging,
    /// What the last staging put there; `None` once a commit has consumed it.
    staged: Option<StagedUpload>,
    /// The holder of the medium, asked once per commit and only after the
    /// generation is assigned — the only order that number admits.
    holder: Arc<Delegated>,
}

impl ChannelConfig {
    /// Take the asking side of the channel — once per domain; a second would
    /// restart at sequence zero and reuse numbers the first has outstanding.
    pub fn attach(
        request: &'static ConfigRequest,
        reply: &'static ConfigReply,
        decider: Channel,
        answer: Option<&'static mut [u8; MAX_DOCUMENT_BYTES]>,
        staging: &'static InstallStaging,
        holder: Arc<Delegated>,
    ) -> Self {
        Self {
            requester: request.requester(reply),
            answer,
            decider,
            awaiting: None,
            staging,
            staged: None,
            holder,
        }
    }

    /// Stage `document` as the candidate and validate it, answering the line the
    /// result frame carries.
    ///
    /// Every failure still produces a line, and that is deliberate: the server is
    /// owed an answer to the document it pushed, and a staging that failed because
    /// this appliance could not reach its own deciding domain is reported as a
    /// refusal with a reason rather than as silence. The console token beside it is
    /// what tells the two apart on the node itself.
    pub fn stage(&mut self, document: &[u8]) -> (StageResult, Option<ConfigFailure>) {
        let poll = self.exchange(|requester| requester.stage(document));
        let mut line = [0_u8; MAX_ANSWER_LEN];
        match poll {
            Ok(Answered::Staged { generation }) => {
                // Where the holder can read them, and only for a document the
                // deciding domain accepted: a region holding a refused one would
                // be a commit away from a version nothing validated.
                let mut cursor = self.staging.upload().cursor();
                let took = cursor.write(document);
                self.staged = (took == document.len()).then(|| cursor.finish());
                let len = write_result_line(&mut line, generation, Outcome::Staged, 0, None);
                (StageResult { line, len }, None)
            }
            Ok(Answered::Rejected {
                generation,
                reason,
                detail,
            }) => {
                let len = write_result_line(
                    &mut line,
                    generation,
                    Outcome::Refused,
                    0,
                    Some((reject_reason_of(reason), detail)),
                );
                (StageResult { line, len }, None)
            }
            Ok(_) => self.stage_failed(line, ConfigFailure::Faulted),
            Err(failure) => self.stage_failed(line, failure),
        }
    }

    /// Commit the candidate the server named, provisionally, and arm the deadline
    /// a confirmation must beat.
    ///
    /// `session` is kept so a confirmation on that same session is refused, `now`
    /// is this appliance's own reading of the wall clock, and `deadline_secs` is
    /// the server's request clamped between [`MIN_CONFIRM_SECONDS`] and
    /// [`MAX_CONFIRM_SECONDS`]. Answering the generation is what the caller turns
    /// into ending the session, closing being how this appliance makes a later
    /// connection the only place a confirmation can arrive.
    pub fn commit(
        &mut self,
        generation: u64,
        deadline_secs: u16,
        now: u64,
        session: u64,
    ) -> Result<u32, ConfigFailure> {
        let Ok(named) = u32::try_from(generation) else {
            return Err(ConfigFailure::GenerationTooWide);
        };
        match self.exchange(|requester| requester.commit(named)) {
            Ok(Answered::Applied { generation }) => {
                let allowed =
                    u64::from(deadline_secs).clamp(MIN_CONFIRM_SECONDS, MAX_CONFIRM_SECONDS);
                self.awaiting = Some(Awaiting {
                    deadline: now.saturating_add(allowed),
                    session,
                });
                // The history, after the configuration is in force: nothing names
                // a version until the deciding domain has. A failure is answered
                // and not undone — see `NotDurable`.
                self.persist(generation)?;
                Ok(generation)
            }
            // The content was already running, so nothing was displaced and there
            // is nothing to confirm. Not a failure — the server asked for a
            // configuration and that configuration is in force — and deliberately
            // *not* armed: a deadline over a commit that changed nothing would
            // revert a configuration that never moved.
            Ok(Answered::Unchanged { generation }) => Ok(generation),
            Ok(_) => Err(ConfigFailure::Faulted),
            Err(failure) => Err(failure),
        }
    }

    /// Keep the commit `generation` names, which is admissible only on a session
    /// other than the one that made it.
    pub fn confirm(&mut self, generation: u64, session: u64) -> Result<u32, ConfigFailure> {
        let Some(awaiting) = self.awaiting else {
            return Err(ConfigFailure::NotProvisional);
        };
        // Before the generation is even looked at, because it is the stronger
        // refusal: a server confirming over the session it committed on has not
        // demonstrated the one property the confirmation exists to demonstrate,
        // whichever generation it names.
        if awaiting.session == session {
            return Err(ConfigFailure::NotAFreshConnection);
        }
        let Ok(named) = u32::try_from(generation) else {
            return Err(ConfigFailure::GenerationTooWide);
        };
        match self.exchange(|requester| requester.confirm(named)) {
            Ok(Answered::Confirmed { generation }) => {
                self.awaiting = None;
                Ok(generation)
            }
            Ok(_) => Err(ConfigFailure::Faulted),
            Err(failure) => Err(failure),
        }
    }

    /// Ask the holder of the medium to make the staged document a slot of the
    /// version history, under the generation the deciding domain assigned.
    ///
    /// The token is consumed either way, so a second commit with nothing staged is
    /// refused by name rather than writing what is there.
    ///
    /// # Errors
    /// [`ConfigFailure::NothingStaged`] and [`ConfigFailure::NotDurable`].
    fn persist(&mut self, generation: u32) -> Result<(), ConfigFailure> {
        let Some(staged) = self.staged.take() else {
            return Err(ConfigFailure::NothingStaged);
        };
        self.holder
            .record_config(u64::from(generation), staged)
            .map_err(|_| ConfigFailure::NotDurable)
    }

    /// Put the previous configuration back where the deadline has passed at `now`,
    /// answering the generation now running.
    ///
    /// `None` where nothing is awaiting confirmation or the deadline has not
    /// passed, which is every ordinary pass. The commit is consumed either way the
    /// request goes, so an unreachable server costs one rollback and never a loop:
    /// a refusal here is a deciding domain that has stopped answering, and asking
    /// it again every pass would be the loop this appliance must not run.
    pub fn expired(&mut self, now: u64) -> Option<Result<u32, ConfigFailure>> {
        let awaiting = self.awaiting?;
        if now < awaiting.deadline {
            return None;
        }
        self.awaiting = None;
        Some(match self.exchange(ConfigRequester::roll_back) {
            Ok(Answered::RolledBack { generation }) => Ok(generation),
            Ok(_) => Err(ConfigFailure::Faulted),
            Err(failure) => Err(failure),
        })
    }

    /// Issue one request and read for its answer inside [`POLL_BUDGET`]. The flag
    /// the signing delegation holds needs no counterpart here: this is `&mut self`
    /// and a protection domain is single-threaded, so two callers interleaving a
    /// request and a read is not a shape the borrow checker admits.
    fn exchange(
        &mut self,
        issue: impl FnOnce(&mut ConfigRequester<'static>) -> PendingConfigRequest,
    ) -> Result<Answered, ConfigFailure> {
        let Some(answer) = self.answer.as_mut() else {
            return Err(ConfigFailure::Unanswered);
        };
        let mut pending = issue(&mut self.requester);
        // After the request is published and not before: the notification is what
        // makes the deciding domain look, and a signal ahead of the sequence would
        // be a wakeup for a request that is not there yet.
        self.decider.notify();
        for _ in 0..POLL_BUDGET {
            match self.requester.poll(pending, answer) {
                ConfigPoll::Outstanding(outstanding) => {
                    pending = outstanding;
                    core::hint::spin_loop();
                }
                ConfigPoll::Applied { generation, .. } => {
                    return Ok(Answered::Applied { generation });
                }
                ConfigPoll::Unchanged { generation } => {
                    return Ok(Answered::Unchanged { generation });
                }
                ConfigPoll::Staged { generation } => return Ok(Answered::Staged { generation }),
                ConfigPoll::Confirmed { generation } => {
                    return Ok(Answered::Confirmed { generation });
                }
                ConfigPoll::RolledBack { generation } => {
                    return Ok(Answered::RolledBack { generation });
                }
                ConfigPoll::Rejected {
                    generation,
                    reason,
                    detail,
                } => {
                    return Ok(Answered::Rejected {
                        generation,
                        reason,
                        detail,
                    });
                }
                ConfigPoll::NoCandidate { .. } => return Err(ConfigFailure::NoCandidate),
                ConfigPoll::NotProvisional { .. } => return Err(ConfigFailure::NotProvisional),
                ConfigPoll::GenerationMismatch { .. } => {
                    return Err(ConfigFailure::GenerationMismatch);
                }
                ConfigPoll::Exhausted { .. } => return Err(ConfigFailure::Exhausted),
                ConfigPoll::NoSuchOperation => return Err(ConfigFailure::NoSuchOperation),
                // A reply that is not this request's answer, which the ABI refuses
                // rather than believes. It consumes the handle, so there is
                // nothing left to read for.
                ConfigPoll::Document { .. } | ConfigPoll::Faulted(_) => {
                    return Err(ConfigFailure::Faulted);
                }
            }
        }
        Err(ConfigFailure::Unanswered)
    }

    /// Compose the refusal line a staging that could not be decided answers with,
    /// and count it.
    fn stage_failed(
        &mut self,
        mut line: [u8; MAX_ANSWER_LEN],
        failure: ConfigFailure,
    ) -> (StageResult, Option<ConfigFailure>) {
        // Generation zero, which is no configuration: an exchange that did not
        // complete is one this end learnt nothing from, and a number here would be
        // a claim about what is running that this domain holds no copy of. And
        // `malformed` as the reason, which is the honest token — what the server is
        // told is that the appliance could not make sense of the exchange about its
        // document. Which part of the appliance could not is a console token and
        // never a thing to put on the wire.
        let len = write_result_line(
            &mut line,
            0,
            Outcome::Refused,
            0,
            Some((lfw_log::RejectReason::Malformed, 0)),
        );
        (StageResult { line, len }, Some(failure))
    }
}

/// The answers a configuration exchange can carry, once the failures are out of
/// the way. A vocabulary of this file rather than the ABI's poll, because a poll
/// borrows the answer buffer and these do not — which is what lets the buffer stay
/// a field.
enum Answered {
    Applied {
        generation: u32,
    },
    Unchanged {
        generation: u32,
    },
    Staged {
        generation: u32,
    },
    Confirmed {
        generation: u32,
    },
    RolledBack {
        generation: u32,
    },
    Rejected {
        generation: u32,
        reason: u32,
        detail: u32,
    },
}
