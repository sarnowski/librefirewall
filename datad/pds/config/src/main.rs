#![no_main]
#![no_std]

//! Configuration protection domain: it owns the appliance's configuration
//! datastore, decides whether a document is one this build can hold, and hands
//! the result to the domain that forwards under it.
//!
//! # Adversary
//!
//! The management-plane attacker, and no longer theoretically. A document now
//! arrives over the network: the management domain takes it off a TCP connection
//! and copies it into a region this domain reads, so every byte the reader below
//! sees is that party's choice. Nothing about the reader changed to meet that —
//! it was written against a fully attacker-controlled byte string from the start,
//! which is why this landing widened a channel rather than a parser.
//!
//! # What this domain holds, and what that leaves it unable to do
//!
//! No device capability, no buffer pool, no dataplane ring: the entire grant is
//! the handover region it writes, the acknowledgement region it reads, the
//! submission channel's two regions and its own log ring. A compromised reader
//! reaches no frame and no NIC, and the worst it produces is a configuration —
//! which the consumer decides for itself, `wire::ConfigImage::check` holding the
//! image it copies out to every rule this domain's own validator applies, field by
//! field and pair by pair. This domain is the one that parses an attacker's
//! document, so a rule it alone enforced would be a rule a compromise of it lifts.
//!
//! # Nothing is published unless everything passed
//!
//! A document this domain will not accept leaves the handover region untouched,
//! so the consumer stays on the generation it was already running and the
//! submitter is told which rule was broken. There is deliberately no default
//! configuration behind the document and no partial apply: a fallback would make
//! a typo indistinguishable from a working appliance until traffic went somewhere
//! nobody intended.
//!
//! # A boot document, and then as many as an operator sends
//!
//! [`CONFIG_XML`] is `include_bytes!` over an `env!`, so a build with no
//! `LIBREFIREWALL_CONFIG_PATH` fails at compilation rather than producing a
//! domain with an empty or default document. It is the *first* generation and no
//! longer the only one: the datastore survives `init` and every later document
//! arrives over the channel, is staged, validated and committed against the same
//! store, and takes the next generation.
//!
//! # Two ports into one store, and why that is not two stores
//!
//! This domain answers **two** submission channels with one datastore behind
//! them: the management domain's, which carries an administrator's `POST` as a
//! single stage-validate-commit step, and the cryptography domain's, which
//! carries the management channel's operations as the separate steps that
//! protocol takes — stage, commit, confirm, revert.
//!
//! One store, because there is one configuration. Two channels, because a channel
//! is the unit of grant and the two requesters are two domains: a single region
//! pair written by both would let either of them answer for the other, and the
//! two are at different points in the trust order — the domain that terminates
//! the management channel is not the domain that owns the management port.
//!
//! **A candidate is the store's and not a port's.** Nothing here remembers which
//! port staged a document, and that is deliberate: an appliance has one
//! configuration and therefore one candidate, so a commit takes whatever was
//! staged last. What keeps two requesters from committing each other's work is
//! not bookkeeping but the generation the commit names — a commit for a
//! generation that is not the one a commit would assign is refused rather than
//! applied to whatever happens to be staged.
//!
//! # The commit the channel makes is provisional, and this domain holds no timer
//!
//! A channel commit keeps the configuration it displaced, so it can be put back;
//! confirming gives that up and reverting restores it. **When** an unconfirmed
//! commit is reverted is decided by the domain that owns the sessions, because
//! "no confirmation arrived over a fresh connection" is a fact about sessions and
//! this domain has none. What lives here is the store and the two operations over
//! it; what lives there is the deadline.
//!
//! # Why the answer does not wait for the dataplane
//!
//! A submission is answered as soon as this domain has committed it, and the
//! forwarding domain switches tables at its next poll boundary — the two-phase
//! handover being what makes that switch happen between two frames rather than
//! inside one. Waiting for the acknowledgement instead would hang a client
//! whenever the consumer refused an image, because a refusal is the *absence* of
//! an acknowledgement and this domain holds no timer to bound the difference. So
//! the answer names the generation that was committed, and the generation each
//! domain is actually running is on `GET /metrics` under that domain's own label
//! — which is the pairing an operator confirms a change with.
//!
//! # Records go to a ring, not to `debug_println!`
//!
//! That macro compiles to `seL4_DebugPutChar`, absent from the release kernel, so
//! a refusal — only safe while visible — would reach nobody in the profile that
//! ships. A typed [`Event`] in this domain's own ring, rendered by the console,
//! works in both.

use config::{
    CommitReport, Datastore, MAX_DOCUMENT_BYTES, ProvisionalReport, StageReport,
    commit_provisionally_and_report, confirm_and_report, revert_and_report, stage_and_report,
};
use lfw_log::{Domain, DomainDetail, DomainState, Event, RingSink, Sink};
use lfw_metrics::StatsShard;
use pd_runtime::{
    ConfigAck, ConfigHandover, ConfigPublisher, ConfigReply, ConfigRequest, PdClock,
    SubmissionCounters, attach_region, config_sample, log_sample,
};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{
    ClockCalibration, ConfigAnswer, ConfigDemand, ConfigOperation, ConfigResponder, LogConsume,
    LogRecords,
};

/// The configuration document this appliance boots with, as bytes.
///
/// `env!` rather than a path literal so the build decides which document is
/// shipped, and so a build that decides nothing fails loudly.
const CONFIG_XML: &[u8] = include_bytes!(env!("LIBREFIREWALL_CONFIG_PATH"));

/// The forwarding domain. Unlike the driver channels, this one carries
/// notifications both ways; see the system description on why.
const CONSUMER: Channel = Channel::new(0);

/// The management domain, which submits documents and asks what is running. Both
/// directions again, and for the same kind of reason: neither end can infer that
/// the other has spoken.
const MANAGEMENT: Channel = Channel::new(1);

// The cryptography domain, which carries the management channel's configuration
// operations, has NO constant here and that is the whole statement: this end of
// that channel holds no send capability, so there is no identifier for this
// domain to notify it by.
//
// That is the signing delegation's shape and its reasoning, with the roles
// exchanged: the asking domain reads for its answer in a bounded spin, because a
// configuration operation happens inside a session's own pass and has no
// continuation a notification could resume, and this domain sits above it in
// priority so the spin ends on its first iteration. A reverse capability would be
// a wakeup on the domain that terminates a management server's session, granted
// to the domain that parses that server's documents, and consumed by nothing.

#[protection_domain]
fn init() -> ConfigDomain {
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let ack: &'static ConfigAck = attach_region!(cfgack_vaddr: ConfigAck);
    let request: &'static ConfigRequest = attach_region!(cfg_request_vaddr: ConfigRequest);
    let reply: &'static ConfigReply = attach_region!(cfg_reply_vaddr: ConfigReply);
    let channel_request: &'static ConfigRequest =
        attach_region!(chan_cfg_request_vaddr: ConfigRequest);
    let channel_reply: &'static ConfigReply = attach_region!(chan_cfg_reply_vaddr: ConfigReply);
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);
    let clock: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));
    announce(&sink, DomainState::Starting);

    // The datastore now outlives `init`, which is the whole of this landing in
    // one line: a second document has somewhere to be staged against. It is the
    // largest thing this domain holds — a running model and a candidate — and it
    // is what makes this domain's stack the largest of any that holds no frame
    // buffer, a commit having three models and an image live at once.
    // `pd_runtime`'s `the_configuration_domains_state_fits_the_stack_it_is_declared_with`
    // is what holds the declared size to them.
    let mut store = Datastore::new();
    let mut publisher = ConfigPublisher::new();

    // Which state each outcome is, and whether there is anything to offer, are
    // decided in `config` where they are host-tested.
    let report = config::commit_and_report(&mut store, CONFIG_XML, &sink);
    // The refusal is unreachable — one offer, from a fresh publisher — and is
    // reported rather than dropped anyway: a generation nobody was offered is
    // one nobody runs, and the console is the only place that could say so.
    let offered = match report.image() {
        Some(image) => publisher.offer(handover, &image).is_ok(),
        None => false,
    };
    if offered {
        CONSUMER.notify();
    }
    let state = if report.image().is_some() && !offered {
        DomainState::Refused
    } else {
        report.state()
    };
    announce(&sink, state);

    let domain = ConfigDomain {
        handover,
        ack,
        responder: reply.responder(request),
        channel: channel_reply.responder(channel_request),
        publisher,
        store,
        document: [0; MAX_DOCUMENT_BYTES],
        stats,
        sink,
        submissions: submission_of(report),
        generation: report.generation(),
    };
    domain.publish();
    domain
}

fn announce(sink: &dyn Sink, state: DomainState) {
    sink.emit(&Event::Domain {
        domain: Domain::Config,
        state,
        detail: DomainDetail::None,
    });
}

/// The boot document counted as the submission it is.
///
/// A document that arrived at build time is still one this domain decided on, so
/// it is counted like any other: a node whose *boot* configuration was refused
/// and whose operator then submitted a good one reads as one applied and one
/// refused, which is what happened.
const fn submission_of(report: CommitReport) -> SubmissionCounters {
    let mut counters = SubmissionCounters {
        applied: 0,
        refused: 0,
        unchanged: 0,
        staged: 0,
        confirmed: 0,
        reverted: 0,
        reads: 0,
    };
    match report {
        CommitReport::Published { .. } => counters.applied = 1,
        CommitReport::Unchanged => counters.unchanged = 1,
        CommitReport::Rejected { .. } | CommitReport::Exhausted | CommitReport::NoCandidate => {
            counters.refused = 1;
        }
    }
    counters
}

/// What survives `init`: the regions, the store every later document is staged
/// against, where the offer has got to, and what this domain has decided.
struct ConfigDomain {
    handover: &'static ConfigHandover,
    ack: &'static ConfigAck,
    /// The answering end of the management domain's submission channel. Kept for
    /// the domain's life because it holds this domain's position in that
    /// channel's sequence; a second responder would answer a request the first
    /// has already served.
    responder: ConfigResponder<'static>,
    /// The answering end of the cryptography domain's, which carries the
    /// management channel's operations. Its own responder for the same reason
    /// there are two regions: a sequence is a channel's, and one responder over
    /// two channels would answer each request under the other's number.
    channel: ConfigResponder<'static>,
    publisher: ConfigPublisher,
    /// The running configuration and the candidate a submission becomes.
    store: Datastore,
    /// One document's worth of scratch, used in both directions and never at
    /// once: a submission is copied *out* of the request region into it and a read
    /// is rendered *into* it, and a demand is one or the other. A field rather
    /// than a local because 64 KiB does not belong in a call frame, and one field
    /// rather than two because the two uses cannot overlap.
    document: [u8; MAX_DOCUMENT_BYTES],
    /// The one region this domain writes its counters into.
    stats: &'static StatsShard,
    /// Kept past `init` because the counters it carries are published on every
    /// activation, not only on the first.
    sink: RingSink<'static, PdClock<'static>>,
    submissions: SubmissionCounters,
    /// The newest generation this domain has committed.
    generation: u32,
}

impl ConfigDomain {
    /// Write what this domain counts into its shard: the generation it has
    /// committed, what it has decided about the documents it was sent, and what
    /// its own log ring lost.
    fn publish(&self) {
        let sample = config_sample(
            self.generation,
            self.submissions,
            log_sample(self.sink.dropped(), self.sink.refused()),
        );
        self.stats.publish(&sample.values());
    }

    /// Answer whatever the management domain has asked, if it has asked anything.
    ///
    /// One demand per wakeup by construction — `ConfigResponder::take` yields one
    /// per change of the requester's sequence — so a submission storm costs one
    /// commit each and never an unbounded loop.
    fn serve(&mut self) {
        let Some(demand) = self.responder.take() else {
            return;
        };
        match demand.operation() {
            Some(ConfigOperation::Submit) => self.submit(demand),
            Some(ConfigOperation::Read) => self.state_running(demand),
            // The four steps of the management channel's own transaction, asked
            // for on the port that carries a single-step submission. Answered as
            // no operation rather than served: this port's requester answers a
            // client holding a TCP connection open and has nowhere to keep a
            // candidate between two requests, so serving a step here would leave
            // an appliance provisionally committed with nothing that can confirm
            // it.
            Some(
                ConfigOperation::Stage
                | ConfigOperation::Commit
                | ConfigOperation::Confirm
                | ConfigOperation::Rollback,
            )
            // The word named no operation. Answered rather than ignored: a
            // requester left waiting cannot tell a refusal from a hang.
            | None => {
                self.responder.answer(demand, ConfigAnswer::NoSuchOperation);
                MANAGEMENT.notify();
            }
        }
    }

    /// Answer whatever the cryptography domain has asked on the management
    /// channel's behalf.
    ///
    /// One demand per wakeup, on [`Self::serve`]'s terms, and no notification
    /// afterwards: this domain holds no send capability on that one, which reads
    /// for its answer in a bounded spin.
    fn serve_channel(&mut self) {
        let Some(demand) = self.channel.take() else {
            return;
        };
        match demand.operation() {
            Some(ConfigOperation::Stage) => self.stage(demand),
            Some(ConfigOperation::Commit) => self.commit(demand),
            Some(ConfigOperation::Confirm) => self.confirm(demand),
            Some(ConfigOperation::Rollback) => self.revert(demand),
            // A one-step submission or a document read over the channel's port.
            // Refused rather than served, and for a sharper reason than the
            // mirror above: a step-free commit over a channel would skip exactly
            // the confirmation the protocol exists to require, and a document
            // read has a frame of its own that this port is not.
            Some(ConfigOperation::Submit | ConfigOperation::Read) | None => {
                self.channel.answer(demand, ConfigAnswer::NoSuchOperation);
            }
        }
    }

    /// Hold the submitted document as the candidate and validate it, committing
    /// nothing.
    ///
    /// The bytes are copied out of the region first, on [`Self::submit`]'s terms.
    fn stage(&mut self, demand: ConfigDemand) {
        let Self {
            channel, document, ..
        } = self;
        let taken = channel.document(&demand, document);
        let answer = match stage_and_report(&mut self.store, taken, &self.sink) {
            StageReport::Staged { generation } => {
                self.submissions.staged = self.submissions.staged.saturating_add(1);
                ConfigAnswer::Staged { generation }
            }
            StageReport::Rejected { reason, detail } => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::Rejected {
                    generation: self.store.running().to_bits(),
                    // The discriminant is the wire encoding of the reason, as it
                    // is in a log record: the vocabulary is appended to and never
                    // reordered.
                    reason: reason as u32,
                    detail,
                }
            }
        };
        self.channel.answer(demand, answer);
    }

    /// Commit the candidate provisionally, held to the generation the request
    /// names.
    ///
    /// The generation is checked **before** anything is committed, and that check
    /// is the whole of what keeps two requesters from committing each other's
    /// work: a server naming a generation that is not the one a commit would
    /// assign has staged against a store that has moved under it, and applying
    /// whatever happens to be staged would be committing a document it never saw.
    fn commit(&mut self, demand: ConfigDemand) {
        let running = self.store.running().to_bits();
        let Some(next) = self.store.next_generation() else {
            self.submissions.refused = self.submissions.refused.saturating_add(1);
            self.channel.answer(
                demand,
                ConfigAnswer::Exhausted {
                    generation: running,
                },
            );
            return;
        };
        if next.to_bits() != demand.generation() {
            self.submissions.refused = self.submissions.refused.saturating_add(1);
            self.channel.answer(
                demand,
                ConfigAnswer::GenerationMismatch {
                    generation: next.to_bits(),
                },
            );
            return;
        }
        let answer = match commit_provisionally_and_report(&mut self.store, &self.sink) {
            CommitReport::Published { image, changes } => {
                self.submissions.applied = self.submissions.applied.saturating_add(1);
                self.generation = image.generation;
                self.offer(&image);
                ConfigAnswer::Applied {
                    generation: image.generation,
                    changes,
                }
            }
            CommitReport::Unchanged => {
                self.submissions.unchanged = self.submissions.unchanged.saturating_add(1);
                ConfigAnswer::Unchanged {
                    generation: self.store.running().to_bits(),
                }
            }
            CommitReport::NoCandidate => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::NoCandidate {
                    generation: self.store.running().to_bits(),
                }
            }
            CommitReport::Rejected { reason, detail } => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::Rejected {
                    generation: self.store.running().to_bits(),
                    reason: reason as u32,
                    detail,
                }
            }
            CommitReport::Exhausted => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::Exhausted {
                    generation: self.store.running().to_bits(),
                }
            }
        };
        self.channel.answer(demand, answer);
    }

    /// Keep the provisional commit the request names.
    fn confirm(&mut self, demand: ConfigDemand) {
        let answer = match confirm_and_report(&mut self.store, demand.generation(), &self.sink) {
            ProvisionalReport::Confirmed { generation } => {
                self.submissions.confirmed = self.submissions.confirmed.saturating_add(1);
                ConfigAnswer::Confirmed { generation }
            }
            ProvisionalReport::NotProvisional { generation } => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::NotProvisional { generation }
            }
            ProvisionalReport::GenerationMismatch { provisional } => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::GenerationMismatch {
                    generation: provisional,
                }
            }
            // A confirmation cannot revert anything, `confirm_and_report` having
            // no path to it. Answered rather than asserted, on every other
            // unreachable branch here's terms.
            ProvisionalReport::Reverted { generation, .. } => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::NotProvisional { generation }
            }
        };
        self.channel.answer(demand, answer);
    }

    /// Put back whatever the provisional commit displaced.
    fn revert(&mut self, demand: ConfigDemand) {
        let answer = match revert_and_report(&mut self.store, &self.sink) {
            ProvisionalReport::Reverted {
                image, generation, ..
            } => {
                self.submissions.reverted = self.submissions.reverted.saturating_add(1);
                self.generation = image.generation;
                self.offer(&image);
                ConfigAnswer::RolledBack { generation }
            }
            ProvisionalReport::NotProvisional { generation } => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::NotProvisional { generation }
            }
            // Neither is reachable from a revert: `revert_and_report` names no
            // generation to match and confirms nothing. Answered rather than
            // asserted.
            ProvisionalReport::Confirmed { generation }
            | ProvisionalReport::GenerationMismatch {
                provisional: generation,
            } => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                ConfigAnswer::NotProvisional { generation }
            }
        };
        self.channel.answer(demand, answer);
    }

    /// Hand `image` to the forwarding domain and wake it.
    ///
    /// A stale offer is unreachable — the generation a commit or a revert assigns
    /// is strictly newer than any this publisher has offered — and is reported
    /// rather than dropped, a generation nobody was offered being one nobody
    /// runs.
    fn offer(&mut self, image: &wire::ConfigImage) {
        if self.publisher.offer(self.handover, image).is_ok() {
            CONSUMER.notify();
        } else {
            announce(&self.sink, DomainState::Refused);
        }
    }

    /// Stage, validate and commit the submitted document, then answer with what
    /// that did.
    ///
    /// The bytes are **copied out of the region first**, and that is not a
    /// convenience: the region is peer-written and may change under a reader, so a
    /// document decided on in place is a document that was never one byte string.
    fn submit(&mut self, demand: ConfigDemand) {
        let Self {
            responder,
            document,
            ..
        } = self;
        let taken = responder.document(&demand, document);
        // Everything below decides on `taken`, which is this domain's own copy.
        let report = config::commit_and_report(&mut self.store, taken, &self.sink);
        match report {
            CommitReport::Published { image, changes } => {
                self.submissions.applied = self.submissions.applied.saturating_add(1);
                self.generation = image.generation;
                // Offered before the submitter is answered, so a client that
                // scrapes the moment it is told cannot see the commit and miss the
                // offer. A stale offer is unreachable — the generation this commit
                // assigned is strictly newer than any this publisher has offered —
                // and is reported rather than dropped, a generation nobody was
                // offered being one nobody runs.
                self.offer(&image);
                self.responder.answer(
                    demand,
                    ConfigAnswer::Applied {
                        generation: image.generation,
                        changes,
                    },
                );
            }
            CommitReport::Unchanged => {
                self.submissions.unchanged = self.submissions.unchanged.saturating_add(1);
                self.responder.answer(
                    demand,
                    ConfigAnswer::Unchanged {
                        generation: self.store.running().to_bits(),
                    },
                );
            }
            CommitReport::Rejected { reason, detail } => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                self.responder.answer(
                    demand,
                    ConfigAnswer::Rejected {
                        generation: self.store.running().to_bits(),
                        // The discriminant is the wire encoding of the reason, as
                        // it is in a log record: the vocabulary is appended to and
                        // never reordered.
                        reason: reason as u32,
                        detail,
                    },
                );
            }
            // The one-step path stages the document it is given, so it reaches
            // neither: a commit here always has a candidate, and a counter with
            // no successor is refused before the document is read. Answered as
            // the exhaustion they amount to rather than asserted, for the reason
            // every other unreachable branch in this domain is.
            CommitReport::Exhausted | CommitReport::NoCandidate => {
                self.submissions.refused = self.submissions.refused.saturating_add(1);
                self.responder.answer(
                    demand,
                    ConfigAnswer::Exhausted {
                        generation: self.store.running().to_bits(),
                    },
                );
            }
        }
        MANAGEMENT.notify();
    }

    /// Answer with the document the appliance is running.
    ///
    /// Rendered from the model rather than echoed from bytes: the submitted bytes
    /// are not kept, and a rendering of what is *in force* is the stronger answer
    /// in any case — it is also the only answer available for the generation this
    /// domain committed at boot, whose document no other domain ever saw.
    ///
    /// The rendering always fits: `config::validate` refuses a configuration whose
    /// canonical form outgrows the document bound, so every model this store holds
    /// is one that can be stated. A failure is answered as an empty document rather
    /// than asserted, for the reason every other unreachable branch here is
    /// counted rather than faulted.
    fn state_running(&mut self, demand: ConfigDemand) {
        let Self {
            responder,
            document,
            store,
            ..
        } = self;
        let len = config::render(store.running_model(), document).unwrap_or(0);
        let generation = store.running().to_bits();
        responder.deliver(demand, generation, document.get(..len).unwrap_or_default());
        self.submissions.reads = self.submissions.reads.saturating_add(1);
        MANAGEMENT.notify();
    }
}

impl Handler for ConfigDomain {
    type Error = Infallible;

    /// A neighbour has said something. Microkit coalesces notifications and a
    /// wakeup names no generation, so every question is asked of the regions
    /// rather than of the wakeup — the two submission ports included, so a
    /// wakeup from one is not a reason to leave the other's request standing.
    ///
    /// The acknowledgement first: releasing a generation the consumer has staged
    /// is what a commit already in flight is waiting on, and a submission that
    /// arrived in the same instant can wait one step.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        if self
            .publisher
            .take_acknowledgement(self.handover, self.ack)
            .is_some()
        {
            CONSUMER.notify();
        }
        self.serve();
        self.serve_channel();
        self.publish();
        Ok(())
    }
}
