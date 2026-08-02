#![no_main]
#![no_std]

//! Configuration protection domain: it owns the appliance's configuration
//! document, decides whether that document is one this build can hold, and
//! hands the result to the domain that forwards under it.
//!
//! # Adversary
//!
//! The management-plane attacker. The document is compiled in
//! today, which makes the threat theoretical; the reader is written against a
//! fully attacker-controlled byte string anyway, because the document will one
//! day arrive over a network and a parser hardened afterwards is a rewrite.
//!
//! # What this domain holds, and what that leaves it unable to do
//!
//! No device capability, no buffer pool, no dataplane ring: the entire grant is
//! the handover region it writes, the acknowledgement region it reads and its
//! own log ring. A compromised reader reaches no frame and no NIC, and the
//! worst it produces is a configuration — which the consumer decides for itself,
//! `wire::ConfigImage::check` holding the image it copies out to every rule this
//! domain's own validator applies, field by field and pair by pair. This domain
//! is the one that parses an attacker's document, so a rule it alone enforced
//! would be a rule a compromise of it lifts.
//!
//! # Nothing is published unless everything passed
//!
//! A document this domain will not accept leaves the handover region untouched,
//! so the consumer stays on generation 0 and the appliance comes up forwarding
//! nothing, visibly. There is deliberately no default configuration behind the
//! document: a fallback would make a typo indistinguishable from a
//! working appliance until traffic went somewhere nobody intended.
//!
//! # The document arrives at build time, or the build fails
//!
//! [`CONFIG_XML`] is `include_bytes!` over an `env!`, so a build with no
//! `LIBREFIREWALL_CONFIG_PATH` fails at compilation rather than producing a
//! domain with an empty or default document. Which file it names is the build's
//! decision and not this domain's.
//!
//! # Records go to a ring, not to `debug_println!`
//!
//! That macro compiles to `seL4_DebugPutChar`, absent from the release kernel,
//! so the refusal above — only safe while visible — would reach nobody in the
//! profile that ships. A typed [`Event`] in this domain's own ring, rendered by
//! the console, works in both.

use config::{Change, Datastore};
use lfw_log::{Domain, DomainDetail, DomainState, Event, Field, RingSink, Sink};
use lfw_metrics::StatsShard;
use pd_runtime::{
    ConfigAck, ConfigHandover, ConfigPublisher, MAX_INTERFACES, MAX_NEIGHBOURS, PdClock,
    attach_region, config_sample, log_sample,
};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{ClockCalibration, LogConsume, LogRecords};

/// The configuration document this appliance runs, as bytes.
///
/// `env!` rather than a path literal so the build decides which document is
/// shipped, and so a build that decides nothing fails loudly.
const CONFIG_XML: &[u8] = include_bytes!(env!("LIBREFIREWALL_CONFIG_PATH"));

/// The forwarding domain. Unlike the driver channels, this one carries
/// notifications both ways; see the system description on why.
const CONSUMER: Channel = Channel::new(0);

/// Room for every record one commit can produce: every object the handover
/// image holds — interfaces, neighbours and the one management interface — in
/// every field a record can name, sized from the image's own constants.
const MAX_CHANGES: usize = (MAX_INTERFACES + MAX_NEIGHBOURS + 1) * Field::ALL.len();

#[protection_domain]
fn init() -> ConfigDomain {
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let ack: &'static ConfigAck = attach_region!(cfgack_vaddr: ConfigAck);
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let stats: &'static StatsShard = attach_region!(stats_vaddr: StatsShard);
    let clock: &'static ClockCalibration = attach_region!(clock_vaddr: ClockCalibration);
    let sink = RingSink::new(log.writer(log_consume), PdClock::new(clock));
    announce(&sink, DomainState::Starting);

    // Both live only as long as this call: a second commit would need the
    // datastore and there is no path to one, so keeping it would leave several
    // kilobytes of model in a domain that reads it again never.
    let mut store = Datastore::new();
    let mut changes = [None::<Change>; MAX_CHANGES];
    let mut publisher = ConfigPublisher::new();

    // Which state each outcome is, and whether there is anything to offer, are
    // decided in `config` where they are host-tested.
    let report = config::commit_and_report(&mut store, CONFIG_XML, &mut changes, &sink);
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
        publisher,
        stats,
        sink,
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

/// What survives `init`: the three regions, where the offer has got to, and the
/// generation this domain committed.
struct ConfigDomain {
    handover: &'static ConfigHandover,
    ack: &'static ConfigAck,
    publisher: ConfigPublisher,
    /// The one region this domain writes its counters into.
    stats: &'static StatsShard,
    /// Kept past `init` because the counters it carries are published on every
    /// activation, not only on the first.
    sink: RingSink<'static, PdClock<'static>>,
    /// The generation committed at boot, and the only one there will ever be:
    /// the document arrives compiled in and this build has no channel to submit
    /// a second one over.
    generation: u32,
}

impl ConfigDomain {
    /// Write what this domain counts into its shard: the generation it
    /// committed, and what its own log ring lost.
    ///
    /// A domain that commits once and then blocks writes a shard that never
    /// moves again, which is correct — its counters do not move either.
    fn publish(&self) {
        let sample = config_sample(
            self.generation,
            log_sample(self.sink.dropped(), self.sink.refused()),
        );
        self.stats.publish(&sample.values());
    }
}

impl Handler for ConfigDomain {
    type Error = Infallible;

    /// The consumer has acknowledged something. Release the offered generation
    /// if that acknowledgement was for it, and tell the consumer it may switch.
    ///
    /// Microkit coalesces notifications and a wakeup names no generation, so
    /// the question is asked from the regions rather than from the wakeup.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        if self
            .publisher
            .take_acknowledgement(self.handover, self.ack)
            .is_some()
        {
            CONSUMER.notify();
        }
        self.publish();
        Ok(())
    }
}
