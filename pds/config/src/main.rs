#![no_main]
#![no_std]

//! Configuration protection domain: it owns the appliance's configuration
//! document, decides whether that document is one this build can hold, and
//! hands the result to the domain that forwards under it.
//!
//! # Adversary
//!
//! The management-plane attacker (CONCEPT §7.1). The document is compiled in
//! today, which makes the threat theoretical; the reader is written against a
//! fully attacker-controlled byte string anyway, because the document will one
//! day arrive over a network and a parser hardened afterwards is a rewrite.
//!
//! # What this domain holds, and what that leaves it unable to do
//!
//! No device capability, no buffer pool, no dataplane ring: the entire grant is
//! the handover region it writes, the acknowledgement region it reads and its
//! own log ring. A compromised reader reaches no frame and no NIC, and the
//! worst it produces is a configuration — which the consumer re-checks field by
//! field before running (`pd_runtime::handover`).
//!
//! # Nothing is published unless everything passed
//!
//! A document this domain will not accept leaves the handover region untouched,
//! so the consumer stays on generation 0 and the appliance comes up forwarding
//! nothing, visibly. There is deliberately no default configuration behind the
//! document (ENG-12): a fallback would make a typo indistinguishable from a
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
use pd_runtime::{
    ConfigAck, ConfigHandover, ConfigPublisher, MAX_INTERFACES, MAX_NEIGHBOURS, attach_region,
};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};
use wire::{LogConsume, LogRecords};

/// The configuration document this appliance runs, as bytes.
///
/// `env!` rather than a path literal so the build decides which document is
/// shipped, and so a build that decides nothing fails loudly.
const CONFIG_XML: &[u8] = include_bytes!(env!("LIBREFIREWALL_CONFIG_PATH"));

/// The forwarding domain. Unlike the driver channels, this one carries
/// notifications both ways; see the system description on why.
const CONSUMER: Channel = Channel::new(0);

/// Room for every record one commit can produce: every object the handover
/// image holds, in every field a record can name. Sized from the same two
/// constants, so a document the image can carry cannot overrun this buffer.
const MAX_CHANGES: usize = (MAX_INTERFACES + MAX_NEIGHBOURS) * Field::ALL.len();

#[protection_domain]
fn init() -> ConfigDomain {
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let ack: &'static ConfigAck = attach_region!(cfgack_vaddr: ConfigAck);
    let log: &'static LogRecords = attach_region!(log_records_vaddr: LogRecords);
    let log_consume: &'static LogConsume = attach_region!(log_consume_vaddr: LogConsume);
    let sink = RingSink::new(log.writer(log_consume));
    announce(&sink, DomainState::Starting);

    // Both live only as long as this call: a second commit would need the
    // datastore and there is no path to one, so keeping it would leave several
    // kilobytes of model in a domain that reads it again never.
    let mut store = Datastore::new();
    let mut changes = [None::<Change>; MAX_CHANGES];
    let mut publisher = ConfigPublisher::new();

    // Which state each outcome is, and whether there is anything to offer, are
    // decided in `config` where they are host-tested (LAY-2).
    let report = config::commit_and_report(&mut store, CONFIG_XML, &mut changes, &sink);
    if let Some(image) = report.image() {
        publisher.offer(handover, &image);
        CONSUMER.notify();
    }
    announce(&sink, report.state());

    ConfigDomain {
        handover,
        ack,
        publisher,
    }
}

fn announce(sink: &dyn Sink, state: DomainState) {
    sink.emit(&Event::Domain {
        domain: Domain::Config,
        state,
        detail: DomainDetail::None,
    });
}

/// What survives `init`: the two regions and where the offer has got to.
struct ConfigDomain {
    handover: &'static ConfigHandover,
    ack: &'static ConfigAck,
    publisher: ConfigPublisher,
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
        Ok(())
    }
}
