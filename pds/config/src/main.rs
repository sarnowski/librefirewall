#![no_main]
#![no_std]

//! Configuration protection domain: it owns the appliance's configuration
//! document, decides whether that document is one this build can hold, and
//! hands the result to the domain that forwards under it.
//!
//! # Adversary
//!
//! The management-plane attacker (CONCEPT §7.1). The document is compiled into
//! this domain today, which makes the threat theoretical; the reader that
//! judges it is written against a fully attacker-controlled byte string anyway,
//! because the reason the reader is isolated in a domain of its own is that the
//! document will one day arrive over a network, and a parser hardened
//! afterwards is a parser rewritten.
//!
//! # What this domain holds, and what that leaves it unable to do
//!
//! No device capability, no buffer pool, no dataplane ring: the entire grant is
//! the handover region it writes and the acknowledgement region it reads. A
//! compromised reader therefore reaches no frame and no NIC, and the worst it
//! can produce is a configuration — which is exactly what the consumer
//! re-checks field by field before running (`pd_runtime::handover`).
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
//! # Why the console `Sink` is written here and not once in `crates/log`
//!
//! Printing needs `sel4_microkit::debug_println`, and everything under
//! `crates/` is deliberately free of Microkit so that it can be host-tested. A
//! backend that prints therefore cannot live there, and each protection domain
//! carries the dozen lines that render an event to its own console.

use config::{Change, Datastore};
use lfw_log::{Domain, DomainDetail, DomainState, Event, Field, MAX_LINE_LEN, Sink, render};
use pd_runtime::{
    ConfigAck, ConfigHandover, ConfigPublisher, MAX_INTERFACES, MAX_NEIGHBOURS, attach_region,
};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, protection_domain};

/// The configuration document this appliance runs, as bytes.
///
/// `env!` rather than a path literal so the build decides which document is
/// shipped, and so a build that decides nothing fails loudly.
const CONFIG_XML: &[u8] = include_bytes!(env!("LIBREFIREWALL_CONFIG_PATH"));

/// The forwarding domain. Unlike the driver channels, this one carries
/// notifications both ways; see the system description on why.
const CONSUMER: Channel = Channel::new(0);

const CONSOLE: Console = Console;

/// Room for every record one commit can produce: every object the handover
/// image holds, in every field a record can name. Sized from the same two
/// constants the image is, so a document the image can carry cannot produce a
/// diff this buffer cannot.
const MAX_CHANGES: usize = (MAX_INTERFACES + MAX_NEIGHBOURS) * Field::ALL.len();

/// The console as a [`Sink`].
///
/// It is the last-resort channel and the only one this build has (CONCEPT §11),
/// so a line that cannot be rendered is reported as the event it came from
/// rather than dropped (ENG-12).
struct Console;

impl Sink for Console {
    fn emit(&self, event: &Event) {
        let mut line = [0u8; MAX_LINE_LEN];
        let rendered = render(event, &mut line)
            .ok()
            .and_then(|written| line.get(..written))
            .and_then(|bytes| core::str::from_utf8(bytes).ok());
        match rendered {
            Some(text) => debug_println!("{text}"),
            None => debug_println!("LFW-PD unrendered={event:?}"),
        }
    }
}

#[protection_domain]
fn init() -> ConfigDomain {
    let handover: &'static ConfigHandover = attach_region!(cfg_vaddr: ConfigHandover);
    let ack: &'static ConfigAck = attach_region!(cfgack_vaddr: ConfigAck);
    announce(DomainState::Starting);

    // Both live only as long as this call: the datastore is what a second
    // commit would need, and there is no path to one. Keeping them would put
    // several kilobytes of model in a domain that reads neither again.
    let mut store = Datastore::new();
    let mut changes = [None::<Change>; MAX_CHANGES];
    let mut publisher = ConfigPublisher::new();

    // Which state each outcome is, and whether there is anything to offer, are
    // both decided in `config` where they are host-tested (LAY-2); the records
    // that say why have already been written by the time this returns.
    let report = config::commit_and_report(&mut store, CONFIG_XML, &mut changes, &CONSOLE);
    if let Some(image) = report.image() {
        publisher.offer(handover, &image);
        CONSUMER.notify();
    }
    announce(report.state());

    ConfigDomain {
        handover,
        ack,
        publisher,
    }
}

fn announce(state: DomainState) {
    CONSOLE.emit(&Event::Domain {
        domain: Domain::Config,
        state,
        detail: DomainDetail::None,
    });
}

/// What survives `init`: the two regions and where the offered generation has
/// got to.
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
