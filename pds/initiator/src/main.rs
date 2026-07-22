#![no_main]
#![no_std]

use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, protection_domain};

const RESPONDER: Channel = Channel::new(0);

#[protection_domain]
fn init() -> Initiator {
    debug_println!("LIBREFIREWALL_BOOTSTRAP:initiator:request");
    RESPONDER.notify();
    Initiator
}

struct Initiator;

impl Handler for Initiator {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        assert!(channels.contains(RESPONDER));
        debug_println!("LIBREFIREWALL_BOOTSTRAP_PASS:initiator-responder-notification-round-trip");
        Ok(())
    }
}
