#![no_main]
#![no_std]

use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, protection_domain};

const INITIATOR: Channel = Channel::new(0);

#[protection_domain]
fn init() -> Responder {
    Responder
}

struct Responder;

impl Handler for Responder {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        assert!(channels.contains(INITIATOR));
        debug_println!("LIBREFIREWALL_BOOTSTRAP:responder:response");
        INITIATOR.notify();
        Ok(())
    }
}
