//! The management port's next hop for everything off its own prefix, and the
//! two things a document may say about it.
//!
//! # Why this sits on `<management>` and not on `<interface>`
//!
//! A gateway is read by exactly one thing: the outbound dial of the port that
//! holds it, deciding which station a frame *this appliance originates* is
//! handed to. The management domain is the only one that originates anything —
//! it holds one addressed port, no dataplane region, no device capability and
//! no I/O port of its own — so it is the only place a gateway has a reader.
//!
//! A gateway beside a dataplane `<interface>` would be a knob nothing in this
//! build can turn: the forwarder chooses an egress from the prefixes it holds
//! and hands the frame to a neighbour it has been told about, never to a next
//! hop of its own, and it originates no traffic to need one. An operator could
//! write such an attribute, an appliance would accept it, and no frame anywhere
//! would go anywhere different — which is the worst kind of configuration
//! surface, because the belief it creates is the thing that is wrong.
//! `<interface>` gains one when the forwarder needs one, and not before.
//!
//! # Why the absence is written
//!
//! A port that reaches only its own link says so in the word `none`, rather
//! than by leaving the attribute out. This is the schema's rule everywhere and
//! it is the same rule here: an omission is indistinguishable from a
//! misspelling, and there is no second channel through which an operator would
//! find out which of the two they wrote.

use lfw_log::{Identifier, Value};
use net_headers::Ipv4Address;

/// The token an absent gateway is written and reported as, mirroring the `any`
/// every wildcard criterion is written as.
///
/// A `const` item, so a literal outside the identifier alphabet would be a
/// build failure rather than a refusal on a path nothing exercises.
pub const NONE: Identifier = match Identifier::new(b"none") {
    Ok(id) => id,
    Err(_) => panic!("the gateway token is not an identifier"),
};

/// What a `<management>` element says its gateway is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gateway {
    /// The port reaches its own link and nothing else.
    None,
    /// The station everything outside the port's prefix is handed to. Whether
    /// it is one this port could reach is [`validate`](crate::validate)'s to
    /// decide; the shape is well formed either way.
    Stated(Ipv4Address),
}

impl Gateway {
    /// The address this states, or `None` for the absent case — which is what a
    /// rule about a gateway iterates, so no rule has to spell the absent arm.
    #[must_use]
    pub const fn stated(self) -> Option<Ipv4Address> {
        match self {
            Self::None => None,
            Self::Stated(address) => Some(address),
        }
    }

    #[must_use]
    pub const fn record(self) -> Value {
        match self {
            Self::None => Value::Selector(NONE),
            Self::Stated(address) => Value::Ipv4(address),
        }
    }

    pub(crate) fn fold(self, hash: u32) -> u32 {
        match self {
            Self::None => crate::hash::fold(hash, &[0]),
            Self::Stated(address) => {
                crate::hash::fold(crate::hash::fold(hash, &[1]), &address.octets())
            }
        }
    }
}
