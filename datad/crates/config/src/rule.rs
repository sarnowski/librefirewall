//! The criteria a filter rule matches on, and the tokens a document writes them
//! as.
//!
//! Every criterion is the same shape: a wildcard arm and a stated arm. Nothing
//! here is optional in the document — a rule that matches every source says so
//! by writing `any` — so the wildcard is a value an operator chose rather than
//! an attribute they left out, and a criterion missing from a `<rule>` is a
//! refusal. On a device whose whole job is to decide what may pass, a criterion
//! that widened itself by omission is the one defaulting mistake worth
//! designing the schema around.
//!
//! # Why these types and not the pipeline's
//!
//! What the dataplane matches with is `pipeline`'s own rule value, built from
//! the handover image. These are the document's, and the two are separate for
//! the reason `config::InterfaceEntry` and `routing::Interface` are: an
//! interface criterion here is the *name* an operator wrote, and there it is
//! the port that name resolved to.

use lfw_log::{Identifier, Value};
use net_headers::{Ipv4Address, Protocol};

/// A token this vocabulary mints, checked where it is written.
///
/// Every call below is a `const` item, so a literal outside the identifier
/// alphabet is a build failure rather than a refusal on a path nothing
/// exercises. There is no run-time caller.
const fn token(text: &[u8]) -> Identifier {
    match Identifier::new(text) {
        Ok(id) => id,
        Err(_) => panic!("a criterion token is not an identifier"),
    }
}

/// What every wildcard criterion is written and reported as.
pub const ANY: Identifier = token(b"any");
const TCP: Identifier = token(b"tcp");
const UDP: Identifier = token(b"udp");
const ICMP: Identifier = token(b"icmp");
const OPENING: Identifier = token(b"opening");
const RELATED: Identifier = token(b"related");
const ACCEPT: Identifier = token(b"accept");
const DROP: Identifier = token(b"drop");

/// Which interface a rule is about, on either side of the forwarding decision.
///
/// Named rather than numbered for [`NeighbourEntry`](crate::NeighbourEntry)'s
/// reason: an id survives an operator renumbering ports, and resolving it is a
/// validation step a port number would skip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceMatch {
    Any,
    Named(Identifier),
}

/// Which addresses a rule is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressMatch {
    Any,
    /// A CIDR block. Its host bits are clear, which
    /// [`validate`](crate::validate) is what establishes.
    Block {
        network: Ipv4Address,
        prefix_length: u8,
    },
}

/// Which protocol a rule is about. A number as well as the three names, so a
/// policy can name a protocol this build's parser does not break down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolMatch {
    Any,
    Only(Protocol),
}

/// Which ports a rule is about: one, an inclusive range, or every one of them.
///
/// A single port is a range whose ends are equal rather than an arm of its own,
/// so nothing downstream branches on which of the two the document wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortMatch {
    Any,
    Range { low: u16, high: u16 },
}

/// Which ICMP message types a rule is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpTypeMatch {
    Any,
    Only(u8),
}

/// Which of the two things that reach the filter a rule is about.
///
/// Two stated values and no third, because two are what reach the filter: a
/// conversation opening, and traffic an existing conversation is the reason for
/// without belonging to it. A frame *within* a conversation the appliance already
/// tracks is carried in front of the filter and never asked about, so there is no
/// `established` token — a criterion that offered one would offer a choice an
/// operator does not have, and `validate` refuses the word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackingMatch {
    Any,
    /// A conversation the appliance has not seen before.
    Opening,
    /// Traffic an existing conversation is the reason for without belonging to
    /// it: an ICMP error quoting one of its datagrams, whose source address is
    /// whatever the sender chose.
    Related,
}

/// What a rule does with a frame that matches it.
///
/// Two arms and no third. A `reject` would have to *originate* an ICMP error,
/// and the forwarding domain owns no buffer pool it may allocate from — it
/// forwards what arrived or it does not — so an action it cannot carry out has
/// no representation here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Accept,
    Drop,
}

impl InterfaceMatch {
    /// The interface this criterion names, or `None` for the wildcard — which
    /// is what a resolution step iterates.
    #[must_use]
    pub const fn named(self) -> Option<Identifier> {
        match self {
            Self::Any => None,
            Self::Named(id) => Some(id),
        }
    }

    #[must_use]
    pub const fn record(self) -> Value {
        Value::Selector(match self {
            Self::Any => ANY,
            Self::Named(id) => id,
        })
    }

    pub(crate) fn fold(self, hash: u32) -> u32 {
        match self {
            Self::Any => crate::hash::fold(hash, &[0]),
            Self::Named(id) => crate::hash::fold_identifier(crate::hash::fold(hash, &[1]), id),
        }
    }
}

impl AddressMatch {
    #[must_use]
    pub const fn record(self) -> Value {
        match self {
            Self::Any => Value::Selector(ANY),
            Self::Block {
                network,
                prefix_length,
            } => Value::Prefix {
                network,
                prefix_length,
            },
        }
    }

    pub(crate) fn fold(self, hash: u32) -> u32 {
        match self {
            Self::Any => crate::hash::fold(hash, &[0]),
            Self::Block {
                network,
                prefix_length,
            } => crate::hash::fold(
                crate::hash::fold(hash, &[1, prefix_length]),
                &network.octets(),
            ),
        }
    }
}

impl ProtocolMatch {
    #[must_use]
    pub const fn record(self) -> Value {
        Value::Selector(match self {
            Self::Any => ANY,
            Self::Only(Protocol::TCP) => TCP,
            Self::Only(Protocol::UDP) => UDP,
            Self::Only(Protocol::ICMP) => ICMP,
            Self::Only(Protocol(number)) => Identifier::decimal(number as u16),
        })
    }

    pub(crate) fn fold(self, hash: u32) -> u32 {
        match self {
            Self::Any => crate::hash::fold(hash, &[0]),
            Self::Only(Protocol(number)) => crate::hash::fold(hash, &[1, number]),
        }
    }
}

impl PortMatch {
    #[must_use]
    pub const fn record(self) -> Value {
        Value::Selector(match self {
            Self::Any => ANY,
            Self::Range { low, high } if low == high => Identifier::decimal(low),
            Self::Range { low, high } => Identifier::decimal_range(low, high),
        })
    }

    pub(crate) fn fold(self, hash: u32) -> u32 {
        match self {
            Self::Any => crate::hash::fold(hash, &[0]),
            Self::Range { low, high } => {
                let [low_high, low_low] = low.to_be_bytes();
                let [high_high, high_low] = high.to_be_bytes();
                crate::hash::fold(hash, &[1, low_high, low_low, high_high, high_low])
            }
        }
    }
}

impl IcmpTypeMatch {
    #[must_use]
    pub const fn record(self) -> Value {
        Value::Selector(match self {
            Self::Any => ANY,
            Self::Only(message_type) => Identifier::decimal(message_type as u16),
        })
    }

    pub(crate) fn fold(self, hash: u32) -> u32 {
        match self {
            Self::Any => crate::hash::fold(hash, &[0]),
            Self::Only(message_type) => crate::hash::fold(hash, &[1, message_type]),
        }
    }
}

impl TrackingMatch {
    #[must_use]
    pub const fn record(self) -> Value {
        Value::Selector(match self {
            Self::Any => ANY,
            Self::Opening => OPENING,
            Self::Related => RELATED,
        })
    }

    pub(crate) fn fold(self, hash: u32) -> u32 {
        crate::hash::fold(
            hash,
            &[match self {
                Self::Any => 0,
                Self::Opening => 1,
                Self::Related => 2,
            }],
        )
    }
}

impl RuleAction {
    #[must_use]
    pub const fn record(self) -> Value {
        Value::Selector(match self {
            Self::Accept => ACCEPT,
            Self::Drop => DROP,
        })
    }

    pub(crate) fn fold(self, hash: u32) -> u32 {
        crate::hash::fold(
            hash,
            &[match self {
                Self::Accept => 0,
                Self::Drop => 1,
            }],
        )
    }
}
