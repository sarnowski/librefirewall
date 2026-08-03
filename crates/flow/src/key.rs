//! A flow's identity: one value for both of its directions, and the number a
//! bucket index is taken from.
//!
//! # Why the identity is orientation-free
//!
//! A packet and its reply are the same flow, and a table that keyed them
//! separately would hold two half-views agreeing about nothing: the reply would
//! open a second flow, the state machine would never see a handshake complete,
//! and every established connection would cost two slots. So the two endpoints
//! are sorted into a canonical pair before the key is formed, which makes the
//! key — and therefore the hash, and therefore the bucket — identical for both
//! orientations. Which orientation a packet travelled in is then a separate
//! answer, taken from the same comparison rather than from a second lookup.
//!
//! The same property is what the multicore dataplane's symmetric receive-side
//! hashing needs later: a hash over an ordered pair steers both directions of a
//! flow to one core, which is the precondition for shared-nothing flow shards.

use net_headers::{Ipv4Address, Protocol};

/// One end of a flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: Ipv4Address,
    /// The transport port, or — for an ICMP echo — the identifier the requester
    /// chose and the responder echoes back, which both ends therefore carry.
    pub port: u16,
}

impl Endpoint {
    #[must_use]
    pub const fn new(address: Ipv4Address, port: u16) -> Self {
        Self { address, port }
    }

    /// The endpoint as one integer, which is what gives the pair a total order.
    ///
    /// Exact rather than a hash: 32 address bits and 16 port bits fit in 48, so
    /// two distinct endpoints never compare equal here.
    const fn ordering_key(self) -> u64 {
        ((self.address.bits() as u64) << 16) | self.port as u64
    }

    const fn precedes_or_equals(self, other: Self) -> bool {
        self.ordering_key() <= other.ordering_key()
    }
}

/// Which orientation of a flow a packet travelled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The orientation the packet that opened the flow travelled in.
    Original,
    Reply,
}

impl Direction {
    #[must_use]
    pub const fn reversed(self) -> Self {
        match self {
            Self::Original => Self::Reply,
            Self::Reply => Self::Original,
        }
    }
}

/// A flow's identity, oriented canonically so a packet and its reply produce the
/// same value bit for bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowKey {
    lower: Endpoint,
    upper: Endpoint,
    protocol: Protocol,
}

impl FlowKey {
    /// The key one packet names, and whether that packet travelled from the
    /// lower endpoint towards the upper one.
    ///
    /// The boolean is the orientation *of this packet*, not of the flow: the
    /// flow's own orientation is whatever its first packet had, which only the
    /// table knows.
    #[must_use]
    pub fn of(source: Endpoint, destination: Endpoint, protocol: Protocol) -> (Self, bool) {
        if source.precedes_or_equals(destination) {
            (
                Self {
                    lower: source,
                    upper: destination,
                    protocol,
                },
                true,
            )
        } else {
            (
                Self {
                    lower: destination,
                    upper: source,
                    protocol,
                },
                false,
            )
        }
    }

    #[must_use]
    pub const fn lower(&self) -> Endpoint {
        self.lower
    }

    #[must_use]
    pub const fn upper(&self) -> Endpoint {
        self.upper
    }

    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The number a bucket index and a bucket tag are both taken from.
    ///
    /// The whole key is exactly two 64-bit words — two 32-bit addresses in one,
    /// two 16-bit ports and the protocol byte in the other — so nothing is
    /// folded away before mixing and two distinct keys differ in the input.
    #[must_use]
    pub const fn hash(&self) -> u64 {
        let addresses =
            ((self.lower.address.bits() as u64) << 32) | self.upper.address.bits() as u64;
        let ports = ((self.lower.port as u64) << 48)
            | ((self.upper.port as u64) << 32)
            | self.protocol.0 as u64;
        avalanche(avalanche(addresses) ^ ports)
    }
}

/// Murmur3's `fmix64` finalizer: a published avalanche step, so every bit of the
/// input reaches the low bits a bucket index is masked out of.
///
/// It is chosen rather than invented because the low bits are the whole output
/// here: a mixer whose avalanche is weak in them puts flows that differ only in
/// a port into one bucket, which is a probe-window exhaustion an ordinary
/// workload reaches by accident.
const fn avalanche(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^= value >> 33;
    value
}

#[cfg(test)]
mod tests;
