//! The route decision: which station a frame this appliance *originates* is
//! handed to.
//!
//! # Adversary
//!
//! **The management-plane attacker**, one step removed. Nothing here reads a
//! byte off the wire — the inputs are this port's own addressing and a
//! destination the appliance chose — so this is not a parser. What it decides is
//! where the appliance's own outbound traffic goes, which is the same thing a
//! poisoned neighbour entry decides and is why the refusals below are refusals
//! rather than clamps: a next hop nothing on this link can answer for is a
//! resolution that would spend its whole request budget, and a next hop off this
//! port's prefix is one whose answer could only come from a station lying about
//! an address it does not hold.
//!
//! # Two answers, and the second one is the whole of the routing
//!
//! A destination inside the port's own prefix is reached *as itself*: the frame
//! is addressed to the destination's own hardware address. A destination outside
//! it is reached through the port's gateway, and the frame is addressed to the
//! gateway's hardware address while the datagram still names the destination.
//! Both come out of [`next_hop`] as the address to resolve, because that is the
//! only thing the caller does with the answer — the datagram's destination is
//! never the question. Which of the two it was travels with it as a [`Via`],
//! because the address alone cannot say: a next hop equal to the destination
//! and a gateway that happens to be the destination read the same, and the two
//! send an operator to different halves of the configuration.
//!
//! # What this deliberately is not
//!
//! Each of these is a decision with a reason, not an unfinished edge. The whole
//! of what exists is what dialling one address off one addressed port needs.
//!
//! * **No route table, and so no choice of interface.** This appliance's
//!   outbound traffic leaves the port whose domain composed it — the management
//!   domain holds one addressed port and no dataplane one — so the interface is
//!   not selected but given, and a table of one row would be a lookup dressed up
//!   as a decision.
//! * **No metrics and no route preference.** Preference exists to order two
//!   routes to one destination, and there is exactly one here: on-link, or the
//!   gateway.
//! * **No default-route election.** A gateway is stated by the operator or there
//!   is none, and an off-link destination with no gateway is [`Unroutable`]
//!   rather than sent to whichever neighbour was learned first.
//! * **No dynamic routing.** Nothing in this appliance speaks a routing
//!   protocol, and a next hop a peer could advertise is a next hop a peer could
//!   choose.
//!
//! [`Unroutable`]: RouteRefusal::Unroutable

use core::fmt;

use net_headers::{Ipv4Address, MAX_PREFIX_LENGTH};

/// One addressed port, as a route decision sees it.
///
/// Copy, unlike everything else this crate holds per port: it is three values
/// read out of the addressing in force and no state at all, so two copies cannot
/// disagree about anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port {
    /// The port's own address, which is what the prefix is stated against and
    /// what a next hop may not be.
    pub address: Ipv4Address,
    pub prefix_length: u8,
    /// The next hop for everything outside the prefix, or `None` where the
    /// operator stated none — then this port reaches its own link and nothing
    /// else.
    pub gateway: Option<Ipv4Address>,
}

/// Which of the port's two answers a next hop came out of.
///
/// A statement about the *decision* and not about the address, which is why it
/// travels beside one rather than being derived from it: an operator reading
/// that a frame went to the gateway looks at `<management>`'s gateway, and one
/// reading that it went on-link looks at the address and the prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// The destination is inside this port's own prefix and is reached as
    /// itself.
    Prefix,
    /// The destination is outside it, so the frame goes to the port's gateway.
    Gateway,
}

impl Via {
    /// A stable short name, hyphenated: this one *is* a console token, unlike
    /// [`RouteRefusal::name`] beside it, so it is spelled the way the console
    /// spells one.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Gateway => "gateway",
        }
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The station a frame is handed to, and which of the port's two answers chose
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hop {
    /// The address to resolve. Never a datagram field: the datagram names the
    /// destination whichever answer this is.
    pub address: Ipv4Address,
    pub via: Via,
}

/// Why no next hop was chosen.
///
/// Every variant is a statement about this appliance's own configuration or its
/// own choice of destination, never about a frame somebody sent: a route
/// decision has no input a peer supplies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteRefusal {
    /// A destination no frame this end originates may be addressed towards: a
    /// group, a broadcast, the unspecified address, or the loopback block. It is
    /// refused here rather than at the neighbour cache so that the address is
    /// never asked about at all — an ARP request for a broadcast address is a
    /// frame every station on the link answers.
    DestinationNotUnicast,
    /// The destination is this port's own address. Nothing is routed to it: the
    /// appliance answers there, so a frame addressed towards it would be one this
    /// node sent to itself through a link that cannot deliver it.
    DestinationIsOurs,
    /// Off-link, and this port has no gateway. Refused rather than resolved
    /// on-link anyway: a request for an address no station on this link holds is
    /// three requests and a reported unreachable, which reports the wrong fact —
    /// the neighbour is not missing, the route is.
    Unroutable,
    /// A gateway outside this port's own prefix, which no station on this link
    /// can legitimately answer for. It is refused rather than asked about,
    /// because the only answer it could draw is one from a station claiming an
    /// address it does not hold.
    GatewayOffLink,
    /// A gateway no frame may be addressed towards, on
    /// [`DestinationNotUnicast`](Self::DestinationNotUnicast)'s terms.
    GatewayNotUnicast,
    /// A gateway equal to this port's own address, which would route every
    /// off-link datagram back to this node.
    GatewayIsOurs,
    /// A prefix length no address can be judged against. It cannot be reached
    /// through an endpoint, whose constructor refuses one, and is answered rather
    /// than asserted for that reason: a value this crate would have to invent a
    /// panic for is one it can simply refuse.
    PrefixLengthOutOfRange,
}

impl RouteRefusal {
    /// A stable short name, for a metric label or a report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DestinationNotUnicast => "destination_not_unicast",
            Self::DestinationIsOurs => "destination_is_ours",
            Self::Unroutable => "unroutable",
            Self::GatewayOffLink => "gateway_off_link",
            Self::GatewayNotUnicast => "gateway_not_unicast",
            Self::GatewayIsOurs => "gateway_is_ours",
            Self::PrefixLengthOutOfRange => "prefix_length_out_of_range",
        }
    }
}

impl fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The station a datagram for `destination` is handed to, leaving `port`.
///
/// The destination itself where it is on-link, the gateway where it is not, and
/// the answer says which.
///
/// # Errors
/// [`RouteRefusal`], for a destination this end may not address, a destination
/// this port cannot reach at all, or a gateway that could not be a next hop.
pub fn next_hop(port: Port, destination: Ipv4Address) -> Result<Hop, RouteRefusal> {
    if port.prefix_length > MAX_PREFIX_LENGTH {
        return Err(RouteRefusal::PrefixLengthOutOfRange);
    }
    if !destination.is_unicast() {
        return Err(RouteRefusal::DestinationNotUnicast);
    }
    if destination == port.address {
        return Err(RouteRefusal::DestinationIsOurs);
    }
    if destination.shares_prefix(port.address, port.prefix_length) {
        return Ok(Hop {
            address: destination,
            via: Via::Prefix,
        });
    }
    let Some(gateway) = port.gateway else {
        return Err(RouteRefusal::Unroutable);
    };
    // The gateway is judged here rather than where it was configured, and
    // deliberately twice over: a validated document is one guarantee, and this
    // crate composing a frame under an address it never checked is the failure
    // that guarantee is one indirection away from.
    if !gateway.is_unicast() {
        return Err(RouteRefusal::GatewayNotUnicast);
    }
    if gateway == port.address {
        return Err(RouteRefusal::GatewayIsOurs);
    }
    if !gateway.shares_prefix(port.address, port.prefix_length) {
        return Err(RouteRefusal::GatewayOffLink);
    }
    Ok(Hop {
        address: gateway,
        via: Via::Gateway,
    })
}

#[cfg(test)]
mod tests;
