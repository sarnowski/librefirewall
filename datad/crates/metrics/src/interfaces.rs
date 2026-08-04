//! The identity of each configured interface, as the info family's labels.
//!
//! # Why an info metric at all
//!
//! Every counter family carries `domain`, the protection domain that produced
//! it, and nothing else identifies a port: `domain="nic_driver0"` is the name in
//! the Microkit system description and says nothing about what an operator
//! configured on that port. Joining the two used to need knowledge held nowhere
//! on the node.
//!
//! The conventional answer is an info metric: one constant-valued series per
//! interface, carrying the identity as labels, joined to the counters in the
//! query on the shared `domain` label. It costs one series per interface and
//! leaves counter cardinality untouched — which is the point, because a
//! re-addressed interface must not fork every counter series it has.
//!
//! # The port-to-domain mapping is the one fact no configuration carries
//!
//! [`PORT_DOMAINS`] is the join key's source and is a **cross-artifact fact**,
//! not a value this crate may choose: which protection domain drives which port
//! is fixed in the system description at build time. It is
//! recorded once here, where the `domain` label values already live, so it
//! cannot be spelled two ways — and it is *checked* against the description by
//! `xtask::sysdesc`, the named enforcer of the precondition below.

use wire::{CheckedIdentifier, MAX_INTERFACES};

use crate::catalog::{SHARDS, same};
use crate::sample::PIPELINES;

/// The protection domain driving each dataplane port, indexed by port number.
///
/// **Delegated precondition.** That port *n* is driven by the domain at
/// index *n* is made true by `systems/qemu-x86_64/librefirewall.system`, where
/// the domain named here maps port *n*'s receive pipeline region as its own
/// `rx_fwd_vaddr`. Nothing in a configuration document states it and nothing in
/// this crate can derive it. **Enforced by** `xtask::sysdesc`'s port-driver
/// table, which reads the description back and fails the gate on any
/// disagreement; its test
/// `a_receive_pipeline_driven_by_another_domain_is_reported` proves the check
/// catches one.
pub const PORT_DOMAINS: [&str; PIPELINES] = ["nic_driver0", "nic_driver1"];

/// The domain driving the dedicated management port, on [`PORT_DOMAINS`]' terms
/// and under the same enforcer. It is separate because the management port
/// carries no port number: it is not in the router's set, and no number in a
/// configuration image can put it there.
pub const MANAGEMENT_PORT_DOMAIN: &str = "nic_driver2";

/// The domain driving `port`, or `None` for a port this build has no driver for.
///
/// The only way to obtain the `domain` label of a dataplane interface, so a call
/// site cannot state one — which is what keeps the mapping a single fact rather
/// than a convention each caller keeps.
#[must_use]
pub fn port_domain(port: u8) -> Option<&'static str> {
    PORT_DOMAINS.get(usize::from(port)).copied()
}

/// What a port is for, in the architecture's terms.
///
/// The design makes the role the architectural unit rather than the port number,
/// so it is what a query groups by. The vocabulary is these two today and grows
/// with the design's remaining roles when they exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A port in the router's set, carrying forwarded traffic.
    Dataplane,
    /// The dedicated management port, which carries none.
    Management,
}

impl Role {
    /// The label value, already in this surface's separator convention.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Dataplane => "dataplane",
            Self::Management => "management",
        }
    }

    /// Every role, for a test that walks the vocabulary.
    pub const ALL: [Self; 2] = [Self::Dataplane, Self::Management];
}

/// One configured interface, as the info family renders it.
///
/// Its fields are private and both constructors derive `domain` from the port
/// rather than taking one, so a series cannot be minted under a domain the
/// system description does not drive that port with — the join would then point
/// at another port's counters, which is worse than no join at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    domain: &'static str,
    interface: CheckedIdentifier,
    role: Role,
    address: [u8; 4],
    prefix_length: u8,
    mac: [u8; 6],
}

impl InterfaceInfo {
    /// One dataplane interface, or `None` for a port this build has no driver
    /// for — which a checked configuration image cannot name, its reader having
    /// refused a port past the build's count.
    #[must_use]
    pub fn dataplane(
        port: u8,
        interface: CheckedIdentifier,
        address: [u8; 4],
        prefix_length: u8,
        mac: [u8; 6],
    ) -> Option<Self> {
        Some(Self {
            domain: port_domain(port)?,
            interface,
            role: Role::Dataplane,
            address,
            prefix_length,
            mac,
        })
    }

    /// The management port. Infallible where the dataplane constructor is not:
    /// there is exactly one such port and [`MANAGEMENT_PORT_DOMAIN`] is its
    /// driver, so there is no index to be out of range. Its `interface` label is
    /// the word the `<management>` element has instead of an `id`, which is the
    /// same identity a console record about it carries.
    #[must_use]
    pub const fn management(address: [u8; 4], prefix_length: u8, mac: [u8; 6]) -> Self {
        Self {
            domain: MANAGEMENT_PORT_DOMAIN,
            interface: CheckedIdentifier::MANAGEMENT,
            role: Role::Management,
            address,
            prefix_length,
            mac,
        }
    }

    #[must_use]
    pub const fn domain(&self) -> &'static str {
        self.domain
    }

    #[must_use]
    pub const fn interface(&self) -> CheckedIdentifier {
        self.interface
    }

    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Network order, as the address appears in a header.
    #[must_use]
    pub const fn address(&self) -> [u8; 4] {
        self.address
    }

    #[must_use]
    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    #[must_use]
    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }
}

/// Series the info family can carry, and so the bound on its cardinality: every
/// dataplane interface a configuration image holds, plus the one management
/// interface.
///
/// Under the designed port model this is at most 7 — six dataplane ports and
/// the management one — so the bound the exposition is sized by is well above
/// what the appliance will ever configure.
pub const MAX_INTERFACE_SERIES: usize = MAX_INTERFACES + 1;

/// The inventory is full. Unreachable from a checked configuration image, which
/// holds at most [`MAX_INTERFACES`] interfaces and one management entry; a typed
/// error rather than a silently dropped series all the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryFull;

/// Every configured interface, in the order the exposition emits them.
///
/// A fixed array with `Option` slots filled from the front, so the length is
/// carried by the data and this is `Copy`: a snapshot holds one and the endpoint
/// that renders it owns it outright.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceInventory {
    entries: [Option<InterfaceInfo>; MAX_INTERFACE_SERIES],
}

impl InterfaceInventory {
    /// No interface at all, which is what generation 0 — the fail-closed empty
    /// configuration — describes and what a node that has committed none is in.
    pub const EMPTY: Self = Self {
        entries: [None; MAX_INTERFACE_SERIES],
    };

    /// # Errors
    /// [`InventoryFull`] once [`MAX_INTERFACE_SERIES`] entries are held.
    pub fn push(&mut self, info: InterfaceInfo) -> Result<(), InventoryFull> {
        match self.entries.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(info);
                Ok(())
            }
            None => Err(InventoryFull),
        }
    }

    pub fn entries(&self) -> impl Iterator<Item = &InterfaceInfo> {
        self.entries.iter().flatten()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries().count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InterfaceInventory {
    fn default() -> Self {
        Self::EMPTY
    }
}

// The join key is one word on both sides or the join silently matches nothing,
// so the domain a port's info series carries is held equal to the domain that
// port's driver shard publishes its counters under.
const _: () = {
    assert!(PORT_DOMAINS.len() == PIPELINES);
    // The driver shards sit at 1..=3 in `SHARDS`, the forwarder holding slot 0.
    let mut port = 0;
    while port < PIPELINES {
        assert!(same(PORT_DOMAINS[port], SHARDS[port + 1].domain));
        port += 1;
    }
    assert!(same(MANAGEMENT_PORT_DOMAIN, SHARDS[PIPELINES + 1].domain));
};
