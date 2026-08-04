//! The addressing a QEMU run is stated in, read from the configuration
//! document the image under test was built from.
//!
//! Three artifacts used to hold the same four addresses and four MACs as three
//! separate literals: the document `pds/config` embeds, the `-device mac=` QEMU
//! puts on each guest NIC, and the endpoints [`crate::forward_harness`] states
//! the routed contract between. Nothing compared them, so a document edited
//! alone produced an appliance addressed one way and a test asserting another —
//! and the failure that reported it was every probe timing out with no reason
//! visible.
//!
//! There is now one literal and two derivations. [`Topology::read`] runs the
//! document through [`config::load`] — the same judgement the configuration
//! domain makes at boot — and hands back the MAC each port carries and the
//! station attached to it. A guest NIC can no longer be given a MAC no
//! interface claims, because the MAC comes from the interface; and the contract
//! cannot expect a station the appliance has never been told about, because the
//! station is the document's own `<neighbour>`.
//!
//! # What this refuses that `config` accepts
//!
//! `config` admits up to [`wire::MAX_INTERFACES`] interfaces and any
//! arrangement of neighbours across them. The harness is a two-port bench with
//! exactly one host station on each port, so a document that leaves a port
//! unclaimed, disables one, or attaches two stations to one port describes a
//! bench this harness cannot play. That is refused by name here rather than
//! silently reduced to the first two of something.
//!
//! # The management port is read out of the document too, station and all
//!
//! Its MAC and address are the `<management>` element's, so the guest NIC on it
//! carries a MAC the appliance was configured with exactly as a dataplane port
//! does. Its *station* is the one address on the bench the document does not
//! name — there is no `<neighbour>` for a port that is not in the router's set —
//! so it is DERIVED from the management prefix rather than written down: host 2
//! of that prefix, which is where QEMU's own user-mode stack puts the gateway.
//! A prefix with no room for a second host is refused by name, for the reason
//! every other unplayable bench is.

use std::{fmt, fs, path::Path};

use config::{
    AddressMatch, ConfigError, IcmpTypeMatch, Identifier, InterfaceMatch, Model, PortMatch,
    ProtocolMatch, RuleAction, RuleEntry,
};
use net_headers::{Ipv4Address, Protocol, prefix_mask};

use crate::image::Standing;

/// Dataplane ports the appliance is built with, and so the ports this harness
/// plays a station on. A property of the build — the system description
/// declares a driver instance per port — which is why it is `config`'s constant
/// rather than a count taken from the document.
pub(crate) const PORTS: usize = config::PORT_COUNT as usize;

/// One appliance port as the bench sees it: the MAC QEMU must give the guest
/// NIC, and the subnet the appliance terminates on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AppliancePort {
    /// The `<interface>` id — the identity the document gave this port, which is
    /// what the appliance's own interface info metric must report it under.
    id: Identifier,
    mac: [u8; 6],
    address: [u8; 4],
    prefix_length: u8,
}

/// The management port as the bench sees it: what the appliance answers at, and
/// the station address the harness must speak from to be answered.
///
/// It is not an [`AppliancePort`] plus an [`Endpoint`]: there is no neighbour in
/// the document to make an endpoint of, and no `port` number to index it by. The
/// station is derived here so a bench cannot be stated between an address the
/// appliance would refuse and a port that never claimed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManagementPort {
    pub(crate) mac: [u8; 6],
    pub(crate) address: [u8; 4],
    pub(crate) prefix_length: u8,
    /// Host 2 of the management prefix, which the appliance's own document puts
    /// QEMU's user-mode gateway at.
    pub(crate) station: [u8; 4],
}

impl ManagementPort {
    /// The network this port sits on, which is what QEMU's user-mode stack is
    /// told to serve when a scenario points a real client at the port.
    ///
    /// Derived from the document rather than written beside it, for the reason
    /// every address here is: a bench cannot then be stated on a network the
    /// appliance is not on.
    pub(crate) fn network(&self) -> [u8; 4] {
        (u32::from_be_bytes(self.address) & prefix_mask(self.prefix_length)).to_be_bytes()
    }
}

/// One dataplane interface as the configuration document describes it — the four
/// values the appliance must report back under that interface's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConfiguredInterface {
    pub(crate) id: Identifier,
    pub(crate) address: [u8; 4],
    pub(crate) prefix_length: u8,
    pub(crate) mac: [u8; 6],
}

/// One rule the bench can state a probe against: it names a single UDP
/// destination port and leaves every other criterion open, so exactly the
/// datagrams the harness sends to that port reach its verdict and nothing else
/// about a probe changes which rule decides it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortRule {
    /// The `<rule>` id, which is the label the appliance's own per-rule counter
    /// carries — so a probe and the metric it is checked against name the rule
    /// the same way, and both take the name from the document.
    pub(crate) id: Identifier,
    pub(crate) destination_port: u16,
}

/// The policy a filter contract can be stated against: one rule that accepts a
/// port, one that drops another, and a third port no rule names.
///
/// The three outcomes a default-deny appliance owes an operator, read out of the
/// document rather than written beside the assertion. A document whose rules are
/// any other shape is refused by name: the harness would otherwise have to decide
/// which rule matches a probe, which is the appliance's job and not a thing to
/// have a second implementation of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortPolicy {
    pub(crate) accepted: PortRule,
    pub(crate) denied: PortRule,
    /// A UDP destination port neither rule names, so a datagram to it falls past
    /// both to the default deny — which is not a rule and has no counter.
    pub(crate) unmatched: u16,
}

/// One host station on one dataplane port: the address the harness injects as,
/// and the address a packet routed towards it must be addressed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    /// The `<neighbour>` id, which is what names this endpoint in a verdict.
    id: Identifier,
    pub(crate) port: usize,
    pub(crate) mac: [u8; 6],
    pub(crate) address: [u8; 4],
    /// The MAC of the appliance interface this endpoint's subnet terminates on
    /// — the destination a packet must carry to be routed, and the source it
    /// carries once it has been. Resolved through the neighbour's `interface`
    /// reference, so it is the MAC the appliance was configured with and, by
    /// [`Topology::port_mac`], the MAC QEMU puts on that port.
    pub(crate) gateway_mac: [u8; 6],
}

impl Endpoint {
    pub(crate) fn name(&self) -> &str {
        self.id.as_str()
    }
}

/// The bench one configuration document describes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Topology {
    ports: [AppliancePort; PORTS],
    endpoints: [Endpoint; PORTS],
    management: ManagementPort,
    /// The rules the document declares that are about one UDP destination port
    /// and nothing else, in document order, each with what it does. A rule of any
    /// other shape is *not* here, so a policy this harness cannot state a probe
    /// against reads as the wrong number of rules rather than as a rule that
    /// quietly decides something else.
    rules: Vec<(RuleAction, PortRule)>,
    /// Every rule's id in document order, which is the numbering the dataplane
    /// identifies a rule by. Held separately from `rules` because that vector
    /// drops the rules a port contract cannot be stated against, and a dropped
    /// rule would shift every position behind it.
    rule_ids: Vec<Identifier>,
    /// The document itself, kept because a scenario that *changes* the running
    /// configuration has to state its claims against what the node booted with:
    /// the read it takes back is a rendering of the model in force, so comparing
    /// the two needs the original bytes rather than the bench read out of them.
    document: Vec<u8>,
}

impl Topology {
    /// Read the document at `path` and read the bench out of it.
    ///
    /// # Errors
    /// [`TopologyError`], naming either the rule `config` refused the document
    /// by or the port whose wiring this harness cannot play.
    pub(crate) fn read(path: &Path) -> Result<Self, TopologyError> {
        let document = fs::read(path).map_err(|error| TopologyError::Unreadable {
            path: path.display().to_string(),
            error: error.to_string(),
        })?;
        Self::from_document(&document)
    }

    /// # Errors
    /// [`TopologyError`], as [`Topology::read`].
    pub(crate) fn from_document(document: &[u8]) -> Result<Self, TopologyError> {
        Self::from_document_with(document, Standing::Accepted)
    }

    /// Read the bench out of a document whose [`Standing`] is `standing`.
    ///
    /// The two standings read the same bench by two different paths, and the
    /// difference is which half of `config::load` has to succeed.
    /// [`Standing::Accepted`] needs both: a document the appliance would refuse
    /// describes a bench no contract can be stated against, because the appliance
    /// in the image would never commit it.
    /// [`Standing::RefusedByRule`] needs the *reader* to accept it and a rule to
    /// refuse it — which is exactly the shape that still names its interfaces, its
    /// neighbours and its management port, so the bench is readable while the
    /// policy is not committable.
    ///
    /// The expectation is asserted rather than tolerated in both directions. A
    /// document declared refused that the rules accept yields
    /// [`TopologyError::UnexpectedlyAccepted`], because a scenario built around
    /// "the appliance will not commit this" would otherwise pass while proving the
    /// opposite of what it says.
    ///
    /// # Errors
    /// [`TopologyError`], as [`Topology::read`], plus the mismatch above.
    pub(crate) fn from_document_with(
        document: &[u8],
        standing: Standing,
    ) -> Result<Self, TopologyError> {
        let model = match standing {
            Standing::Accepted => config::load(document).map_err(TopologyError::Refused)?,
            Standing::RefusedByRule => {
                let parsed = config::parse(document)
                    .map_err(|fault| TopologyError::Refused(ConfigError::Document(fault)))?;
                match config::validate(&parsed) {
                    Err(_) => parsed,
                    Ok(()) => return Err(TopologyError::UnexpectedlyAccepted),
                }
            }
        };
        let mut topology = Self::from_model(&model)?;
        topology.document = document.to_vec();
        Ok(topology)
    }

    /// The document this bench was read out of.
    pub(crate) fn document(&self) -> &[u8] {
        &self.document
    }

    fn from_model(model: &Model) -> Result<Self, TopologyError> {
        let mut ports: [Option<(Identifier, AppliancePort)>; PORTS] = [None; PORTS];
        for entry in model.interfaces() {
            let port = usize::from(entry.port);
            // `config` already refused a port beyond the build's count and a
            // second interface on one port, so a slot that is not there or is
            // already taken cannot be reached from a document — but the array
            // is indexed by a number that came out of one, and this is the
            // check that keeps that true rather than assumed.
            let slot = ports
                .get_mut(port)
                .ok_or(TopologyError::PortBeyondTheBuild { port })?;
            if slot.is_some() {
                return Err(TopologyError::PortClaimedTwice { port });
            }
            if !entry.enabled {
                return Err(TopologyError::PortDisabled { port });
            }
            *slot = Some((
                entry.id,
                AppliancePort {
                    id: entry.id,
                    mac: entry.mac.0,
                    address: entry.address.octets(),
                    prefix_length: entry.prefix_length,
                },
            ));
        }

        let mut endpoints: [Option<Endpoint>; PORTS] = [None; PORTS];
        for entry in model.neighbours() {
            // The neighbour's interface reference resolved to a port, which is
            // the whole reason a neighbour names an interface by id: the
            // reference is validated, a port number would not be.
            let (port, appliance) = ports
                .iter()
                .enumerate()
                .find_map(|(port, slot)| match slot {
                    Some((id, appliance)) if *id == entry.interface => Some((port, appliance)),
                    _ => None,
                })
                .ok_or(TopologyError::NeighbourOnAnUnclaimedPort { id: entry.id })?;
            let slot = endpoints
                .get_mut(port)
                .ok_or(TopologyError::PortBeyondTheBuild { port })?;
            if slot.is_some() {
                return Err(TopologyError::PortWithSeveralStations { port });
            }
            *slot = Some(Endpoint {
                id: entry.id,
                port,
                mac: entry.mac.0,
                address: entry.address.octets(),
                gateway_mac: appliance.mac,
            });
        }

        // Collected port by port and only then fixed into arrays: an array of
        // `Endpoint` has no value a caller can write down as a filler — an
        // `Identifier` has no infallible constructor — so building it up and
        // converting at the end is what keeps a placeholder that could survive
        // into a verdict out of the type.
        let mut claimed = Vec::with_capacity(PORTS);
        let mut stations = Vec::with_capacity(PORTS);
        for port in 0..PORTS {
            let (_, appliance) = ports
                .get(port)
                .copied()
                .flatten()
                .ok_or(TopologyError::PortUnclaimed { port })?;
            let endpoint = endpoints
                .get(port)
                .copied()
                .flatten()
                .ok_or(TopologyError::PortWithoutAStation { port })?;
            claimed.push(appliance);
            stations.push(endpoint);
        }
        let management = management_port(model)?;
        let rules = model.rules().filter_map(port_rule).collect();
        let rule_ids = model.rules().map(|entry| entry.id).collect();
        match (claimed.try_into(), stations.try_into()) {
            (Ok(ports), Ok(endpoints)) => Ok(Self {
                ports,
                endpoints,
                management,
                rules,
                rule_ids,
                // Filled by `from_document`, which is the only path a document
                // reaches this from; `from_model` is a test's entry point and has
                // no bytes to give.
                document: Vec::new(),
            }),
            // Unreachable by the loop above, which pushes exactly `PORTS` of
            // each; the conversion is fallible and this is what that costs.
            _ => Err(TopologyError::PortBeyondTheBuild { port: PORTS }),
        }
    }

    /// The MAC QEMU gives the guest NIC on `port` — the appliance interface's
    /// own MAC, so the address the routed contract expects the appliance to
    /// answer to is the address the port carries.
    ///
    /// # Errors
    /// [`TopologyError::PortBeyondTheBuild`] for a port this build has none of.
    pub(crate) fn port_mac(&self, port: usize) -> Result<[u8; 6], TopologyError> {
        self.ports
            .get(port)
            .map(|appliance| appliance.mac)
            .ok_or(TopologyError::PortBeyondTheBuild { port })
    }

    pub(crate) fn endpoints(&self) -> [Endpoint; PORTS] {
        self.endpoints
    }

    /// What the document says each dataplane port *is*, port by port: its id, its
    /// address, its prefix length and its MAC.
    ///
    /// This exists for one caller — [`crate::metrics_contract`], which holds the
    /// appliance's interface info series to it field by field. That comparison is
    /// only worth making against the document, so it is read out of the document
    /// here rather than restated beside the assertion.
    pub(crate) fn interfaces(&self) -> [ConfiguredInterface; PORTS] {
        self.ports.map(|appliance| ConfiguredInterface {
            id: appliance.id,
            address: appliance.address,
            prefix_length: appliance.prefix_length,
            mac: appliance.mac,
        })
    }

    /// The management port, which is not one of [`Topology::endpoints`] and never
    /// will be: the design keeps it out of the dataplane, so no probe crosses
    /// it and no routed contract is stated between it and anything.
    pub(crate) fn management(&self) -> ManagementPort {
        self.management
    }

    /// Whether any interface prefix covers `address` — which is to say whether
    /// the appliance has a route for it. The harness needs an address it has
    /// none for, and "none" is a property of the document rather than of a
    /// literal somebody once chose.
    pub(crate) fn covers(&self, address: [u8; 4]) -> bool {
        self.ports
            .iter()
            .any(|appliance| same_prefix(appliance.address, address, appliance.prefix_length))
    }

    /// The filter policy as a bench can state three outcomes against.
    ///
    /// Nothing here decides which rule matches a frame — that is the appliance's
    /// and there is one implementation of it. What this does is refuse a document
    /// the question is ambiguous for, so that under a document it accepts the
    /// answer is a matter of reading rather than of matching: two rules, each
    /// naming one UDP destination port and every other criterion `any`, one
    /// accepting and one dropping.
    ///
    /// # Errors
    /// [`TopologyError`] for a policy of any other shape.
    /// Every rule the document declares, in document order.
    ///
    /// Order is the whole content: the dataplane identifies a rule by its
    /// **position**, which is its precedence and the slot its hit counter
    /// occupies, and a recording carries that position rather than the id an
    /// operator wrote. This is what joins the two, so a rule named in an
    /// annotation can be held to the counter published under its own id.
    ///
    /// Read from the document rather than from [`Self::port_policy`]'s pair,
    /// which drops any rule that is about more than one UDP destination port and
    /// so cannot be indexed by position.
    #[must_use]
    pub(crate) fn rule_ids(&self) -> &[Identifier] {
        &self.rule_ids
    }

    pub(crate) fn port_policy(&self) -> Result<PortPolicy, TopologyError> {
        let [(first_action, first), (second_action, second)] = self.rules.as_slice() else {
            return Err(TopologyError::PolicyIsNotTwoPortRules {
                rules: self.rules.len(),
            });
        };
        let (accepted, denied) = match (first_action, second_action) {
            (RuleAction::Accept, RuleAction::Drop) => (*first, *second),
            (RuleAction::Drop, RuleAction::Accept) => (*second, *first),
            _ => {
                return Err(TopologyError::PolicyDoesNotAcceptAndDrop);
            }
        };
        if accepted.destination_port == denied.destination_port {
            return Err(TopologyError::PolicyDecidesOnePortTwice {
                port: accepted.destination_port,
            });
        }
        // The lowest port neither rule is about. Searched rather than chosen so
        // it stays a port of *this* document's policy: a literal would silently
        // become one of the named ports the day somebody edited the document.
        let unmatched = (1..=u16::MAX)
            .find(|port| *port != accepted.destination_port && *port != denied.destination_port)
            .ok_or(TopologyError::PolicyLeavesNoUnmatchedPort)?;
        Ok(PortPolicy {
            accepted,
            denied,
            unmatched,
        })
    }

    /// Whether `mac` belongs to anything on the bench: an appliance port, the
    /// management port, or a station on one of them.
    pub(crate) fn carries_mac(&self, mac: [u8; 6]) -> bool {
        self.ports.iter().any(|appliance| appliance.mac == mac)
            || self.endpoints.iter().any(|endpoint| endpoint.mac == mac)
            || self.management.mac == mac
    }
}

/// Read one `<rule>` as a [`PortRule`], or `None` where it is about anything
/// besides one UDP destination port.
///
/// A rule that names an ingress, an address block, a source port or an ICMP type
/// decides some frames and not others for a reason a probe would have to model,
/// so it is dropped here — and dropping it is what makes
/// [`Topology::port_policy`]'s refusal reachable rather than making the rule
/// silently ignorable. `protocol` may be `any` or `udp` because every probe is a
/// UDP datagram: either way the rule is about all of them and none of anything
/// else the bench sends.
fn port_rule(entry: &RuleEntry) -> Option<(RuleAction, PortRule)> {
    let open = matches!(entry.ingress, InterfaceMatch::Any)
        && matches!(entry.egress, InterfaceMatch::Any)
        && matches!(entry.source, AddressMatch::Any)
        && matches!(entry.destination, AddressMatch::Any)
        && matches!(entry.source_port, PortMatch::Any)
        && matches!(entry.icmp_type, IcmpTypeMatch::Any)
        && matches!(
            entry.protocol,
            ProtocolMatch::Any | ProtocolMatch::Only(Protocol::UDP)
        );
    let PortMatch::Range { low, high } = entry.destination_port else {
        return None;
    };
    (open && low == high).then_some((
        entry.action,
        PortRule {
            id: entry.id,
            destination_port: low,
        },
    ))
}

/// Read the `<management>` element as a bench: the port's own addressing, and the
/// station address derived from its prefix.
///
/// # Errors
/// [`TopologyError`] for a document with no management interface, one that is
/// disabled, or one whose prefix has no room for a station beside the appliance.
fn management_port(model: &Model) -> Result<ManagementPort, TopologyError> {
    let Some(entry) = model.management() else {
        return Err(TopologyError::NoManagementInterface);
    };
    if !entry.enabled {
        return Err(TopologyError::ManagementDisabled);
    }
    let address = entry.address.octets();
    let station = management_station(address, entry.prefix_length)
        .ok_or(TopologyError::ManagementPrefixHasNoStation { address })?;
    Ok(ManagementPort {
        mac: entry.mac.0,
        address,
        prefix_length: entry.prefix_length,
        station,
    })
}

/// Host 2 of the prefix `address` sits in, or `None` where that is not a second
/// host address on the same link.
///
/// Host 2 rather than "the next free one" because it is where QEMU's user-mode
/// stack puts its gateway, so an interactive `make run` reaches the port from the
/// same address the harness speaks from. A `/31` or `/32` has no room for the
/// pair, and a management address that IS host 2 would leave the station talking
/// to itself; both are refused rather than nudged to a third value nobody wrote.
fn management_station(address: [u8; 4], prefix_length: u8) -> Option<[u8; 4]> {
    // A `/31` is two addresses and a `/32` is one, so neither holds the pair.
    if prefix_length >= 31 {
        return None;
    }
    let station = (u32::from_be_bytes(address) & prefix_mask(prefix_length)) | 2;
    if station == u32::from_be_bytes(address) {
        return None;
    }
    Some(station.to_be_bytes())
}

/// Whether two addresses share the first `prefix_length` bits, decided by the
/// appliance's own mask rather than by a second copy of it here.
fn same_prefix(left: [u8; 4], right: [u8; 4], prefix_length: u8) -> bool {
    Ipv4Address::from_octets(left).shares_prefix(Ipv4Address::from_octets(right), prefix_length)
}

/// Why a document does not describe a bench this harness can play.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TopologyError {
    Unreadable {
        path: String,
        error: String,
    },
    Refused(ConfigError),
    /// A document declared to be one the appliance refuses that every rule
    /// accepts. Carries nothing: what is wrong is the absence of a refusal, and
    /// there is no value to name.
    UnexpectedlyAccepted,
    PortBeyondTheBuild {
        port: usize,
    },
    PortUnclaimed {
        port: usize,
    },
    PortClaimedTwice {
        port: usize,
    },
    PortDisabled {
        port: usize,
    },
    PortWithoutAStation {
        port: usize,
    },
    PortWithSeveralStations {
        port: usize,
    },
    NeighbourOnAnUnclaimedPort {
        id: Identifier,
    },
    NoManagementInterface,
    ManagementDisabled,
    ManagementPrefixHasNoStation {
        address: [u8; 4],
    },
    PolicyIsNotTwoPortRules {
        rules: usize,
    },
    PolicyDoesNotAcceptAndDrop,
    PolicyDecidesOnePortTwice {
        port: u16,
    },
    PolicyLeavesNoUnmatchedPort,
}

impl fmt::Display for TopologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, error } => {
                write!(f, "read the configuration document {path}: {error}")
            }
            Self::Refused(error) => write!(
                f,
                "the configuration domain would refuse this document: {}",
                error.reason().name()
            ),
            Self::UnexpectedlyAccepted => f.write_str(
                "this document is declared to be one the appliance refuses and every rule \
                 accepts it, so a scenario built around its refusal would prove the opposite of \
                 what it says while passing",
            ),
            Self::PortBeyondTheBuild { port } => write!(
                f,
                "port {port} is past the {PORTS} this build has dataplane drivers for"
            ),
            Self::PortUnclaimed { port } => write!(
                f,
                "no interface claims port {port}, so the guest NIC on it would carry a MAC \
                 the appliance has never been told about"
            ),
            Self::PortClaimedTwice { port } => {
                write!(f, "two interfaces claim port {port}")
            }
            Self::PortDisabled { port } => write!(
                f,
                "the interface on port {port} is disabled, so the appliance would refuse \
                 every frame the bench puts on it"
            ),
            Self::PortWithoutAStation { port } => write!(
                f,
                "no neighbour is attached to port {port}, so there is no station for the \
                 routed contract to be stated between"
            ),
            Self::PortWithSeveralStations { port } => write!(
                f,
                "two neighbours are attached to port {port}; the bench plays one station per port"
            ),
            Self::NeighbourOnAnUnclaimedPort { id } => write!(
                f,
                "neighbour {:?} names an interface that claims no port of this build",
                id.as_str()
            ),
            Self::NoManagementInterface => f.write_str(
                "the document has no <management> element, so the guest NIC on the management \
                 port would carry a MAC the appliance has never been told about",
            ),
            Self::ManagementDisabled => f.write_str(
                "the management interface is disabled, so the appliance would answer nothing \
                 the bench puts on that port",
            ),
            Self::ManagementPrefixHasNoStation { address } => {
                let [a, b, c, d] = address;
                write!(
                    f,
                    "the management prefix around {a}.{b}.{c}.{d} has no room for a station \
                     beside the appliance, so there is nobody for the endpoint to answer"
                )
            }
            Self::PolicyIsNotTwoPortRules { rules } => write!(
                f,
                "{rules} of the document's rules name one UDP destination port and every other \
                 criterion `any`, and a filter contract is stated against exactly two — one \
                 accepting and one dropping. A rule of any other shape decides some frames and \
                 not others for a reason a probe would have to model, and which rule matches a \
                 frame is the appliance's to answer"
            ),
            Self::PolicyDoesNotAcceptAndDrop => f.write_str(
                "both of the document's port rules take the same action, so two of the three \
                 outcomes a filter contract is stated over cannot be told apart",
            ),
            Self::PolicyDecidesOnePortTwice { port } => write!(
                f,
                "both of the document's port rules name destination port {port}, so only the \
                 first of them can ever match and the second's verdict is unobservable"
            ),
            Self::PolicyLeavesNoUnmatchedPort => f.write_str(
                "every UDP destination port is named by a rule, so no datagram would reach the \
                 default deny",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-port document of the shape the appliance ships with, with every
    /// field a test wants to move left as a substitution target.
    fn document(body: &str) -> Vec<u8> {
        format!("<configuration>{body}</configuration>").into_bytes()
    }

    const INTERFACES: &str = concat!(
        "<interfaces>",
        "<interface id=\"one\" port=\"0\" enabled=\"true\" mac=\"52:54:00:12:34:50\" ",
        "address=\"10.0.0.1\" prefix-length=\"24\"/>",
        "<interface id=\"two\" port=\"1\" enabled=\"true\" mac=\"52:54:00:12:34:51\" ",
        "address=\"10.0.1.1\" prefix-length=\"24\"/>",
        "</interfaces>"
    );

    /// The management element the bench documents carry, on a prefix neither
    /// interface claims and with room for a station at host 2.
    const MANAGEMENT: &str = concat!(
        "<management mac=\"52:54:00:12:34:52\" address=\"10.0.2.15\" ",
        "prefix-length=\"24\" enabled=\"true\"/>"
    );

    const NEIGHBOURS: &str = concat!(
        "<neighbours>",
        "<neighbour id=\"station-a\" interface=\"one\" address=\"10.0.0.2\" ",
        "mac=\"52:54:00:00:00:0a\"/>",
        "<neighbour id=\"station-b\" interface=\"two\" address=\"10.0.1.2\" ",
        "mac=\"52:54:00:00:00:0b\"/>",
        "</neighbours>"
    );

    /// The empty policy every bench document here carries but the ones written to
    /// exercise [`Topology::port_policy`]. The element is required, and an empty
    /// one forwards nothing — which is fine for a document nothing boots.
    const NO_RULES: &str = "<rules/>";

    fn whole() -> Vec<u8> {
        document(&format!("{INTERFACES}{NEIGHBOURS}{NO_RULES}{MANAGEMENT}"))
    }

    #[test]
    fn every_address_the_bench_uses_comes_out_of_the_document() {
        let topology = Topology::from_document(&whole()).expect("a two-port bench");
        assert_eq!(
            topology.port_mac(0),
            Ok([0x52, 0x54, 0x00, 0x12, 0x34, 0x50])
        );
        assert_eq!(
            topology.port_mac(1),
            Ok([0x52, 0x54, 0x00, 0x12, 0x34, 0x51])
        );

        let [a, b] = topology.endpoints();
        assert_eq!(a.name(), "station-a");
        assert_eq!(a.port, 0);
        assert_eq!(a.address, [10, 0, 0, 2]);
        assert_eq!(a.mac, [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a]);
        assert_eq!(b.name(), "station-b");
        assert_eq!(b.port, 1);
        assert_eq!(b.address, [10, 0, 1, 2]);
    }

    /// The cross-artifact fact this module exists to close: an endpoint's
    /// gateway MAC is the MAC of the interface its own neighbour entry names,
    /// and that is the MAC QEMU is told to put on the port.
    #[test]
    fn an_endpoints_gateway_mac_is_the_mac_its_port_carries() {
        let topology = Topology::from_document(&whole()).expect("a two-port bench");
        for endpoint in topology.endpoints() {
            assert_eq!(
                Ok(endpoint.gateway_mac),
                topology.port_mac(endpoint.port),
                "endpoint {} expects a MAC its port does not carry",
                endpoint.name()
            );
            assert_ne!(endpoint.gateway_mac, endpoint.mac);
        }
    }

    /// Reordering the document changes nothing: the bench is keyed by port and
    /// by the neighbour's interface reference, never by document position. A
    /// harness that read the first element as port 0 would pass every other
    /// test here and route backwards under a document somebody tidied.
    #[test]
    fn the_bench_is_the_same_whichever_order_the_document_is_written_in() {
        let reversed = document(&format!(
            "{MANAGEMENT}{}{}",
            concat!(
                "<interfaces>",
                "<interface id=\"two\" port=\"1\" enabled=\"true\" mac=\"52:54:00:12:34:51\" ",
                "address=\"10.0.1.1\" prefix-length=\"24\"/>",
                "<interface id=\"one\" port=\"0\" enabled=\"true\" mac=\"52:54:00:12:34:50\" ",
                "address=\"10.0.0.1\" prefix-length=\"24\"/>",
                "</interfaces>"
            ),
            concat!(
                "<neighbours>",
                "<neighbour id=\"station-b\" interface=\"two\" address=\"10.0.1.2\" ",
                "mac=\"52:54:00:00:00:0b\"/>",
                "<neighbour id=\"station-a\" interface=\"one\" address=\"10.0.0.2\" ",
                "mac=\"52:54:00:00:00:0a\"/>",
                "</neighbours><rules/>"
            )
        ));
        let straight = Topology::from_document(&whole()).expect("a two-port bench");
        let other = Topology::from_document(&reversed).expect("a two-port bench");
        for port in 0..PORTS {
            assert_eq!(straight.port_mac(port), other.port_mac(port));
        }
        let [left, right] = other.endpoints();
        assert_eq!((left.name(), left.port), ("station-a", 0));
        assert_eq!((right.name(), right.port), ("station-b", 1));
    }

    #[test]
    fn the_management_port_and_its_station_come_out_of_the_document() {
        let management = Topology::from_document(&whole())
            .expect("a two-port bench")
            .management();
        assert_eq!(management.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
        assert_eq!(management.address, [10, 0, 2, 15]);
        assert_eq!(management.prefix_length, 24);
        assert_eq!(
            management.station,
            [10, 0, 2, 2],
            "host 2 of the prefix, where QEMU's own user-mode gateway sits"
        );
    }

    /// The management port is not one of the dataplane ports, and nothing about
    /// the bench may confuse the two: its MAC belongs to nothing else, and no
    /// endpoint the routed contract is stated between sits on its prefix.
    #[test]
    fn the_management_port_shares_nothing_with_the_dataplane() {
        let topology = Topology::from_document(&whole()).expect("a two-port bench");
        let management = topology.management();
        for port in 0..PORTS {
            assert_ne!(topology.port_mac(port), Ok(management.mac));
        }
        for endpoint in topology.endpoints() {
            assert_ne!(endpoint.mac, management.mac);
            assert_ne!(endpoint.address, management.address);
        }
        assert!(
            !topology.covers(management.address),
            "a dataplane prefix covering the management address would make one \
             address reachable two ways"
        );
        assert!(!topology.covers(management.station));
        // It is nevertheless on the bench, so a probe addressed to it is not
        // addressed to nobody.
        assert!(topology.carries_mac(management.mac));
    }

    #[test]
    fn a_document_with_no_management_interface_or_a_disabled_one_is_refused() {
        let absent = document(&format!("{INTERFACES}{NEIGHBOURS}{NO_RULES}"));
        // `config` refuses it first: the element is required by the schema.
        assert!(matches!(
            Topology::from_document(&absent),
            Err(TopologyError::Refused(_))
        ));

        let text = String::from_utf8(whole()).expect("ASCII");
        let disabled = text.replacen(
            "prefix-length=\"24\" enabled=\"true\"/>",
            "prefix-length=\"24\" enabled=\"false\"/>",
            1,
        );
        let error = Topology::from_document(disabled.as_bytes())
            .expect_err("an unaddressed management port answers nothing");
        assert_eq!(error, TopologyError::ManagementDisabled);
        assert!(format!("{error}").contains("answer nothing"), "{error}");
    }

    /// A prefix with no second host has nobody for the endpoint to answer, and
    /// the bench says so rather than inventing an address off the link.
    #[test]
    fn a_management_prefix_with_no_room_for_a_station_is_refused() {
        let text = String::from_utf8(whole()).expect("ASCII");
        for (prefix_length, address) in [(31u8, "10.0.2.15"), (32, "10.0.2.15")] {
            let narrow = text.replacen(
                "address=\"10.0.2.15\" prefix-length=\"24\" enabled=\"true\"",
                &format!(
                    "address=\"{address}\" prefix-length=\"{prefix_length}\" enabled=\"true\""
                ),
                1,
            );
            let error =
                Topology::from_document(narrow.as_bytes()).expect_err("no room for a station");
            assert_eq!(
                error,
                TopologyError::ManagementPrefixHasNoStation {
                    address: [10, 0, 2, 15],
                }
            );
        }
        // And an appliance sitting *on* host 2 leaves the station talking to
        // itself, which is refused rather than nudged elsewhere.
        let collides = text.replacen("address=\"10.0.2.15\"", "address=\"10.0.2.2\"", 1);
        assert_eq!(
            Topology::from_document(collides.as_bytes()),
            Err(TopologyError::ManagementPrefixHasNoStation {
                address: [10, 0, 2, 2],
            })
        );
    }

    #[test]
    fn a_station_is_derived_only_where_the_prefix_holds_one() {
        assert_eq!(management_station([10, 0, 2, 15], 24), Some([10, 0, 2, 2]));
        assert_eq!(management_station([10, 0, 2, 15], 16), Some([10, 0, 0, 2]));
        assert_eq!(management_station([10, 0, 2, 15], 0), Some([0, 0, 0, 2]));
        assert_eq!(management_station([10, 0, 2, 2], 24), None);
        assert_eq!(management_station([10, 0, 2, 15], 31), None);
        assert_eq!(management_station([10, 0, 2, 15], 32), None);
        assert_eq!(management_station([10, 0, 2, 15], 255), None);
    }

    #[test]
    fn a_document_the_configuration_domain_refuses_is_refused_here_too() {
        let error = Topology::from_document(b"<!DOCTYPE evil><configuration/>")
            .expect_err("a doctype is refused before anything else");
        assert!(matches!(error, TopologyError::Refused(_)));
        assert!(format!("{error}").contains("doctype"), "{error}");
    }

    #[test]
    fn a_port_no_interface_claims_is_named_rather_than_left_carrying_an_invented_mac() {
        let one_port = document(&format!(
            "{}{}{MANAGEMENT}",
            concat!(
                "<interfaces>",
                "<interface id=\"one\" port=\"0\" enabled=\"true\" mac=\"52:54:00:12:34:50\" ",
                "address=\"10.0.0.1\" prefix-length=\"24\"/>",
                "</interfaces>"
            ),
            concat!(
                "<neighbours>",
                "<neighbour id=\"station-a\" interface=\"one\" address=\"10.0.0.2\" ",
                "mac=\"52:54:00:00:00:0a\"/>",
                "</neighbours><rules/>"
            )
        ));
        let error = Topology::from_document(&one_port).expect_err("port 1 is unclaimed");
        assert_eq!(error, TopologyError::PortUnclaimed { port: 1 });
        assert!(format!("{error}").contains("port 1"), "{error}");
    }

    #[test]
    fn a_port_with_no_station_leaves_the_contract_nothing_to_be_stated_between() {
        let one_station = document(&format!(
            "{INTERFACES}{}{MANAGEMENT}",
            concat!(
                "<neighbours>",
                "<neighbour id=\"station-a\" interface=\"one\" address=\"10.0.0.2\" ",
                "mac=\"52:54:00:00:00:0a\"/>",
                "</neighbours><rules/>"
            )
        ));
        assert_eq!(
            Topology::from_document(&one_station),
            Err(TopologyError::PortWithoutAStation { port: 1 })
        );
    }

    #[test]
    fn a_second_station_on_one_port_is_refused_rather_than_reduced_to_the_first() {
        let crowded = document(&format!(
            "{INTERFACES}{}{MANAGEMENT}",
            concat!(
                "<neighbours>",
                "<neighbour id=\"station-a\" interface=\"one\" address=\"10.0.0.2\" ",
                "mac=\"52:54:00:00:00:0a\"/>",
                "<neighbour id=\"station-c\" interface=\"one\" address=\"10.0.0.3\" ",
                "mac=\"52:54:00:00:00:0c\"/>",
                "<neighbour id=\"station-b\" interface=\"two\" address=\"10.0.1.2\" ",
                "mac=\"52:54:00:00:00:0b\"/>",
                "</neighbours><rules/>"
            )
        ));
        assert_eq!(
            Topology::from_document(&crowded),
            Err(TopologyError::PortWithSeveralStations { port: 0 })
        );
    }

    #[test]
    fn a_disabled_port_is_refused_because_the_appliance_would_refuse_every_frame_on_it() {
        let down = whole();
        let text = String::from_utf8(down).expect("ASCII");
        let down = text.replacen(
            "id=\"two\" port=\"1\" enabled=\"true\"",
            "id=\"two\" port=\"1\" enabled=\"false\"",
            1,
        );
        assert_eq!(
            Topology::from_document(down.as_bytes()),
            Err(TopologyError::PortDisabled { port: 1 })
        );
    }

    #[test]
    fn coverage_answers_which_addresses_the_appliance_has_a_route_for() {
        let topology = Topology::from_document(&whole()).expect("a two-port bench");
        assert!(topology.covers([10, 0, 0, 2]));
        assert!(topology.covers([10, 0, 1, 254]));
        assert!(!topology.covers([192, 0, 2, 9]));
        assert!(!topology.covers([10, 0, 2, 1]));
    }

    #[test]
    fn a_mac_is_recognised_as_the_benchs_only_when_something_on_it_carries_that_mac() {
        let topology = Topology::from_document(&whole()).expect("a two-port bench");
        assert!(topology.carries_mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x50]));
        assert!(topology.carries_mac([0x52, 0x54, 0x00, 0x00, 0x00, 0x0b]));
        assert!(!topology.carries_mac([0x52, 0x54, 0x00, 0x99, 0x99, 0x99]));
    }

    #[test]
    fn a_prefix_mask_is_right_at_both_ends_of_its_range() {
        // A /0 covers everything and a /32 covers one address; the shift that
        // computes the mask is undefined at one of those two widths, so both
        // are pinned rather than reasoned about.
        assert!(same_prefix([1, 2, 3, 4], [255, 254, 253, 252], 0));
        assert!(same_prefix([1, 2, 3, 4], [1, 2, 3, 4], 32));
        assert!(!same_prefix([1, 2, 3, 4], [1, 2, 3, 5], 32));
        assert!(same_prefix([10, 0, 0, 1], [10, 0, 0, 254], 24));
        assert!(!same_prefix([10, 0, 0, 1], [10, 0, 1, 1], 24));
        assert!(same_prefix([10, 0, 0, 1], [10, 0, 1, 1], 16));
    }

    #[test]
    fn the_unreadable_case_names_the_path_and_the_reason() {
        let error =
            Topology::read(Path::new("/nonexistent/librefirewall/configuration.xml")).unwrap_err();
        let rendered = format!("{error}");
        assert!(rendered.contains("configuration.xml"), "{rendered}");
        assert!(matches!(error, TopologyError::Unreadable { .. }));
    }

    /// Both documents the build ships are benches this harness can play. They
    /// are what scenarios 1 and 3 are stated against, and a document that
    /// stopped being readable here would otherwise surface as a QEMU timeout.
    #[test]
    fn every_document_the_build_ships_describes_a_playable_bench() {
        for document in [
            include_bytes!("../../../systems/qemu-x86_64/configuration.xml").as_slice(),
            include_bytes!("../scenarios/alternate-addressing.xml").as_slice(),
        ] {
            let topology =
                Topology::from_document(document).expect("a shipped document is a bench");
            let [a, b] = topology.endpoints();
            assert_ne!(a.address, b.address);
            assert_ne!(a.mac, b.mac);
            assert_ne!(topology.port_mac(0), topology.port_mac(1));
            // And a management port that answers, on a prefix neither dataplane
            // port routes into.
            let management = topology.management();
            assert!(!topology.covers(management.address));
            assert_ne!(management.station, management.address);
        }
    }

    /// The point of the second document: it must agree with the first about
    /// nothing at all, or scenario 3 could pass on a stale table.
    #[test]
    fn the_alternate_document_shares_no_address_and_no_mac_with_the_shipped_one() {
        let shipped = Topology::from_document(include_bytes!(
            "../../../systems/qemu-x86_64/configuration.xml"
        ))
        .expect("the shipped document");
        let alternate =
            Topology::from_document(include_bytes!("../scenarios/alternate-addressing.xml"))
                .expect("the alternate document");

        for port in 0..PORTS {
            assert_ne!(shipped.port_mac(port), alternate.port_mac(port));
        }
        for endpoint in alternate.endpoints() {
            assert!(!shipped.covers(endpoint.address), "{}", endpoint.name());
            assert!(!shipped.carries_mac(endpoint.mac), "{}", endpoint.name());
            assert!(!shipped.carries_mac(endpoint.gateway_mac));
        }
        for endpoint in shipped.endpoints() {
            assert!(!alternate.covers(endpoint.address), "{}", endpoint.name());
            assert!(!alternate.carries_mac(endpoint.mac), "{}", endpoint.name());
        }
        // Including the management port: scenario 3 proves the endpoint answers
        // under the addressing it was configured with, which needs both
        // documents to disagree about every value it uses.
        assert_ne!(shipped.management().mac, alternate.management().mac);
        assert_ne!(shipped.management().address, alternate.management().address);
        assert_ne!(shipped.management().station, alternate.management().station);
        assert!(!shipped.carries_mac(alternate.management().mac));
        assert!(!alternate.carries_mac(shipped.management().mac));
    }

    /// A `<rules>` section of the shape a filter contract is stated against: one
    /// accepting and one dropping rule, each about a single UDP destination port.
    fn rules(accept: u16, drop: u16) -> String {
        format!(
            concat!(
                "<rules>",
                "<rule id=\"blocked\" ingress=\"any\" egress=\"any\" source=\"any\" ",
                "destination=\"any\" protocol=\"udp\" source-port=\"any\" ",
                "destination-port=\"{drop}\" icmp-type=\"any\" tracking=\"any\" action=\"drop\"/>",
                "<rule id=\"allowed\" ingress=\"any\" egress=\"any\" source=\"any\" ",
                "destination=\"any\" protocol=\"udp\" source-port=\"any\" ",
                "destination-port=\"{accept}\" icmp-type=\"any\" tracking=\"opening\" action=\"accept\"/>",
                "</rules>"
            ),
            accept = accept,
            drop = drop
        )
    }

    /// A whole document carrying `policy` where the bench documents carry
    /// `<rules/>`.
    fn with_policy(policy: &str) -> Vec<u8> {
        document(&format!("{INTERFACES}{NEIGHBOURS}{policy}{MANAGEMENT}"))
    }

    /// The shipped document's policy, read as a bench reads it: which port each
    /// rule names, under the id the document gave it, and a port neither names.
    #[test]
    fn the_shipped_policy_reads_as_three_outcomes() {
        let shipped = Topology::from_document(include_bytes!(
            "../../../systems/qemu-x86_64/configuration.xml"
        ))
        .expect("the shipped document");
        let policy = shipped.port_policy().expect("two port rules");
        assert_eq!(policy.accepted.id.as_str(), "probe-forward");
        assert_eq!(policy.accepted.destination_port, 5000);
        assert_eq!(policy.denied.id.as_str(), "probe-blocked");
        assert_eq!(policy.denied.destination_port, 5001);
        // A port neither rule names, searched rather than chosen — so it is a
        // port of *this* policy and cannot silently become one of the two.
        assert_ne!(policy.unmatched, policy.accepted.destination_port);
        assert_ne!(policy.unmatched, policy.denied.destination_port);

        // And the alternate document's, which shares neither id nor port.
        let alternate =
            Topology::from_document(include_bytes!("../scenarios/alternate-addressing.xml"))
                .expect("the alternate document");
        let other = alternate.port_policy().expect("two port rules");
        assert_ne!(policy.accepted.id, other.accepted.id);
        assert_ne!(policy.denied.id, other.denied.id);
    }

    /// A policy of any other shape is refused by name rather than reduced to the
    /// first two of something: which rule matches a frame is the appliance's to
    /// answer, and this harness must not hold a second implementation of it.
    #[test]
    fn a_policy_no_filter_contract_can_be_stated_against_is_refused_by_name() {
        // Too few, and too many.
        for (policy, expected) in [
            ("<rules/>", "0 of the document's rules"),
            (
                &format!(
                    "{}{}",
                    rules(5000, 5001).replace("</rules>", ""),
                    concat!(
                        "<rule id=\"third\" ingress=\"any\" egress=\"any\" source=\"any\" ",
                        "destination=\"any\" protocol=\"udp\" source-port=\"any\" ",
                        "destination-port=\"5002\" icmp-type=\"any\" tracking=\"any\" action=\"drop\"/>",
                        "</rules>"
                    )
                ),
                "3 of the document's rules",
            ),
        ] {
            let topology = Topology::from_document(&with_policy(policy)).expect("a valid document");
            let verdict = topology
                .port_policy()
                .expect_err("a policy of the wrong size")
                .to_string();
            assert!(verdict.contains(expected), "{verdict}");
        }

        // A rule that is about more than a port is not a port rule at all, so a
        // document of two such rules reads as a policy with none.
        let narrowed = rules(5000, 5001).replace("source=\"any\"", "source=\"10.0.0.0/24\"");
        let topology = Topology::from_document(&with_policy(&narrowed)).expect("a valid document");
        let verdict = topology
            .port_policy()
            .expect_err("a rule about an address block as well as a port")
            .to_string();
        assert!(verdict.contains("0 of the document's rules"), "{verdict}");

        // Two rules that take the same action: two of the three outcomes cannot
        // be told apart.
        let both_drop = rules(5000, 5001).replace("action=\"accept\"", "action=\"drop\"");
        let topology = Topology::from_document(&with_policy(&both_drop)).expect("a valid document");
        let verdict = topology
            .port_policy()
            .expect_err("no accepting rule")
            .to_string();
        assert!(verdict.contains("the same action"), "{verdict}");

        // And two rules about one port: the second can never match.
        let one_port = rules(5000, 5000);
        let topology = Topology::from_document(&with_policy(&one_port)).expect("a valid document");
        let verdict = topology
            .port_policy()
            .expect_err("one port decided twice")
            .to_string();
        assert!(verdict.contains("destination port 5000"), "{verdict}");
    }

    /// A port range, a wildcard, and a rule narrowed by any other criterion are
    /// each about something a probe would have to model, so none of them is a port
    /// rule — and a document of one port rule and one of these reads as a policy
    /// with one, which is refused.
    #[test]
    fn only_a_rule_about_exactly_one_udp_port_is_a_port_rule() {
        /// One `<rule>` with every criterion at its widest but for the
        /// substitutions in `narrowed`, which are written out as attributes.
        fn rule(id: &str, action: &str, narrowed: &[(&str, &str)]) -> String {
            let mut attributes = vec![
                ("ingress", "any"),
                ("egress", "any"),
                ("source", "any"),
                ("destination", "any"),
                ("protocol", "udp"),
                ("source-port", "any"),
                ("destination-port", "5000"),
                ("icmp-type", "any"),
                ("tracking", "any"),
            ];
            for (name, value) in narrowed {
                for attribute in &mut attributes {
                    if attribute.0 == *name {
                        attribute.1 = value;
                    }
                }
            }
            let written: Vec<String> = attributes
                .iter()
                .map(|(name, value)| format!("{name}=\"{value}\""))
                .collect();
            format!(
                "<rule id=\"{id}\" {} action=\"{action}\"/>",
                written.join(" ")
            )
        }

        // The accepting rule stays a port rule throughout, so what the verdict
        // counts is exactly the number of *other* rules that qualified.
        let accepting = rule("allowed", "accept", &[]);
        for narrowed in [
            vec![("destination-port", "5000-5002")],
            vec![("destination-port", "any")],
            vec![("protocol", "tcp")],
            vec![("protocol", "icmp"), ("destination-port", "any")],
            vec![("ingress", "one")],
            vec![("egress", "two")],
            vec![("destination", "10.0.1.0/24")],
            vec![("source", "10.0.0.0/24")],
            vec![("source-port", "4444")],
        ] {
            let policy = format!(
                "<rules>{}{accepting}</rules>",
                rule("blocked", "drop", &narrowed)
            );
            let topology =
                Topology::from_document(&with_policy(&policy)).expect("a valid document");
            let verdict = topology
                .port_policy()
                .expect_err(&format!("{narrowed:?} is not a port rule"))
                .to_string();
            assert!(
                verdict.contains("1 of the document's rules"),
                "{narrowed:?}: {verdict}"
            );
        }

        // The control: the same shape with nothing narrowed is two port rules and
        // reads as a policy, so the refusals above are the criterion's own.
        let policy = format!(
            "<rules>{}{accepting}</rules>",
            rule("blocked", "drop", &[("destination-port", "5001")])
        );
        let topology = Topology::from_document(&with_policy(&policy)).expect("a valid document");
        let read = topology.port_policy().expect("two port rules");
        assert_eq!(read.accepted.destination_port, 5000);
        assert_eq!(read.denied.destination_port, 5001);
    }
}
