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

use config::{ConfigError, Identifier, Model};
use net_headers::{Ipv4Address, prefix_mask};

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
        let model = config::load(document).map_err(TopologyError::Refused)?;
        Self::from_model(&model)
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
        match (claimed.try_into(), stations.try_into()) {
            (Ok(ports), Ok(endpoints)) => Ok(Self {
                ports,
                endpoints,
                management,
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

    /// Whether `mac` belongs to anything on the bench: an appliance port, the
    /// management port, or a station on one of them.
    pub(crate) fn carries_mac(&self, mac: [u8; 6]) -> bool {
        self.ports.iter().any(|appliance| appliance.mac == mac)
            || self.endpoints.iter().any(|endpoint| endpoint.mac == mac)
            || self.management.mac == mac
    }
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
    Unreadable { path: String, error: String },
    Refused(ConfigError),
    PortBeyondTheBuild { port: usize },
    PortUnclaimed { port: usize },
    PortClaimedTwice { port: usize },
    PortDisabled { port: usize },
    PortWithoutAStation { port: usize },
    PortWithSeveralStations { port: usize },
    NeighbourOnAnUnclaimedPort { id: Identifier },
    NoManagementInterface,
    ManagementDisabled,
    ManagementPrefixHasNoStation { address: [u8; 4] },
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

    fn whole() -> Vec<u8> {
        document(&format!("{INTERFACES}{NEIGHBOURS}{MANAGEMENT}"))
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
                "</neighbours>"
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
        let absent = document(&format!("{INTERFACES}{NEIGHBOURS}"));
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
                "</neighbours>"
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
                "</neighbours>"
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
                "</neighbours>"
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
}
