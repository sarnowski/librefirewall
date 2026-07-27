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

use std::{fmt, fs, path::Path};

use config::{ConfigError, Identifier, Model};

/// Dataplane ports the appliance is built with, and so the ports this harness
/// plays a station on. A property of the build — the system description
/// declares a driver instance per port — which is why it is `config`'s constant
/// rather than a count taken from the document.
pub(crate) const PORTS: usize = config::PORT_COUNT as usize;

/// One appliance port as the bench sees it: the MAC QEMU must give the guest
/// NIC, and the subnet the appliance terminates on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AppliancePort {
    mac: [u8; 6],
    address: [u8; 4],
    prefix_length: u8,
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
        match (claimed.try_into(), stations.try_into()) {
            (Ok(ports), Ok(endpoints)) => Ok(Self { ports, endpoints }),
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

    /// Whether any interface prefix covers `address` — which is to say whether
    /// the appliance has a route for it. The harness needs an address it has
    /// none for, and "none" is a property of the document rather than of a
    /// literal somebody once chose.
    pub(crate) fn covers(&self, address: [u8; 4]) -> bool {
        self.ports
            .iter()
            .any(|appliance| same_prefix(appliance.address, address, appliance.prefix_length))
    }

    /// Whether `mac` belongs to an appliance port or to a station on the bench.
    pub(crate) fn carries_mac(&self, mac: [u8; 6]) -> bool {
        self.ports.iter().any(|appliance| appliance.mac == mac)
            || self.endpoints.iter().any(|endpoint| endpoint.mac == mac)
    }
}

/// Whether two addresses share the first `prefix_length` bits.
fn same_prefix(left: [u8; 4], right: [u8; 4], prefix_length: u8) -> bool {
    let mask = match prefix_length {
        0 => 0u32,
        // `config` refuses a prefix length beyond 32, and a shift of exactly 32
        // is undefined for a `u32`; both bounds are handled rather than assumed.
        length if length >= 32 => u32::MAX,
        length => u32::MAX << (32 - length),
    };
    (u32::from_be_bytes(left) & mask) == (u32::from_be_bytes(right) & mask)
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

    const NEIGHBOURS: &str = concat!(
        "<neighbours>",
        "<neighbour id=\"station-a\" interface=\"one\" address=\"10.0.0.2\" ",
        "mac=\"52:54:00:00:00:0a\"/>",
        "<neighbour id=\"station-b\" interface=\"two\" address=\"10.0.1.2\" ",
        "mac=\"52:54:00:00:00:0b\"/>",
        "</neighbours>"
    );

    fn whole() -> Vec<u8> {
        document(&format!("{INTERFACES}{NEIGHBOURS}"))
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
            "{}{}",
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
    fn a_document_the_configuration_domain_refuses_is_refused_here_too() {
        let error = Topology::from_document(b"<!DOCTYPE evil><configuration/>")
            .expect_err("a doctype is refused before anything else");
        assert!(matches!(error, TopologyError::Refused(_)));
        assert!(format!("{error}").contains("doctype"), "{error}");
    }

    #[test]
    fn a_port_no_interface_claims_is_named_rather_than_left_carrying_an_invented_mac() {
        let one_port = document(&format!(
            "{}{}",
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
            "{INTERFACES}{}",
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
            "{INTERFACES}{}",
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
    }
}
