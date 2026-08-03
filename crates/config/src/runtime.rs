//! What a committed configuration becomes: the handover image the domain that
//! forwards reads it out of. No forwarding table is built here — the domain
//! that routes builds its own from the image it was handed, and a second one
//! built from the model would be a table nothing routes on. Building an image
//! resolves a neighbour's `interface` id to a port, and is fallible because the
//! alternative is a panic reached through a rule enforced in another module.

use lfw_log::Identifier;
use wire::{ConfigImage, IdentifierImage, InterfaceImage, ManagementImage, NeighbourImage};

use crate::{entity::NeighbourEntry, hash::content_hash, model::Model, store::Generation};

/// Why a validated configuration could not be turned into a handover image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A neighbour naming an interface [`validate`](crate::validate) refuses.
    UnresolvedInterface {
        neighbour: Identifier,
        interface: Identifier,
    },
}

/// Build the handover image a consumer reads a configuration out of.
///
/// # Errors
/// [`BuildError::UnresolvedInterface`].
pub fn image_from(model: &Model, generation: Generation) -> Result<ConfigImage, BuildError> {
    let mut image = ConfigImage {
        generation: generation.to_bits(),
        content_hash: content_hash(model).to_bits(),
        management: match model.management() {
            Some(entry) => ManagementImage {
                enabled: u8::from(entry.enabled),
                prefix_length: entry.prefix_length,
                _pad: [0; 2],
                mac: entry.mac.0,
                _pad2: [0; 2],
                address: entry.address.octets(),
            },
            // A configuration describing no management port leaves the zeroed
            // entry, which is what the reader decodes as "no addressing".
            None => ManagementImage::ZERO,
        },
        ..ConfigImage::ZERO
    };

    let mut count = 0u32;
    for (slot, entry) in image.interfaces.iter_mut().zip(model.interfaces()) {
        *slot = InterfaceImage {
            port: entry.port,
            enabled: u8::from(entry.enabled),
            prefix_length: entry.prefix_length,
            _pad: [0; 1],
            mac: entry.mac.0,
            _pad2: [0; 2],
            address: entry.address.octets(),
            id: IdentifierImage::from_text(entry.id.as_bytes()),
        };
        count = count.saturating_add(1);
    }
    image.interface_count = count;

    let mut count = 0u32;
    for (slot, entry) in image.neighbours.iter_mut().zip(model.neighbours()) {
        *slot = NeighbourImage {
            port: port_of(model, entry)?,
            _pad: [0; 3],
            mac: entry.mac.0,
            _pad2: [0; 2],
            address: entry.address.octets(),
        };
        count = count.saturating_add(1);
    }
    image.neighbour_count = count;

    Ok(image)
}

fn port_of(model: &Model, entry: &NeighbourEntry) -> Result<u8, BuildError> {
    model
        .interface(entry.interface)
        .map(|interface| interface.port)
        .ok_or(BuildError::UnresolvedInterface {
            neighbour: entry.id,
            interface: entry.interface,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PORT_COUNT, entity::InterfaceEntry, load, validate};
    use net_headers::{Ipv4Address, MacAddress};
    use proptest::prelude::*;
    use std::{format, string::String};
    use wire::{MAX_INTERFACES, MAX_NEIGHBOURS};

    /// The canonical contract configuration document plus a second interface, so both
    /// ports this build has are named and a neighbour resolves onto one of
    /// them rather than onto the only interface there is.
    const TWO_PORTS: &str = concat!(
        "<configuration><interfaces>",
        "<interface id=\"wan\" port=\"0\" enabled=\"true\" mac=\"52:54:00:12:34:50\" ",
        "address=\"10.0.0.1\" prefix-length=\"24\"/>",
        "<interface id=\"lan\" port=\"1\" enabled=\"false\" mac=\"52:54:00:12:34:51\" ",
        "address=\"10.0.1.1\" prefix-length=\"24\"/>",
        "</interfaces><neighbours>",
        "<neighbour id=\"gateway-a\" interface=\"lan\" address=\"10.0.1.2\" ",
        "mac=\"52:54:00:00:00:0a\"/>",
        "</neighbours>",
        "<management enabled=\"true\" mac=\"52:54:00:12:34:52\" ",
        "address=\"192.168.42.15\" prefix-length=\"24\"/>",
        "</configuration>"
    );

    /// The management element the generated documents below carry, on a prefix
    /// none of their interfaces claims.
    const MANAGEMENT: &str = concat!(
        "<management enabled=\"true\" mac=\"52:54:00:12:34:52\" ",
        "address=\"192.168.42.15\" prefix-length=\"24\"/>"
    );

    fn id(text: &str) -> Identifier {
        Identifier::new(text.as_bytes()).expect("the test uses the identifier alphabet")
    }

    fn model() -> Model {
        load(TWO_PORTS.as_bytes()).expect("the document satisfies every rule")
    }

    #[test]
    fn a_neighbour_takes_the_port_of_the_interface_it_names() {
        let image = image_from(&model(), Generation::ZERO).expect("a validated model builds");
        // The neighbour names `lan`, which sits on port 1 — the resolution the
        // document never states as a number.
        assert_eq!(image.neighbours.first().map(|entry| entry.port), Some(1));
        assert_eq!(image.neighbour_count, 1);
    }

    #[test]
    fn the_management_entry_crosses_into_the_image_and_its_reader_decodes_it() {
        let image = image_from(&model(), Generation::ZERO).expect("a validated model builds");
        assert_eq!(image.management.enabled, 1);
        assert_eq!(image.management.prefix_length, 24);
        assert_eq!(image.management.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
        assert_eq!(image.management.address, [192, 168, 42, 15]);

        let management = image
            .check(PORT_COUNT)
            .expect("its own reader accepts it")
            .management()
            .expect("an enabled entry decodes");
        assert_eq!(management.mac(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
        assert_eq!(management.address(), [192, 168, 42, 15]);
        assert_eq!(management.prefix_length(), 24);
    }

    /// A disabled entry crosses as a zero byte, not as an absent one — and its
    /// reader decodes that as no addressing at all.
    #[test]
    fn a_disabled_management_interface_crosses_as_disabled() {
        let disabled = TWO_PORTS.replacen(
            "<management enabled=\"true\"",
            "<management enabled=\"false\"",
            1,
        );
        let model = load(disabled.as_bytes()).expect("a sound document");
        let image = image_from(&model, Generation::ZERO).expect("it builds");
        assert_eq!(image.management.enabled, 0);
        assert_eq!(image.management.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x52]);
        assert_eq!(
            image
                .check(PORT_COUNT)
                .expect("still a valid image")
                .management(),
            None
        );
    }

    #[test]
    fn the_empty_configuration_builds_an_image_that_forwards_nothing() {
        let image = image_from(&Model::EMPTY, Generation::ZERO).expect("the fail-closed model");
        assert_eq!(image.interface_count, 0);
        assert_eq!(image.neighbour_count, 0);
        assert_eq!(image.generation, 0);
        assert_eq!(image.management, ManagementImage::ZERO);
    }

    #[test]
    fn a_neighbour_whose_interface_is_gone_is_refused_rather_than_guessed_at() {
        // Reachable only by assembling a model directly: validation refuses
        // this document. The builder repeats the check because it must not
        // rest on a rule enforced somewhere else.
        let mut broken = Model::EMPTY;
        broken
            .push_neighbour(crate::NeighbourEntry {
                id: id("gateway-a"),
                interface: id("dmz"),
                address: Ipv4Address::from_octets([10, 0, 0, 2]),
                mac: MacAddress([0x52, 0x54, 0, 0, 0, 0x0a]),
            })
            .expect("capacity");

        let expected = BuildError::UnresolvedInterface {
            neighbour: id("gateway-a"),
            interface: id("dmz"),
        };
        assert_eq!(image_from(&broken, Generation::ZERO), Err(expected));
        assert!(validate(&broken).is_err(), "and validation refuses it too");
    }

    #[test]
    fn an_image_carries_the_generation_and_the_content_hash_it_was_built_under() {
        let model = model();
        let image = image_from(&model, Generation::from_bits(7)).expect("it builds");
        assert_eq!(image.generation, 7);
        assert_eq!(image.content_hash, content_hash(&model).to_bits());
        assert_eq!(image.interface_count, 2);
        assert_eq!(image.neighbour_count, 1);
    }

    #[test]
    fn an_image_lays_each_field_out_where_the_abi_says() {
        let image = image_from(&model(), Generation::ZERO).expect("it builds");
        let wan = image.interfaces.first().expect("a first slot");
        assert_eq!(wan.port, 0);
        assert_eq!(wan.enabled, 1);
        assert_eq!(wan.prefix_length, 24);
        assert_eq!(wan.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x50]);
        assert_eq!(wan.address, [10, 0, 0, 1]);

        let lan = image.interfaces.get(1).expect("a second slot");
        assert_eq!(lan.enabled, 0, "false is a zero byte, not an absent one");

        let gateway = image.neighbours.first().expect("a first slot");
        assert_eq!(gateway.port, 1);
        assert_eq!(gateway.address, [10, 0, 1, 2]);
        assert_eq!(image.neighbours.get(1), Some(&NeighbourImage::ZERO));
    }

    #[test]
    fn the_slots_past_the_counts_are_left_as_the_zero_image() {
        let image = image_from(&model(), Generation::ZERO).expect("it builds");
        assert!(
            image
                .interfaces
                .iter()
                .skip(2)
                .all(|slot| *slot == InterfaceImage::ZERO)
        );
    }

    /// A document with `count` interfaces, each on a port this build has.
    fn document(count: usize) -> String {
        let mut text = String::from("<configuration><interfaces>");
        for index in 0..count {
            let port = index % usize::from(PORT_COUNT);
            text.push_str(&format!(
                "<interface id=\"i{index}\" port=\"{port}\" enabled=\"true\" \
                 mac=\"52:54:00:00:00:0{index}\" address=\"10.0.{index}.1\" \
                 prefix-length=\"24\"/>"
            ));
        }
        text.push_str("</interfaces><neighbours/>");
        text.push_str(MANAGEMENT);
        text.push_str("</configuration>");
        text
    }

    /// The model an accepted image describes, or `None` where the image says
    /// something no model can.
    ///
    /// The inverse of [`image_from`], and total on an accepted image for the
    /// reasons `ConfigImage::check` enforces: one interface per port makes
    /// port-to-interface a function, so a neighbour's port names exactly the
    /// interface whose id it was built from. Neighbour ids are minted here
    /// rather than recovered, the image carrying none.
    fn model_from(checked: &wire::CheckedConfig) -> Option<Model> {
        let mut model = Model::EMPTY;
        for entry in checked.interfaces() {
            model
                .push_interface(InterfaceEntry {
                    id: Identifier::new(entry.id().as_bytes()).ok()?,
                    port: entry.port(),
                    enabled: entry.enabled(),
                    mac: MacAddress(entry.mac()),
                    address: Ipv4Address::from_octets(entry.address()),
                    prefix_length: entry.prefix_length(),
                })
                .ok()?;
        }
        for (index, entry) in checked.neighbours().enumerate() {
            let interface = checked
                .interfaces()
                .find(|candidate| candidate.port() == entry.port())?;
            model
                .push_neighbour(crate::NeighbourEntry {
                    id: Identifier::new(format!("n{index}").as_bytes()).ok()?,
                    interface: Identifier::new(interface.id().as_bytes()).ok()?,
                    address: Ipv4Address::from_octets(entry.address()),
                    mac: MacAddress(entry.mac()),
                })
                .ok()?;
        }
        if let Some(entry) = checked.management() {
            model
                .set_management(crate::entity::ManagementEntry {
                    enabled: true,
                    mac: MacAddress(entry.mac()),
                    address: Ipv4Address::from_octets(entry.address()),
                    prefix_length: entry.prefix_length(),
                })
                .ok()?;
        }
        Some(model)
    }

    /// A consistent image: one interface per port with its own MAC, `/24` and
    /// id, every neighbour a host address on the link its port names, and the
    /// management port on a prefix none of them claims.
    ///
    /// Every rule admits it, which is the whole point: it is the base exactly
    /// one rule is broken from below, so what an accepted image proves is that
    /// *that* rule was the only thing wrong with it.
    fn consistent_image(interfaces: usize, neighbours: usize, management: bool) -> ConfigImage {
        // A neighbour with no interface on its port is not a neighbour of
        // anything, so a configuration with no interfaces holds none.
        let neighbours = if interfaces == 0 { 0 } else { neighbours };
        let mut image = ConfigImage {
            interface_count: interfaces as u32,
            neighbour_count: neighbours as u32,
            management: if management {
                ManagementImage {
                    enabled: 1,
                    prefix_length: 24,
                    mac: [0x52, 0x54, 0x00, 0x33, 0x00, 0x00],
                    address: [192, 168, 42, 15],
                    ..ManagementImage::ZERO
                }
            } else {
                ManagementImage::ZERO
            },
            ..ConfigImage::ZERO
        };
        for (index, slot) in image.interfaces.iter_mut().enumerate().take(interfaces) {
            let port = index as u8;
            *slot = InterfaceImage {
                port,
                enabled: 1,
                prefix_length: 24,
                mac: [0x52, 0x54, 0x00, 0x11, 0x00, port],
                address: [10, 0, port, 1],
                id: IdentifierImage::from_text(&[b'i', b'0' + port]),
                ..InterfaceImage::ZERO
            };
        }
        for (index, slot) in image.neighbours.iter_mut().enumerate().take(neighbours) {
            let port = (index % interfaces) as u8;
            *slot = NeighbourImage {
                port,
                mac: [0x52, 0x54, 0x00, 0x22, 0x00, index as u8],
                address: [10, 0, port, 2 + (index / interfaces) as u8],
                ..NeighbourImage::ZERO
            };
        }
        image
    }

    /// The ways a byzantine writer can break one rule about an image, applied
    /// to a consistent one.
    ///
    /// One at a time, never two: an image broken twice is refused by whichever
    /// rule runs first, which proves nothing about the second. Together they
    /// are the reason the property below has teeth — the reverse claim is only
    /// interesting on images that are *nearly* valid, and a strategy drawing
    /// every field independently reaches almost none of those.
    const MUTATIONS: [fn(&mut ConfigImage); 29] = [
        |image| image.interfaces[1].mac = image.interfaces[0].mac,
        |image| image.interfaces[1].id = image.interfaces[0].id,
        |image| image.interfaces[0].mac = [0xff; 6],
        |image| image.interfaces[0].mac = [0; 6],
        |image| image.interfaces[0].enabled = 7,
        |image| image.interfaces[0].id = IdentifierImage::ZERO,
        |image| image.interfaces[0].prefix_length = 33,
        // Moving an interface's port or its addressing moves the link every
        // neighbour on it was placed against, so these drop the neighbours:
        // otherwise a neighbour rule refuses the image first and the rule under
        // test is never the one that decided.
        |image| {
            image.neighbour_count = 0;
            image.interfaces[1].port = image.interfaces[0].port;
        },
        |image| {
            image.neighbour_count = 0;
            image.interfaces[0].port = 200;
        },
        |image| {
            image.neighbour_count = 0;
            image.interfaces[1].address = [10, 0, 0, 9];
        },
        |image| {
            image.neighbour_count = 0;
            image.interfaces[0].address = [224, 0, 0, 1];
        },
        |image| {
            image.neighbour_count = 0;
            image.interfaces[0].address = [127, 0, 0, 1];
        },
        |image| {
            image.neighbour_count = 0;
            image.interfaces[0].address = [10, 0, 0, 0];
        },
        |image| {
            image.neighbour_count = 0;
            image.interfaces[0].address = [10, 0, 0, 255];
        },
        // Not a fault at all: a disabled interface is held to every rule an
        // enabled one is, so this must stay accepted on both sides.
        |image| image.interfaces[0].enabled = 0,
        |image| image.neighbours[0].address = [224, 0, 0, 1],
        |image| image.neighbours[0].address = [10, 0, 0, 255],
        |image| image.neighbours[0].address = [10, 0, 0, 1],
        |image| image.neighbours[0].address = [10, 9, 9, 9],
        |image| {
            image.neighbours[1].port = image.neighbours[0].port;
            image.neighbours[1].address = image.neighbours[0].address;
        },
        |image| image.neighbours[0].port = 3,
        |image| image.neighbours[0].mac = [0x01, 0, 0, 0, 0, 1],
        |image| image.management.address = [10, 0, 0, 9],
        |image| image.management.mac = image.interfaces[0].mac,
        |image| image.management.address = [224, 0, 0, 1],
        |image| image.management.address = [192, 168, 42, 0],
        |image| image.management.prefix_length = 33,
        |image| {
            image.management.prefix_length = 8;
            image.management.address = [10, 200, 0, 1];
        },
        // A neighbour that is loopback rather than unicast, on a link whose
        // prefix is short enough to cover it: the containment rule admits it,
        // so this is the one shape in which the unicast rule is the only thing
        // standing between the table and a next hop no frame may be sent to.
        |image| {
            image.interface_count = 1;
            image.neighbour_count = 1;
            image.interfaces[0].prefix_length = 1;
            image.neighbours[0].address = [127, 0, 0, 1];
        },
    ];

    /// A nearly-consistent image, holding at most as many interfaces as this
    /// build has ports.
    ///
    /// At most, because one interface per port is a rule: a build with two
    /// ports admits two interfaces however many slots the image holds, so a
    /// wider image would be refused for the port bound and prove nothing about
    /// any other rule.
    fn any_image() -> impl Strategy<Value = ConfigImage> {
        (
            // Weighted to the full shape, because a mutation that lands on a
            // slot the counts do not cover changes nothing and tests nothing:
            // the smaller arms are what keep the empty and one-interface
            // configurations reachable.
            prop_oneof![6 => Just(usize::from(PORT_COUNT)), 1 => 0usize..=usize::from(PORT_COUNT)],
            prop_oneof![6 => Just(4usize), 1 => 0usize..=4],
            prop_oneof![6 => Just(true), 1 => Just(false)],
            0usize..=MUTATIONS.len(),
        )
            .prop_map(|(interfaces, neighbours, management, mutation)| {
                let mut image = consistent_image(interfaces, neighbours, management);
                // The index past the last is "break nothing", so the unbroken
                // image is drawn as often as any single fault.
                if let Some(apply) = MUTATIONS.get(mutation) {
                    apply(&mut image);
                }
                image
            })
    }

    proptest! {
        /// The direction that guards the trust boundary: an image the consuming
        /// domain accepts is one this crate's own rules would have accepted.
        ///
        /// The forward claim below says the validator cannot hand its consumer
        /// an image the consumer refuses. This one says the consumer cannot be
        /// *made* to run a configuration the validator would have refused —
        /// which is the claim that matters, because the domain writing the
        /// region is the domain that parses an attacker's document, and a rule
        /// only this crate enforced would be a rule a compromised writer does
        /// not enforce.
        ///
        /// Two rules are outside the claim and are the reason `model_from`
        /// mints what it cannot recover: an image carries no neighbour id, so
        /// two neighbours under one id are indistinguishable in it; and a
        /// disabled management entry decodes to no entry at all rather than to
        /// a disabled one, so the rules this crate holds a disabled entry to
        /// have no value on the far side to be about.
        #[test]
        fn every_image_the_consumer_accepts_is_one_validation_would_have_accepted(
            image in any_image(),
        ) {
            let Ok(checked) = image.check(PORT_COUNT) else {
                return Ok(());
            };
            let model = model_from(&checked)
                .expect("an accepted image describes a model");
            prop_assert_eq!(
                validate(&model),
                Ok(()),
                "the consuming domain accepted an image the rules refuse: {:?}",
                validate(&model)
            );
            // And the round trip closes: the image that model builds is the one
            // the consumer was handed, entry for entry.
            let rebuilt = image_from(&model, Generation::from_bits(image.generation))
                .expect("a validated model builds");
            prop_assert_eq!(rebuilt.interface_count, image.interface_count);
            prop_assert_eq!(rebuilt.neighbour_count, image.neighbour_count);
        }

        /// Every configuration this crate accepts produces an image the
        /// byzantine-peer checker accepts. A validator that could hand its own
        /// consumer an image the consumer refuses would fail closed for a
        /// reason nobody could act on.
        #[test]
        fn every_validated_model_produces_an_image_its_own_reader_accepts(
            count in 0usize..3,
            generation in any::<u32>(),
        ) {
            let Ok(model) = load(document(count).as_bytes()) else {
                return Ok(());
            };
            let image = image_from(&model, Generation::from_bits(generation))
                .expect("a validated model builds");
            let checked = image.check(PORT_COUNT).expect("its own reader accepts it");
            prop_assert_eq!(checked.generation(), generation);
            prop_assert_eq!(checked.content_hash(), content_hash(&model).to_bits());
            prop_assert_eq!(checked.interfaces().count(), model.interface_count());
        }

        /// Building an image never panics, whatever a model holds — including
        /// the ones validation would refuse, which a caller may still hand over.
        #[test]
        fn building_from_any_model_is_total(
            port in any::<u8>(),
            prefix_length in any::<u8>(),
            address in proptest::array::uniform4(any::<u8>()),
            mac in proptest::array::uniform6(any::<u8>()),
            resolvable in any::<bool>(),
        ) {
            let mut model = Model::EMPTY;
            model
                .push_interface(InterfaceEntry {
                    id: id("wan"),
                    port,
                    enabled: true,
                    mac: MacAddress(mac),
                    address: Ipv4Address::from_octets(address),
                    prefix_length,
                })
                .expect("capacity");
            model
                .push_neighbour(crate::NeighbourEntry {
                    id: id("gw"),
                    interface: if resolvable { id("wan") } else { id("dmz") },
                    address: Ipv4Address::from_octets(address),
                    mac: MacAddress(mac),
                })
                .expect("capacity");

            prop_assert_eq!(image_from(&model, Generation::ZERO).is_ok(), resolvable);
        }

        /// A model filled to the image's capacity still fits it: the model and
        /// the image are sized by the same two constants, so a document the
        /// reader accepted can never overrun the region it is handed over in.
        ///
        /// Capacity alone. Whether the consuming domain *accepts* such an image
        /// is a narrower claim — one interface per port bounds a two-port build
        /// to two interfaces however many slots the image holds — and it is
        /// `every_validated_model_produces_an_image_its_own_reader_accepts` and
        /// its reverse that make it, over models validation admits.
        #[test]
        fn a_model_at_capacity_fills_the_image(interfaces in 0usize..=MAX_INTERFACES) {
            let mut model = Model::EMPTY;
            for index in 0..interfaces {
                let name = format!("i{index}");
                model
                    .push_interface(InterfaceEntry {
                        id: Identifier::new(name.as_bytes()).expect("alphabet"),
                        port: 0,
                        enabled: true,
                        mac: MacAddress([0x52, 0x54, 0, 0, 0, index as u8]),
                        address: Ipv4Address::from_octets([10, 0, index as u8, 1]),
                        prefix_length: 24,
                    })
                    .expect("capacity");
            }
            for index in 0..MAX_NEIGHBOURS {
                if interfaces == 0 {
                    break;
                }
                model
                    .push_neighbour(crate::NeighbourEntry {
                        id: Identifier::new(format!("n{index}").as_bytes()).expect("alphabet"),
                        interface: id("i0"),
                        address: Ipv4Address::from_octets([10, 0, 0, index as u8]),
                        mac: MacAddress([0x52, 0x54, 0, 0, 1, index as u8]),
                    })
                    .expect("capacity");
            }

            let image = image_from(&model, Generation::ZERO).expect("the image holds as many");
            prop_assert_eq!(usize::try_from(image.interface_count), Ok(interfaces));
            prop_assert_eq!(
                usize::try_from(image.neighbour_count),
                Ok(model.neighbour_count())
            );
        }
    }
}
