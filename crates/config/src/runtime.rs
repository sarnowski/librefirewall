//! What a committed configuration becomes: the handover image the domain that
//! forwards reads it out of. No forwarding table is built here — the domain
//! that routes builds its own from the image it was handed, and a second one
//! built from the model would be a table nothing routes on. Building an image
//! resolves a neighbour's `interface` id to a port, and is fallible because the
//! alternative is a panic reached through a rule enforced in another module.

use lfw_log::Identifier;
use wire::{ConfigImage, InterfaceImage, NeighbourImage};

use crate::{
    hash::content_hash,
    model::{Model, NeighbourEntry},
    store::Generation,
};

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
        ..ConfigImage::ZERO
    };

    let mut count = 0u32;
    for (slot, entry) in image.interfaces.iter_mut().zip(model.interfaces()) {
        *slot = InterfaceImage {
            port: entry.port,
            enabled: u8::from(entry.enabled),
            prefix_length: entry.prefix_length,
            _pad: 0,
            mac: entry.mac.0,
            _pad2: [0; 2],
            address: entry.address.octets(),
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
    use crate::{PORT_COUNT, load, model::InterfaceEntry, validate};
    use net_headers::{Ipv4Address, MacAddress};
    use proptest::prelude::*;
    use std::{format, string::String};
    use wire::{MAX_INTERFACES, MAX_NEIGHBOURS};

    /// The document from CONTRACTS.md §4b plus a second interface, so both
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
        "</neighbours></configuration>"
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
    fn the_empty_configuration_builds_an_image_that_forwards_nothing() {
        let image = image_from(&Model::EMPTY, Generation::ZERO).expect("the fail-closed model");
        assert_eq!(image.interface_count, 0);
        assert_eq!(image.neighbour_count, 0);
        assert_eq!(image.generation, 0);
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
        text.push_str("</interfaces><neighbours/></configuration>");
        text
    }

    proptest! {
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
            prop_assert!(image.check(PORT_COUNT).is_ok());
        }
    }
}
