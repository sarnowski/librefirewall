//! What a configuration *is*, as one number.
//!
//! Folded over the model rather than over the document, so the two things an
//! operator changes without changing anything — whitespace and the order lines
//! were written in — cannot move it. A hash over the bytes would move on both,
//! and a commit keyed on one would then re-apply a configuration that had not
//! changed.
//!
//! FNV-1a, and 32 bits, because nothing here decides anything: this is the label
//! a configuration carries across the handover, never the answer to whether two
//! configurations are the same one. That is
//! [`Model::has_same_content`](crate::Model::has_same_content), which compares
//! the objects. A commit keyed on a digest this short — of a document somebody
//! else may one day choose — would let a collision suppress a configuration
//! with no generation, no record and nothing published.

use lfw_log::Identifier;

use crate::model::Model;

const OFFSET_BASIS: u32 = 0x811c_9dc5;
const PRIME: u32 = 0x0100_0193;

/// Closes an identifier, so a variable-width field cannot run into the one
/// after it. Outside the identifier alphabet, which is what makes the folded
/// sequence have exactly one reading. Every other field is fixed-width, and
/// where one object begins is the mark each declares for itself.
const ID_END: u8 = 0xff;

/// The identity of a configuration's content.
///
/// A distinct type from [`Generation`](crate::Generation) because both are a
/// `u32` and they answer opposite questions: a generation says *when* a
/// configuration was committed and a hash says *what* was committed, and a
/// commit compares one against the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash(u32);

impl ContentHash {
    /// A configuration holding no objects folds nothing, so its hash is the
    /// basis the fold starts from — which is what lets the fail-closed
    /// generation zero be a constant rather than a computation.
    pub const EMPTY: Self = Self(OFFSET_BASIS);

    #[must_use]
    pub const fn to_bits(self) -> u32 {
        self.0
    }
}

/// Fold a configuration into its content hash.
///
/// Each object folds itself, mark first, in the field order its own
/// declaration fixes; this walks them in the order that makes the result a
/// property of the configuration rather than of the document — by id, and the
/// management entry last. It folds at all because a commit is keyed on this
/// number: a document whose only edit is the management address would
/// otherwise read as unchanged.
///
/// The rules are the one exception, and they are folded **in document order**
/// for the reason they are compared that way: first match wins, so two
/// documents holding the same rules in a different order are two policies, and
/// a hash that sorted them would report the second as unchanged.
#[must_use]
pub fn content_hash(model: &Model) -> ContentHash {
    let mut hash = OFFSET_BASIS;
    for entry in model.interfaces_by_id().iter().flatten() {
        hash = entry.fold(hash);
    }
    for entry in model.neighbours_by_id().iter().flatten() {
        hash = entry.fold(hash);
    }
    for entry in model.rules() {
        hash = entry.fold(hash);
    }
    if let Some(entry) = model.management() {
        hash = entry.fold(hash);
    }
    ContentHash(hash)
}

pub(crate) fn fold(hash: u32, bytes: &[u8]) -> u32 {
    let mut hash = hash;
    for byte in bytes {
        hash = (hash ^ u32::from(*byte)).wrapping_mul(PRIME);
    }
    hash
}

pub(crate) fn fold_identifier(hash: u32, id: Identifier) -> u32 {
    fold(fold(hash, id.as_bytes()), &[ID_END])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{InterfaceEntry, NeighbourEntry};
    use net_headers::{Ipv4Address, MacAddress};
    use proptest::prelude::*;
    use std::{format, string::String, vec::Vec};

    fn id(text: &str) -> Identifier {
        Identifier::new(text.as_bytes()).expect("the test uses the identifier alphabet")
    }

    fn interface(name: &str, port: u8) -> InterfaceEntry {
        InterfaceEntry {
            id: id(name),
            port,
            enabled: true,
            mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, port]),
            address: Ipv4Address::from_octets([10, 0, port, 1]),
            prefix_length: 24,
        }
    }

    fn neighbour(name: &str, interface: &str, host: u8) -> NeighbourEntry {
        NeighbourEntry {
            id: id(name),
            interface: id(interface),
            address: Ipv4Address::from_octets([10, 0, 0, host]),
            mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x01, host]),
        }
    }

    fn model(names: &[&str]) -> Model {
        let mut model = Model::EMPTY;
        for (index, name) in names.iter().enumerate() {
            model
                .push_interface(interface(name, index as u8))
                .expect("capacity");
            model
                .push_neighbour(neighbour(name, name, index as u8))
                .expect("capacity");
        }
        model
    }

    /// `model(names)` with one interface field rewritten by `change`.
    fn interface_edited(names: &[&str], change: fn(&mut InterfaceEntry)) -> ContentHash {
        let base = model(names);
        let mut edited = Model::EMPTY;
        let mut first = true;
        for entry in base.interfaces() {
            let mut entry = *entry;
            if core::mem::take(&mut first) {
                change(&mut entry);
            }
            edited.push_interface(entry).expect("capacity");
        }
        for entry in base.neighbours() {
            edited.push_neighbour(*entry).expect("capacity");
        }
        content_hash(&edited)
    }

    /// As [`interface_edited`], for the first neighbour.
    fn neighbour_edited(names: &[&str], change: fn(&mut NeighbourEntry)) -> ContentHash {
        let base = model(names);
        let mut edited = Model::EMPTY;
        for entry in base.interfaces() {
            edited.push_interface(*entry).expect("capacity");
        }
        let mut first = true;
        for entry in base.neighbours() {
            let mut entry = *entry;
            if core::mem::take(&mut first) {
                change(&mut entry);
            }
            edited.push_neighbour(entry).expect("capacity");
        }
        content_hash(&edited)
    }

    /// The commit path keys on this number, so every field of the management
    /// entry has to move it — including the enable flag, which is the one an
    /// operator flips without touching an address.
    #[test]
    fn changing_any_single_management_field_changes_the_hash() {
        let base = |change: fn(&mut crate::entity::ManagementEntry)| {
            let mut model = model(&["wan"]);
            let mut entry = crate::entity::ManagementEntry {
                enabled: true,
                mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]),
                address: Ipv4Address::from_octets([10, 0, 2, 15]),
                prefix_length: 24,
            };
            change(&mut entry);
            model.set_management(entry).expect("one");
            content_hash(&model)
        };
        let hash = base(|_| {});
        let edits: [fn(&mut crate::entity::ManagementEntry); 4] = [
            |entry| entry.enabled = false,
            |entry| entry.mac = MacAddress([1, 2, 3, 4, 5, 6]),
            |entry| entry.address = Ipv4Address::from_octets([9, 9, 9, 9]),
            |entry| entry.prefix_length = 25,
        ];
        for (index, edit) in edits.into_iter().enumerate() {
            assert_ne!(base(edit), hash, "edit {index}");
        }
        // And an absent entry is not a disabled one.
        assert_ne!(hash, content_hash(&model(&["wan"])));
    }

    #[test]
    fn the_empty_configuration_hashes_to_the_constant_that_names_it() {
        assert_eq!(content_hash(&Model::EMPTY), ContentHash::EMPTY);
        assert_eq!(ContentHash::EMPTY.to_bits(), OFFSET_BASIS);
    }

    #[test]
    fn one_configuration_written_two_ways_hashes_the_same() {
        let forwards = model(&["wan", "lan", "dmz"]);
        let mut backwards = Model::EMPTY;
        for entry in forwards.interfaces().collect::<Vec<_>>().iter().rev() {
            backwards.push_interface(**entry).expect("capacity");
        }
        for entry in forwards.neighbours().collect::<Vec<_>>().iter().rev() {
            backwards.push_neighbour(**entry).expect("capacity");
        }

        assert_ne!(
            forwards, backwards,
            "the two really are written differently"
        );
        assert_eq!(content_hash(&forwards), content_hash(&backwards));
    }

    #[test]
    fn changing_any_single_interface_field_changes_the_hash() {
        let names = ["wan", "lan"];
        let hash = content_hash(&model(&names));
        let edits: [fn(&mut InterfaceEntry); 6] = [
            |entry| entry.id = id("other"),
            |entry| entry.port = 7,
            |entry| entry.enabled = false,
            |entry| entry.mac = MacAddress([1, 2, 3, 4, 5, 6]),
            |entry| entry.address = Ipv4Address::from_octets([9, 9, 9, 9]),
            |entry| entry.prefix_length = 8,
        ];
        for (index, edit) in edits.into_iter().enumerate() {
            assert_ne!(interface_edited(&names, edit), hash, "edit {index}");
        }
    }

    #[test]
    fn changing_any_single_neighbour_field_changes_the_hash() {
        let names = ["wan", "lan"];
        let hash = content_hash(&model(&names));
        let edits: [fn(&mut NeighbourEntry); 4] = [
            |entry| entry.id = id("other"),
            |entry| entry.interface = id("elsewhere"),
            |entry| entry.address = Ipv4Address::from_octets([9, 9, 9, 9]),
            |entry| entry.mac = MacAddress([1, 2, 3, 4, 5, 6]),
        ];
        for (index, edit) in edits.into_iter().enumerate() {
            assert_ne!(neighbour_edited(&names, edit), hash, "edit {index}");
        }
    }

    #[test]
    fn an_object_boundary_is_not_a_place_two_configurations_can_meet() {
        // Without the mark and the id terminator these two fold the same byte
        // sequence: one identifier's tail is the next one's head.
        assert_ne!(
            content_hash(&model(&["ab", "c"])),
            content_hash(&model(&["a", "bc"]))
        );

        let mut one = Model::EMPTY;
        one.push_interface(interface("wan", 0)).expect("capacity");
        let mut other = Model::EMPTY;
        other
            .push_neighbour(neighbour("wan", "wan", 0))
            .expect("capacity");
        assert_ne!(content_hash(&one), content_hash(&other));
    }

    #[test]
    fn adding_or_dropping_an_object_changes_the_hash() {
        assert_ne!(
            content_hash(&model(&["wan", "lan"])),
            content_hash(&model(&["wan"]))
        );
        assert_ne!(content_hash(&model(&["wan"])), content_hash(&Model::EMPTY));
    }

    proptest! {
        /// A function of the configuration alone, and of nothing about the run
        /// that produced it.
        #[test]
        fn the_hash_is_deterministic(count in 0usize..6) {
            let names: Vec<String> = (0..count).map(|index| format!("i{index}")).collect();
            let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
            let subject = model(&borrowed);
            prop_assert_eq!(content_hash(&subject), content_hash(&subject));
        }

        /// The headline property of the hash: the order objects were written in
        /// is not part of what a configuration is.
        #[test]
        fn a_rotation_of_the_document_hashes_the_same(
            count in 1usize..6,
            rotation in 0usize..6,
        ) {
            let names: Vec<String> = (0..count).map(|index| format!("i{index}")).collect();
            let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
            let written = model(&borrowed);

            let interfaces: Vec<_> = written.interfaces().copied().collect();
            let neighbours: Vec<_> = written.neighbours().copied().collect();
            let mut rotated = Model::EMPTY;
            for offset in 0..count {
                let entry = interfaces
                    .get((offset + rotation) % count)
                    .expect("within the vector");
                rotated.push_interface(*entry).expect("capacity");
                let entry = neighbours
                    .get((offset + rotation) % count)
                    .expect("within the vector");
                rotated.push_neighbour(*entry).expect("capacity");
            }

            prop_assert_eq!(content_hash(&written), content_hash(&rotated));
        }
    }
}
