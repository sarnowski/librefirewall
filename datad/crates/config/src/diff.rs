//! What changed between two configurations, one record per changed value.
//!
//! This is the audit log's raw material, so what it must not do is more
//! constraining than what it must: a record for a value nobody edited would
//! make every commit look like a rewrite, and a record whose position depended
//! on where a line sat in the document would make two identical commits read
//! differently. Both are avoided the same way — objects are matched by id in id
//! order, and an object's fields are walked in [`Field`] order — so the output
//! is a function of the two configurations and of nothing else.
//!
//! # Why records are handed out rather than written into a buffer
//!
//! A diff used to fill a caller's array, and that array had to be sized for the
//! largest diff the configuration ABI could produce — every object it can hold,
//! in every field a record can name. That number is a product of capacities, so
//! it grows with the ABI rather than with what an operator edited, and the
//! buffer was a stack local in a protection domain with a fixed stack: an
//! object kind with a large capacity would have overrun it, at boot, in the
//! domain that decides what the appliance forwards under.
//!
//! Handing each record to the caller as it is produced removes the quantity
//! rather than resizing it. A diff costs one record of stack whatever the ABI
//! grows to, no bound is left here to keep in step with [`wire::MAX_INTERFACES`]
//! and its siblings, and a caller that has an allocator — a test, the build
//! tooling — collects into whatever it likes.

use lfw_log::{ChangeKind, Field, Identifier, ObjectKind, Value};

use crate::{
    entity::{InterfaceEntry, ManagementEntry, NeighbourEntry, RuleEntry},
    model::Model,
};

/// One value that changed, named the way the document names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub object: ObjectKind,
    pub key: Identifier,
    pub field: Field,
    /// Absent exactly when the object was added.
    pub from: Option<Value>,
    /// Absent exactly when the object was removed.
    pub to: Option<Value>,
}

/// Where a diff's records go.
///
/// A trait rather than a closure type so the protection domain can pass a value
/// that emits straight into its log ring and a test can pass one that collects:
/// both are one record at a time, which is the whole of what a consumer of this
/// has to be able to do.
pub trait Records {
    fn record(&mut self, change: Change);
}

impl<F: FnMut(Change)> Records for F {
    fn record(&mut self, change: Change) {
        self(change);
    }
}

/// What one object says about one field, or `None` where it has no such field.
///
/// A lookup rather than an array position: the record's place in the output is
/// then a property of the field vocabulary alone, and an object that grows a
/// field cannot shift another object's records by declaring it in a different
/// place.
type FieldValue<T> = fn(&T, Field) -> Option<Value>;

/// Hand `out` every record that turns `before` into `after`, and answer how
/// many there were.
///
/// Records are produced by object kind, then id, then field, so two runs over
/// one pair of configurations produce the same sequence record for record.
pub fn diff(before: &Model, after: &Model, out: &mut dyn Records) -> usize {
    let mut out = Counted {
        records: out,
        count: 0,
    };
    walk(
        InterfaceEntry::OBJECT,
        &before.interfaces_by_id(),
        &after.interfaces_by_id(),
        InterfaceEntry::key,
        InterfaceEntry::field_value,
        &mut out,
    );
    walk(
        NeighbourEntry::OBJECT,
        &before.neighbours_by_id(),
        &after.neighbours_by_id(),
        NeighbourEntry::key,
        NeighbourEntry::field_value,
        &mut out,
    );
    walk_rules(before, after, &mut out);
    // One slot, and the same merge: an element that appears, disappears or
    // changes a field is added, removed or modified on the terms every other
    // object kind is held to.
    walk(
        ManagementEntry::OBJECT,
        &before.management_slot(),
        &after.management_slot(),
        ManagementEntry::key,
        ManagementEntry::field_value,
        &mut out,
    );
    out.count
}

/// Merge the two rulesets **by position**, which is the one object kind whose
/// records are not keyed by an id.
///
/// A rule's position is its semantics: the filter is first-match-wins, so
/// moving a rule from the third line to the fifth changes what the appliance
/// forwards even though every attribute of it is identical. Keyed by id, that
/// edit would produce no record at all and a commit would report a policy
/// change as nothing. Keyed by position, the id becomes a value like any other
/// and a moved rule is reported as the two positions whose contents changed —
/// which is what an operator has to read to see what the new policy is.
///
/// The cost is that inserting a rule reports every rule behind it as modified.
/// That is not noise: under first-match-wins, every one of them now sits behind
/// a test that was not there before.
fn walk_rules(before: &Model, after: &Model, out: &mut Counted<'_>) {
    let (before, after) = (before.rules(), after.rules());
    for (position, (earlier, later)) in zip_longest(before, after).enumerate() {
        // Bounded by `MAX_RULES`, which is far inside a `u16`, so the token is
        // the position and never a truncation of it.
        let key = Identifier::decimal(position as u16);
        match (earlier, later) {
            (None, None) => {}
            (from, to) => {
                for field in Field::ALL {
                    let was = from.and_then(|entry| entry.field_value(field));
                    let now = to.and_then(|entry| entry.field_value(field));
                    if was == now {
                        continue;
                    }
                    out.push(Change {
                        kind: match (was, now) {
                            (None, _) => ChangeKind::Added,
                            (_, None) => ChangeKind::Removed,
                            _ => ChangeKind::Modified,
                        },
                        object: RuleEntry::OBJECT,
                        key,
                        field,
                        from: was,
                        to: now,
                    });
                }
            }
        }
    }
}

/// The two rulesets side by side, position for position, running to the length
/// of the longer: a position one side has and the other has not is a rule added
/// or removed, and stopping at the shorter would lose exactly those.
fn zip_longest<'a>(
    before: impl Iterator<Item = &'a RuleEntry>,
    after: impl Iterator<Item = &'a RuleEntry>,
) -> impl Iterator<Item = (Option<&'a RuleEntry>, Option<&'a RuleEntry>)> {
    let mut before = before.map(Some).chain(core::iter::repeat(None));
    let mut after = after.map(Some).chain(core::iter::repeat(None));
    core::iter::from_fn(
        move || match (before.next().flatten(), after.next().flatten()) {
            (None, None) => None,
            pair => Some(pair),
        },
    )
}

/// The caller's sink and the count of what went through it. Counting here
/// rather than at the caller is what makes the number a generation reports and
/// the records it emitted the same walk.
struct Counted<'sink> {
    records: &'sink mut dyn Records,
    count: usize,
}

impl Counted<'_> {
    fn push(&mut self, change: Change) {
        self.records.record(change);
        self.count = self.count.saturating_add(1);
    }
}

/// Merge two id-ordered runs of one object kind, which is where added, removed
/// and modified are told apart: an id in one side only is an addition or a
/// removal, and an id in both is a comparison field by field.
fn walk<T: Copy, const N: usize>(
    object: ObjectKind,
    before: &[Option<T>; N],
    after: &[Option<T>; N],
    key: fn(&T) -> Identifier,
    field_value: FieldValue<T>,
    out: &mut Counted<'_>,
) {
    let mut before = before.iter().flatten().peekable();
    let mut after = after.iter().flatten().peekable();
    loop {
        let ordering = match (before.peek(), after.peek()) {
            (None, None) => return,
            (Some(_), None) => core::cmp::Ordering::Less,
            (None, Some(_)) => core::cmp::Ordering::Greater,
            (Some(gone), Some(kept)) => key(gone).cmp(&key(kept)),
        };
        match ordering {
            core::cmp::Ordering::Less => {
                if let Some(entry) = before.next() {
                    record(
                        object,
                        key(entry),
                        ChangeKind::Removed,
                        |field| field_value(entry, field),
                        out,
                    );
                }
            }
            core::cmp::Ordering::Greater => {
                if let Some(entry) = after.next() {
                    record(
                        object,
                        key(entry),
                        ChangeKind::Added,
                        |field| field_value(entry, field),
                        out,
                    );
                }
            }
            core::cmp::Ordering::Equal => {
                if let (Some(gone), Some(kept)) = (before.next(), after.next()) {
                    modified(
                        object,
                        key(kept),
                        |field| field_value(gone, field),
                        |field| field_value(kept, field),
                        out,
                    );
                }
            }
        }
    }
}

/// One record per field the object has, with the absent side left empty: for an
/// addition there is nothing it came from, and for a removal nothing it went
/// to.
fn record(
    object: ObjectKind,
    key: Identifier,
    kind: ChangeKind,
    value_of: impl Fn(Field) -> Option<Value>,
    out: &mut Counted<'_>,
) {
    for field in Field::ALL {
        let Some(value) = value_of(field) else {
            continue;
        };
        let (from, to) = match kind {
            ChangeKind::Removed => (Some(value), None),
            _ => (None, Some(value)),
        };
        out.push(Change {
            kind,
            object,
            key,
            field,
            from,
            to,
        });
    }
}

/// One record per field whose value differs, and nothing at all for the rest:
/// a commit's volume is the size of what an operator changed.
fn modified(
    object: ObjectKind,
    key: Identifier,
    before: impl Fn(Field) -> Option<Value>,
    after: impl Fn(Field) -> Option<Value>,
    out: &mut Counted<'_>,
) {
    for field in Field::ALL {
        let (Some(from), Some(to)) = (before(field), after(field)) else {
            continue;
        };
        if from == to {
            continue;
        }
        out.push(Change {
            kind: ChangeKind::Modified,
            object,
            key,
            field,
            from: Some(from),
            to: Some(to),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::Gateway;
    use crate::rule::{
        AddressMatch, IcmpTypeMatch, InterfaceMatch, PortMatch, ProtocolMatch, RuleAction,
        TrackingMatch,
    };
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

    fn with_interfaces(names: &[&str]) -> Model {
        let mut model = Model::EMPTY;
        for (index, name) in names.iter().enumerate() {
            model
                .push_interface(interface(name, index as u8))
                .expect("capacity");
        }
        model
    }

    /// The records a diff handed out, as owned values, so an assertion reads as
    /// the list it is checking. The count the diff answers with is asserted
    /// against the records that actually arrived, because a generation reports
    /// that number and a walk that counted more than it emitted would say a
    /// commit moved values nobody can see.
    fn records(before: &Model, after: &Model) -> (Vec<Change>, usize) {
        let mut written = Vec::new();
        let counted = diff(before, after, &mut |change: Change| written.push(change));
        assert_eq!(written.len(), counted);
        (written, counted)
    }

    #[test]
    fn two_identical_configurations_produce_nothing_at_all() {
        let model = with_interfaces(&["wan", "lan"]);
        let (written, counted) = records(&model, &model);
        assert!(written.is_empty());
        assert_eq!(counted, 0);
    }

    #[test]
    fn reordering_the_document_produces_no_records() {
        let forwards = with_interfaces(&["wan", "lan", "dmz"]);
        let mut backwards = Model::EMPTY;
        for entry in forwards.interfaces().collect::<Vec<_>>().iter().rev() {
            backwards.push_interface(**entry).expect("capacity");
        }
        assert_ne!(
            forwards, backwards,
            "the two really are written differently"
        );
        assert!(records(&forwards, &backwards).0.is_empty());
    }

    #[test]
    fn an_added_object_produces_one_record_per_field_with_nothing_it_came_from() {
        let (written, _) = records(&Model::EMPTY, &with_interfaces(&["wan"]));
        assert_eq!(written.len(), 5);
        for change in &written {
            assert_eq!(change.kind, ChangeKind::Added);
            assert_eq!(change.object, ObjectKind::Interface);
            assert_eq!(change.key, id("wan"));
            assert_eq!(change.from, None);
            assert!(change.to.is_some());
        }
        let fields: Vec<Field> = written.iter().map(|change| change.field).collect();
        assert_eq!(
            fields,
            [
                Field::Port,
                Field::Enabled,
                Field::Mac,
                Field::Address,
                Field::PrefixLength
            ]
        );
    }

    #[test]
    fn a_removed_object_produces_one_record_per_field_with_nothing_it_went_to() {
        let (written, _) = records(&with_interfaces(&["wan"]), &Model::EMPTY);
        assert_eq!(written.len(), 5);
        for change in &written {
            assert_eq!(change.kind, ChangeKind::Removed);
            assert!(change.from.is_some());
            assert_eq!(change.to, None);
        }
    }

    #[test]
    fn an_added_neighbour_names_the_three_fields_a_neighbour_has() {
        let mut after = Model::EMPTY;
        after
            .push_neighbour(neighbour("gateway-a", "wan", 2))
            .expect("capacity");
        let (written, _) = records(&Model::EMPTY, &after);
        let fields: Vec<Field> = written.iter().map(|change| change.field).collect();
        assert_eq!(fields, [Field::Mac, Field::Address, Field::Interface]);
        assert!(
            written
                .iter()
                .all(|change| change.object == ObjectKind::Neighbour)
        );
        assert_eq!(
            written.last().expect("the interface reference").to,
            Some(Value::Id(id("wan")))
        );
    }

    #[test]
    fn changing_exactly_one_field_produces_exactly_one_record() {
        let before = with_interfaces(&["wan", "lan"]);
        let mut after = Model::EMPTY;
        for (index, entry) in before.interfaces().enumerate() {
            let mut entry = *entry;
            if index == 1 {
                entry.enabled = false;
            }
            after.push_interface(entry).expect("capacity");
        }

        let (written, counted) = records(&before, &after);
        assert_eq!(counted, 1);
        assert_eq!(
            written.first().copied(),
            Some(Change {
                kind: ChangeKind::Modified,
                object: ObjectKind::Interface,
                key: id("lan"),
                field: Field::Enabled,
                from: Some(Value::Bool(true)),
                to: Some(Value::Bool(false)),
            })
        );
    }

    #[test]
    fn an_unchanged_field_of_a_changed_object_produces_nothing() {
        let before = with_interfaces(&["wan"]);
        let mut after = Model::EMPTY;
        let mut entry = *before.interfaces().next().expect("one");
        entry.address = Ipv4Address::from_octets([10, 0, 0, 9]);
        entry.prefix_length = 8;
        after.push_interface(entry).expect("capacity");

        let (written, _) = records(&before, &after);
        assert_eq!(written.len(), 2, "port, enabled and mac did not move");
        assert_eq!(
            written
                .iter()
                .map(|change| change.field)
                .collect::<Vec<_>>(),
            [Field::Address, Field::PrefixLength]
        );
    }

    #[test]
    fn an_addition_a_removal_and_a_modification_are_told_apart_in_one_diff() {
        let before = with_interfaces(&["kept", "gone"]);
        let mut after = Model::EMPTY;
        let mut kept = *before.interfaces().next().expect("kept");
        kept.port = 5;
        after.push_interface(kept).expect("capacity");
        after
            .push_interface(interface("fresh", 3))
            .expect("capacity");

        let (written, _) = records(&before, &after);
        let summary: Vec<(ChangeKind, &str, Field)> = written
            .iter()
            .map(|change| (change.kind, change.key.as_str(), change.field))
            .collect();
        assert_eq!(
            summary,
            [
                (ChangeKind::Added, "fresh", Field::Port),
                (ChangeKind::Added, "fresh", Field::Enabled),
                (ChangeKind::Added, "fresh", Field::Mac),
                (ChangeKind::Added, "fresh", Field::Address),
                (ChangeKind::Added, "fresh", Field::PrefixLength),
                (ChangeKind::Removed, "gone", Field::Port),
                (ChangeKind::Removed, "gone", Field::Enabled),
                (ChangeKind::Removed, "gone", Field::Mac),
                (ChangeKind::Removed, "gone", Field::Address),
                (ChangeKind::Removed, "gone", Field::PrefixLength),
                (ChangeKind::Modified, "kept", Field::Port),
            ]
        );
    }

    fn management(enabled: bool, last: u8) -> ManagementEntry {
        ManagementEntry {
            enabled,
            mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]),
            address: Ipv4Address::from_octets([10, 0, 2, last]),
            prefix_length: 24,
            gateway: Gateway::Stated(Ipv4Address::from_octets([10, 0, 2, 1])),
        }
    }

    #[test]
    fn the_management_interface_is_diffed_field_by_field_like_any_other_object() {
        let mut before = Model::EMPTY;
        before.set_management(management(true, 15)).expect("one");
        let mut after = Model::EMPTY;
        after.set_management(management(false, 15)).expect("one");

        let (written, counted) = records(&before, &after);
        assert_eq!(counted, 1);
        assert_eq!(
            written.first().copied(),
            Some(Change {
                kind: ChangeKind::Modified,
                object: ObjectKind::Management,
                key: Identifier::MANAGEMENT,
                field: Field::Enabled,
                from: Some(Value::Bool(true)),
                to: Some(Value::Bool(false)),
            })
        );

        // Appearing and disappearing, on the terms every other object is held to.
        let (added, _) = records(&Model::EMPTY, &before);
        assert_eq!(added.len(), 5);
        assert!(added.iter().all(|change| change.kind == ChangeKind::Added
            && change.object == ObjectKind::Management
            && change.from.is_none()));
        assert_eq!(
            added.iter().map(|change| change.field).collect::<Vec<_>>(),
            [
                Field::Enabled,
                Field::Mac,
                Field::Address,
                Field::PrefixLength,
                Field::Gateway
            ]
        );
        let (removed, _) = records(&before, &Model::EMPTY);
        assert!(
            removed
                .iter()
                .all(|change| change.kind == ChangeKind::Removed && change.to.is_none())
        );

        // An unchanged entry produces nothing at all.
        assert!(records(&before, &before).0.is_empty());
    }

    /// The management records come last, after both dataplane object kinds: the
    /// ordering is by object kind, and a reader depends on it.
    #[test]
    fn management_records_follow_the_dataplane_ones() {
        let mut after = with_interfaces(&["wan"]);
        after
            .push_neighbour(neighbour("gateway-a", "wan", 2))
            .expect("capacity");
        after.set_management(management(true, 15)).expect("one");
        let (written, _) = records(&Model::EMPTY, &after);
        let kinds: Vec<ObjectKind> = written.iter().map(|change| change.object).collect();
        let mut sorted = kinds.clone();
        sorted.sort_unstable();
        assert_eq!(kinds, sorted);
        assert_eq!(kinds.last(), Some(&ObjectKind::Management));
    }

    #[test]
    fn interfaces_are_reported_before_neighbours() {
        let mut after = with_interfaces(&["wan"]);
        after
            .push_neighbour(neighbour("gateway-a", "wan", 2))
            .expect("capacity");
        let (written, _) = records(&Model::EMPTY, &after);
        let kinds: Vec<ObjectKind> = written.iter().map(|change| change.object).collect();
        let boundary = kinds
            .iter()
            .position(|kind| *kind == ObjectKind::Neighbour)
            .expect("a neighbour record");
        assert!(
            kinds
                .iter()
                .take(boundary)
                .all(|kind| *kind == ObjectKind::Interface)
        );
        assert!(
            kinds
                .iter()
                .skip(boundary)
                .all(|kind| *kind == ObjectKind::Neighbour)
        );
    }

    /// Every record reaches the caller: there is no buffer between the two, so
    /// the count a generation reports and the records an operator reads are one
    /// walk rather than two quantities that could disagree.
    #[test]
    fn the_count_a_diff_answers_with_is_the_records_it_handed_out() {
        let after = with_interfaces(&["wan"]);
        let (written, counted) = records(&Model::EMPTY, &after);
        assert_eq!(counted, 5);
        assert_eq!(written.len(), 5);

        // A sink that keeps nothing is still handed every one of them, which is
        // what makes the count independent of what the caller does with them.
        let mut seen = 0usize;
        assert_eq!(
            diff(&Model::EMPTY, &after, &mut |_: Change| seen += 1),
            seen
        );
        assert_eq!(seen, 5);
    }

    #[test]
    fn the_diff_from_a_configuration_back_to_the_other_is_the_diff_reversed() {
        let before = with_interfaces(&["wan"]);
        let after = with_interfaces(&["lan"]);
        let (forwards, _) = records(&before, &after);
        let (backwards, _) = records(&after, &before);
        assert_eq!(forwards.len(), backwards.len());
        for change in &forwards {
            let mirrored = backwards
                .iter()
                .find(|other| other.key == change.key && other.field == change.field)
                .expect("the same value in the other direction");
            assert_eq!(mirrored.from, change.to);
            assert_eq!(mirrored.to, change.from);
        }
    }

    proptest! {
        /// A diff hands out one record per field of every object it added, and
        /// the number it answers with is the number that arrived — whatever the
        /// configuration's size, there being no capacity left between the two
        /// for them to disagree across.
        #[test]
        fn every_record_a_diff_counts_is_one_the_caller_was_handed(
            count in 0usize..6,
        ) {
            let names: Vec<String> = (0..count).map(|index| format!("i{index}")).collect();
            let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
            let after = with_interfaces(&borrowed);

            let mut handed = Vec::new();
            let counted = diff(&Model::EMPTY, &after, &mut |change: Change| {
                handed.push(change);
            });

            prop_assert_eq!(counted, count * 5);
            prop_assert_eq!(handed.len(), counted);
        }

        /// The ordering rule, stated as the invariant rather than as a list:
        /// records never step backwards in object kind, then id, then field.
        #[test]
        fn records_are_ordered_by_object_then_id_then_field(
            before_count in 0usize..5,
            after_count in 0usize..5,
        ) {
            let names = |count: usize| -> Vec<String> {
                (0..count).map(|index| format!("i{index}")).collect()
            };
            let build = |count: usize, port: u8| {
                let held = names(count);
                let mut model = Model::EMPTY;
                for name in &held {
                    let mut entry = interface(name, port);
                    entry.id = Identifier::new(name.as_bytes()).expect("alphabet");
                    model.push_interface(entry).expect("capacity");
                    model
                        .push_neighbour(neighbour(name, name, port))
                        .expect("capacity");
                }
                model
            };

            let (written, _) = records(&build(before_count, 0), &build(after_count, 1));
            let keys: Vec<(ObjectKind, Identifier, Field)> = written
                .iter()
                .map(|change| (change.object, change.key, change.field))
                .collect();
            for pair in keys.windows(2) {
                if let [earlier, later] = pair {
                    prop_assert!(earlier <= later, "{earlier:?} then {later:?}");
                }
            }
        }

        /// The round trip: every record says what the value became, so replaying
        /// them onto the old configuration reaches the new one.
        #[test]
        fn applying_a_diff_to_the_old_configuration_yields_the_new_one(
            before_count in 0usize..5,
            after_count in 0usize..5,
            moved in proptest::collection::vec(any::<bool>(), 0..5),
        ) {
            let build = |count: usize, shift: bool| {
                let mut model = Model::EMPTY;
                for index in 0..count {
                    let name = format!("i{index}");
                    let mut entry = interface(&name, index as u8);
                    entry.id = Identifier::new(name.as_bytes()).expect("alphabet");
                    if shift && moved.get(index).copied().unwrap_or(false) {
                        entry.enabled = false;
                        entry.prefix_length = 8;
                    }
                    model.push_interface(entry).expect("capacity");

                    let name = format!("n{index}");
                    let mut entry = neighbour(&name, "i0", index as u8);
                    entry.id = Identifier::new(name.as_bytes()).expect("alphabet");
                    if shift && moved.get(index).copied().unwrap_or(false) {
                        entry.interface = id("i1");
                        entry.mac = MacAddress([2, 2, 2, 2, 2, 2]);
                    }
                    model.push_neighbour(entry).expect("capacity");
                }
                model
            };
            let before = build(before_count, false);
            let after = build(after_count, true);

            let (written, _) = records(&before, &after);
            let mut replayed = before;
            for change in &written {
                apply(&mut replayed, change);
            }
            prop_assert_eq!(content_of(&replayed), content_of(&after));
        }

        /// The headline property, at the level an operator sees it: two
        /// documents naming the same objects in different orders are one
        /// configuration, so nothing about them differs.
        #[test]
        fn reordering_a_document_changes_neither_the_hash_nor_anything_else(
            count in 1usize..8,
            rotation in 0usize..8,
        ) {
            let peer = |index: usize| format!(
                "<neighbour id=\"n{index}\" interface=\"wan\" address=\"10.0.0.{}\" \
                 mac=\"52:54:00:00:01:0{index}\"/>",
                index + 2
            );
            let written = |order: &dyn Fn(usize) -> usize| {
                let mut text = String::from(
                    "<configuration><interfaces>\
                     <interface id=\"wan\" port=\"0\" enabled=\"true\" \
                     mac=\"52:54:00:00:00:01\" address=\"10.0.0.1\" prefix-length=\"24\"/>\
                     <interface id=\"lan\" port=\"1\" enabled=\"true\" \
                     mac=\"52:54:00:00:00:02\" address=\"10.0.1.1\" prefix-length=\"24\"/>\
                     </interfaces><neighbours>",
                );
                for offset in 0..count {
                    text.push_str(&peer(order(offset)));
                }
                text.push_str("</neighbours><rules/>");
                text.push_str(
                    "<management enabled=\"true\" mac=\"52:54:00:12:34:52\" \
                     address=\"192.168.42.15\" prefix-length=\"24\" gateway=\"none\"/>",
                );
                text.push_str("</configuration>");
                text
            };

            let forwards = crate::load(written(&|offset| offset).as_bytes())
                .expect("every rule holds");
            let rotated = crate::load(
                written(&|offset| (offset + rotation) % count).as_bytes(),
            )
            .expect("every rule holds");

            if rotation % count != 0 {
                prop_assert_ne!(forwards, rotated, "the two are written differently");
            }
            prop_assert_eq!(
                crate::content_hash(&forwards),
                crate::content_hash(&rotated)
            );
            prop_assert!(records(&forwards, &rotated).0.is_empty());
            prop_assert!(records(&rotated, &forwards).0.is_empty());
        }
    }

    /// Replay one record onto a configuration, which is what makes the round
    /// trip a test of the records rather than of the two models.
    fn apply(model: &mut Model, change: &Change) {
        match change.object {
            ObjectKind::Interface => apply_interface(model, change),
            ObjectKind::Neighbour => apply_neighbour(model, change),
            ObjectKind::Management => apply_management(model, change),
            ObjectKind::Rule => apply_rule(model, change),
        }
    }

    /// Replay one rule record, which is keyed by position rather than by id.
    ///
    /// The position is the slot to write, so a replay rebuilds the ruleset with
    /// that slot replaced — which is the same operation an operator performs by
    /// editing the nth `<rule>` line.
    fn apply_rule(model: &mut Model, change: &Change) {
        let position: usize = change.key.as_str().parse().expect("a positional key");
        let mut rules: Vec<RuleEntry> = model.rules().copied().collect();
        if change.kind == ChangeKind::Removed {
            if position < rules.len() {
                rules.remove(position);
            }
        } else {
            if position >= rules.len() {
                rules.resize(position + 1, blank_rule());
            }
            let entry = rules.get_mut(position).expect("just sized");
            apply_rule_field(entry, change);
        }
        let mut rebuilt = Model::EMPTY;
        for interface in model.interfaces() {
            rebuilt.push_interface(*interface).expect("capacity");
        }
        for neighbour in model.neighbours() {
            rebuilt.push_neighbour(*neighbour).expect("capacity");
        }
        for rule in rules {
            rebuilt.push_rule(rule).expect("capacity");
        }
        if let Some(management) = model.management() {
            rebuilt.set_management(management).expect("one");
        }
        *model = rebuilt;
    }

    /// The rule a replay starts from before the record's own field is written
    /// over it: every criterion at its widest, which is what an `<rule>` with
    /// nothing said about it would be if the schema admitted one.
    fn blank_rule() -> RuleEntry {
        RuleEntry {
            id: id("placeholder"),
            ingress: InterfaceMatch::Any,
            egress: InterfaceMatch::Any,
            source: AddressMatch::Any,
            destination: AddressMatch::Any,
            protocol: ProtocolMatch::Any,
            source_port: PortMatch::Any,
            destination_port: PortMatch::Any,
            icmp_type: IcmpTypeMatch::Any,
            tracking: TrackingMatch::Any,
            action: RuleAction::Drop,
        }
    }

    /// The one field a record names, written onto `entry`.
    ///
    /// Matched on the field rather than on the value's shape, because two
    /// criteria share a shape: `ingress` and `egress` are both a selector
    /// token, and a replay keyed on the token would write one into the other.
    fn apply_rule_field(entry: &mut RuleEntry, change: &Change) {
        let Some(value) = change.to else {
            return;
        };
        match (change.field, value) {
            (Field::Id, Value::Selector(id)) => entry.id = id,
            (Field::Ingress, value) => entry.ingress = interface_of(value),
            (Field::Egress, value) => entry.egress = interface_of(value),
            (Field::Source, value) => entry.source = address_of(value),
            (Field::Destination, value) => entry.destination = address_of(value),
            (Field::Protocol, Value::Selector(token)) => {
                entry.protocol = crate::value::protocol_match(token.as_bytes())
                    .expect("a token this crate minted");
            }
            (Field::SourcePort, Value::Selector(token)) => {
                entry.source_port =
                    crate::value::port_match(token.as_bytes()).expect("a token this crate minted");
            }
            (Field::DestinationPort, Value::Selector(token)) => {
                entry.destination_port =
                    crate::value::port_match(token.as_bytes()).expect("a token this crate minted");
            }
            (Field::Tracking, Value::Selector(token)) => {
                entry.tracking = crate::value::tracking_match(token.as_bytes())
                    .expect("a token this crate minted");
            }
            (Field::IcmpType, Value::Selector(token)) => {
                entry.icmp_type = crate::value::icmp_type_match(token.as_bytes())
                    .expect("a token this crate minted");
            }
            (Field::Action, Value::Selector(token)) => {
                entry.action =
                    crate::value::action(token.as_bytes()).expect("a token this crate minted");
            }
            (field, value) => panic!("a rule record named {field} carrying {value}"),
        }
    }

    fn interface_of(value: Value) -> InterfaceMatch {
        match value {
            Value::Selector(token) => {
                crate::value::interface_match(token.as_bytes()).expect("a token this crate minted")
            }
            other => panic!("an interface criterion carrying {other}"),
        }
    }

    fn address_of(value: Value) -> AddressMatch {
        match value {
            Value::Selector(_) => AddressMatch::Any,
            Value::Prefix {
                network,
                prefix_length,
            } => AddressMatch::Block {
                network,
                prefix_length,
            },
            other => panic!("an address criterion carrying {other}"),
        }
    }

    fn apply_management(model: &mut Model, change: &Change) {
        let mut entry = model.management().unwrap_or(ManagementEntry {
            enabled: false,
            mac: MacAddress([0; 6]),
            address: Ipv4Address::from_octets([0, 0, 0, 0]),
            prefix_length: 0,
            gateway: Gateway::None,
        });
        let mut rebuilt = Model::EMPTY;
        for interface in model.interfaces() {
            rebuilt.push_interface(*interface).expect("capacity");
        }
        for neighbour in model.neighbours() {
            rebuilt.push_neighbour(*neighbour).expect("capacity");
        }
        if change.kind != ChangeKind::Removed {
            // Keyed on the field rather than on the value's shape: the
            // management element carries two `Ipv4` values now, so the shape
            // alone no longer says which one a record is about.
            match (change.field, change.to) {
                (Field::Enabled, Some(Value::Bool(enabled))) => entry.enabled = enabled,
                (Field::Mac, Some(Value::Mac(mac))) => entry.mac = mac,
                (Field::Address, Some(Value::Ipv4(address))) => entry.address = address,
                (Field::PrefixLength, Some(Value::PrefixLength(length))) => {
                    entry.prefix_length = length;
                }
                (Field::Gateway, Some(Value::Ipv4(address))) => {
                    entry.gateway = Gateway::Stated(address);
                }
                (Field::Gateway, Some(Value::Selector(_))) => entry.gateway = Gateway::None,
                _ => {}
            }
            rebuilt.set_management(entry).expect("one");
        }
        *model = rebuilt;
    }

    fn apply_interface(model: &mut Model, change: &Change) {
        let mut rebuilt = Model::EMPTY;
        let mut seen = change.kind != ChangeKind::Added;
        for entry in model.interfaces() {
            let mut entry = *entry;
            if entry.id == change.key {
                if change.kind == ChangeKind::Removed {
                    continue;
                }
                set_interface(&mut entry, change);
                seen = true;
            }
            rebuilt.push_interface(entry).expect("capacity");
        }
        if !seen {
            let mut fresh = interface("placeholder", 0);
            fresh.id = change.key;
            set_interface(&mut fresh, change);
            rebuilt.push_interface(fresh).expect("capacity");
        }
        for entry in model.neighbours() {
            rebuilt.push_neighbour(*entry).expect("capacity");
        }
        *model = rebuilt;
    }

    fn apply_neighbour(model: &mut Model, change: &Change) {
        let mut rebuilt = Model::EMPTY;
        for entry in model.interfaces() {
            rebuilt.push_interface(*entry).expect("capacity");
        }
        let mut seen = change.kind != ChangeKind::Added;
        for entry in model.neighbours() {
            let mut entry = *entry;
            if entry.id == change.key {
                if change.kind == ChangeKind::Removed {
                    continue;
                }
                set_neighbour(&mut entry, change);
                seen = true;
            }
            rebuilt.push_neighbour(entry).expect("capacity");
        }
        if !seen {
            let mut fresh = neighbour("placeholder", "placeholder", 0);
            fresh.id = change.key;
            set_neighbour(&mut fresh, change);
            rebuilt.push_neighbour(fresh).expect("capacity");
        }
        *model = rebuilt;
    }

    fn set_interface(entry: &mut InterfaceEntry, change: &Change) {
        match change.to {
            Some(Value::Port(port)) => entry.port = port,
            Some(Value::Bool(enabled)) => entry.enabled = enabled,
            Some(Value::Mac(mac)) => entry.mac = mac,
            Some(Value::Ipv4(address)) => entry.address = address,
            Some(Value::PrefixLength(length)) => entry.prefix_length = length,
            _ => {}
        }
    }

    fn set_neighbour(entry: &mut NeighbourEntry, change: &Change) {
        match change.to {
            Some(Value::Mac(mac)) => entry.mac = mac,
            Some(Value::Ipv4(address)) => entry.address = address,
            Some(Value::Id(interface)) => entry.interface = interface,
            _ => {}
        }
    }

    /// The objects a configuration holds, in id order and stripped of the order
    /// they were written in — which is the equality a replay can reach.
    fn content_of(
        model: &Model,
    ) -> (
        Vec<InterfaceEntry>,
        Vec<NeighbourEntry>,
        Option<ManagementEntry>,
    ) {
        (
            model.interfaces_by_id().iter().flatten().copied().collect(),
            model.neighbours_by_id().iter().flatten().copied().collect(),
            model.management(),
        )
    }
}
