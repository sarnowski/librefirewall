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
//! # Why the slice holds `Option<Change>`
//!
//! There is no allocator, so the caller owns the buffer; and a [`Change`]
//! carries an [`Identifier`], which has no infallible constructor, so a caller
//! cannot name an array's fill value without a fallible call standing in a
//! place that has no failure. `Option` is what the caller can write down —
//! `[None; N]` — and it carries a second property worth having: a slot past the
//! last record is emptied rather than left holding whatever a previous diff put
//! there, so the buffer is the diff rather than a prefix of it.

use lfw_log::{ChangeKind, Field, Identifier, ObjectKind, Value};

use crate::model::{InterfaceEntry, Model, NeighbourEntry};

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

/// How much of a diff reached the caller's buffer.
///
/// `dropped` rather than a bare flag because an incomplete audit trail is
/// worth knowing the size of: the commit still happened, and the number of
/// records that did not fit is how far the record of it falls short.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiffSummary {
    written: usize,
    dropped: usize,
}

impl DiffSummary {
    /// No records, which is what an unchanged configuration produces.
    pub const NONE: Self = Self {
        written: 0,
        dropped: 0,
    };

    #[must_use]
    pub const fn written(self) -> usize {
        self.written
    }

    #[must_use]
    pub const fn dropped(self) -> usize {
        self.dropped
    }

    /// Every record the diff had, whether or not it fitted — what a generation
    /// reports as its change count.
    #[must_use]
    pub const fn total(self) -> usize {
        self.written.saturating_add(self.dropped)
    }

    #[must_use]
    pub const fn overflowed(self) -> bool {
        self.dropped > 0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.total() == 0
    }
}

/// One slot per [`Field`], in `Field` order, empty where the object has no such
/// field. Comparing two of these slot by slot is what makes a record's position
/// in the output a property of the field rather than of the code below.
type Fields = [Option<Value>; Field::ALL.len()];

const _: () = {
    // The arrays below are positional, so the order they assume is checked
    // rather than described.
    assert!(matches!(
        Field::ALL,
        [
            Field::Port,
            Field::Enabled,
            Field::Mac,
            Field::Address,
            Field::PrefixLength,
            Field::Interface,
        ]
    ));
};

/// Write the records that turn `before` into `after` into `records`.
///
/// Records are ordered by object kind, then id, then field, so two runs over
/// one pair of configurations produce the same buffer byte for byte.
pub fn diff(before: &Model, after: &Model, records: &mut [Option<Change>]) -> DiffSummary {
    let mut out = Records {
        slots: records.iter_mut(),
        summary: DiffSummary::NONE,
    };
    walk(
        ObjectKind::Interface,
        &before.interfaces_by_id(),
        &after.interfaces_by_id(),
        |entry| entry.id,
        interface_fields,
        &mut out,
    );
    walk(
        ObjectKind::Neighbour,
        &before.neighbours_by_id(),
        &after.neighbours_by_id(),
        |entry| entry.id,
        neighbour_fields,
        &mut out,
    );
    out.finish()
}

/// The caller's buffer while it is being filled, and the count of what did not
/// fit. Holding the iterator rather than an index is what leaves nothing to
/// bound: a slot that is not there is a `None` from `next`.
struct Records<'slice> {
    slots: core::slice::IterMut<'slice, Option<Change>>,
    summary: DiffSummary,
}

impl Records<'_> {
    fn push(&mut self, change: Change) {
        match self.slots.next() {
            Some(slot) => {
                *slot = Some(change);
                self.summary.written = self.summary.written.saturating_add(1);
            }
            None => self.summary.dropped = self.summary.dropped.saturating_add(1),
        }
    }

    /// Empties what the diff did not write, so a reused buffer cannot present
    /// a record from an earlier commit as one from this one.
    fn finish(mut self) -> DiffSummary {
        for slot in &mut self.slots {
            *slot = None;
        }
        self.summary
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
    fields: fn(&T) -> Fields,
    out: &mut Records<'_>,
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
                    record(object, key(entry), ChangeKind::Removed, fields(entry), out);
                }
            }
            core::cmp::Ordering::Greater => {
                if let Some(entry) = after.next() {
                    record(object, key(entry), ChangeKind::Added, fields(entry), out);
                }
            }
            core::cmp::Ordering::Equal => {
                if let (Some(gone), Some(kept)) = (before.next(), after.next()) {
                    modified(object, key(kept), fields(gone), fields(kept), out);
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
    fields: Fields,
    out: &mut Records<'_>,
) {
    for (field, value) in Field::ALL.into_iter().zip(fields) {
        let Some(value) = value else {
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
    before: Fields,
    after: Fields,
    out: &mut Records<'_>,
) {
    for (field, (from, to)) in Field::ALL.into_iter().zip(before.into_iter().zip(after)) {
        let (Some(from), Some(to)) = (from, to) else {
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

fn interface_fields(entry: &InterfaceEntry) -> Fields {
    [
        Some(Value::Port(entry.port)),
        Some(Value::Bool(entry.enabled)),
        Some(Value::Mac(entry.mac)),
        Some(Value::Ipv4(entry.address)),
        Some(Value::PrefixLength(entry.prefix_length)),
        None,
    ]
}

fn neighbour_fields(entry: &NeighbourEntry) -> Fields {
    [
        None,
        None,
        Some(Value::Mac(entry.mac)),
        Some(Value::Ipv4(entry.address)),
        None,
        Some(Value::Id(entry.interface)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_headers::{Ipv4Address, MacAddress};
    use proptest::prelude::*;
    use std::{format, string::String, vec::Vec};

    /// Room for every record two full configurations can produce, so a test
    /// that did not set out to overflow does not.
    const ROOMY: usize = 512;

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

    /// The records a diff wrote, as owned values, so an assertion reads as the
    /// list it is checking.
    fn records(before: &Model, after: &Model) -> (Vec<Change>, DiffSummary) {
        let mut buffer = [None; ROOMY];
        let summary = diff(before, after, &mut buffer);
        let written: Vec<Change> = buffer.iter().flatten().copied().collect();
        assert_eq!(written.len(), summary.written());
        assert!(
            !summary.overflowed(),
            "{ROOMY} slots were meant to be enough"
        );
        (written, summary)
    }

    #[test]
    fn two_identical_configurations_produce_nothing_at_all() {
        let model = with_interfaces(&["wan", "lan"]);
        let (written, summary) = records(&model, &model);
        assert!(written.is_empty());
        assert!(summary.is_empty());
        assert_eq!(summary.total(), 0);
        assert_eq!(summary, DiffSummary::NONE);
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

        let (written, summary) = records(&before, &after);
        assert_eq!(summary.written(), 1);
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

    #[test]
    fn a_buffer_too_small_is_reported_rather_than_quietly_cut_short() {
        let after = with_interfaces(&["wan"]);
        let mut buffer = [None; 3];
        let summary = diff(&Model::EMPTY, &after, &mut buffer);
        assert_eq!(summary.written(), 3);
        assert_eq!(summary.dropped(), 2);
        assert_eq!(summary.total(), 5);
        assert!(summary.overflowed());
        assert_eq!(buffer.iter().flatten().count(), 3);

        let none = diff(&Model::EMPTY, &after, &mut []);
        assert_eq!(none.written(), 0);
        assert_eq!(none.total(), 5);
        assert!(none.overflowed());
    }

    #[test]
    fn a_reused_buffer_holds_this_diff_and_no_part_of_the_last_one() {
        let mut buffer = [None; ROOMY];
        let after = with_interfaces(&["wan"]);
        assert_eq!(diff(&Model::EMPTY, &after, &mut buffer).written(), 5);
        assert_eq!(diff(&after, &after, &mut buffer), DiffSummary::NONE);
        assert_eq!(buffer.iter().flatten().count(), 0);
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
        /// A diff never writes past the buffer it was given, and says how far
        /// short it fell whenever it would have.
        #[test]
        fn a_diff_stays_inside_the_buffer_and_reports_what_did_not_fit(
            count in 0usize..6,
            capacity in 0usize..40,
        ) {
            let names: Vec<String> = (0..count).map(|index| format!("i{index}")).collect();
            let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
            let after = with_interfaces(&borrowed);

            let mut buffer = [None; 40];
            let slice = buffer.get_mut(..capacity).expect("within the array");
            let summary = diff(&Model::EMPTY, &after, slice);

            prop_assert_eq!(summary.total(), count * 5);
            prop_assert_eq!(summary.written(), summary.total().min(capacity));
            prop_assert_eq!(summary.overflowed(), summary.total() > capacity);
            prop_assert_eq!(
                buffer.iter().flatten().count(),
                summary.written(),
                "nothing was written past the slice the caller handed over"
            );
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
                text.push_str("</neighbours></configuration>");
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
        }
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
    fn content_of(model: &Model) -> (Vec<InterfaceEntry>, Vec<NeighbourEntry>) {
        (
            model.interfaces_by_id().iter().flatten().copied().collect(),
            model.neighbours_by_id().iter().flatten().copied().collect(),
        )
    }
}
