//! The parsed configuration, as a value: the fixed-capacity container the
//! objects declared beside it are held in.
//!
//! This is what a document becomes once it is no longer bytes, and what every
//! later step — validation, hashing, diffing, the handover image — reads
//! instead of the document. It holds no offsets and no source text on purpose:
//! two documents that differ only in whitespace, attribute order or element
//! order must be the same configuration, and the surest way to guarantee that
//! is to leave the reader nothing to remember them by.

use lfw_log::Identifier;
use wire::{MAX_INTERFACES, MAX_NEIGHBOURS, MAX_RULES};

use crate::entity::{InterfaceEntry, ManagementEntry, NeighbourEntry, RuleEntry};
#[cfg(test)]
use crate::gateway::Gateway;

/// The handover image has a fixed number of slots and there is no allocator, so
/// an object past the last of them cannot be stored and is not truncated away
/// either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// A whole configuration.
///
/// `Copy`, because a domain holds a running one beside a candidate one and
/// swapping them must not be an operation that can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Model {
    interfaces: [Option<InterfaceEntry>; MAX_INTERFACES],
    neighbours: [Option<NeighbourEntry>; MAX_NEIGHBOURS],
    management: Option<ManagementEntry>,
    rules: [Option<RuleEntry>; MAX_RULES],
}

impl Model {
    /// No interfaces and no neighbours: the fail-closed configuration a domain
    /// runs under before it is given one, and after one is refused.
    pub const EMPTY: Self = Self {
        interfaces: [None; MAX_INTERFACES],
        neighbours: [None; MAX_NEIGHBOURS],
        management: None,
        rules: [None; MAX_RULES],
    };

    /// # Errors
    /// [`Full`] once [`wire::MAX_INTERFACES`] entries are held.
    pub fn push_interface(&mut self, entry: InterfaceEntry) -> Result<(), Full> {
        match self.interfaces.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(entry);
                Ok(())
            }
            None => Err(Full),
        }
    }

    /// # Errors
    /// [`Full`] once [`wire::MAX_NEIGHBOURS`] entries are held.
    pub fn push_neighbour(&mut self, entry: NeighbourEntry) -> Result<(), Full> {
        match self.neighbours.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(entry);
                Ok(())
            }
            None => Err(Full),
        }
    }

    /// # Errors
    /// [`Full`] once [`wire::MAX_RULES`] entries are held.
    pub fn push_rule(&mut self, entry: RuleEntry) -> Result<(), Full> {
        match self.rules.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(entry);
                Ok(())
            }
            None => Err(Full),
        }
    }

    /// In document order, which is the order every later step iterates in: a
    /// diff is keyed by id and so is order-independent, but a *rejection* names
    /// the first offending object and that has to be the first one an operator
    /// reads.
    pub fn interfaces(&self) -> impl Iterator<Item = &InterfaceEntry> {
        self.interfaces.iter().flatten()
    }

    pub fn neighbours(&self) -> impl Iterator<Item = &NeighbourEntry> {
        self.neighbours.iter().flatten()
    }

    /// In document order, and for this object that is not a convenience: the
    /// ruleset is decided first-match-wins, so the order these come back in
    /// *is* the policy.
    pub fn rules(&self) -> impl Iterator<Item = &RuleEntry> {
        self.rules.iter().flatten()
    }

    #[must_use]
    pub fn interface_count(&self) -> usize {
        self.interfaces().count()
    }

    #[must_use]
    pub fn neighbour_count(&self) -> usize {
        self.neighbours().count()
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules().count()
    }

    #[must_use]
    pub fn interface(&self, id: Identifier) -> Option<&InterfaceEntry> {
        self.interfaces().find(|entry| entry.id == id)
    }

    #[must_use]
    pub fn neighbour(&self, id: Identifier) -> Option<&NeighbourEntry> {
        self.neighbours().find(|entry| entry.id == id)
    }

    #[must_use]
    pub fn rule(&self, id: Identifier) -> Option<&RuleEntry> {
        self.rules().find(|entry| entry.id == id)
    }

    /// One port, one element, held here rather than only in the reader.
    ///
    /// # Errors
    /// [`Full`] once an entry is held.
    pub fn set_management(&mut self, entry: ManagementEntry) -> Result<(), Full> {
        match self.management {
            Some(_) => Err(Full),
            None => {
                self.management = Some(entry);
                Ok(())
            }
        }
    }

    /// `None` for a configuration describing none, which generation 0 is.
    #[must_use]
    pub const fn management(&self) -> Option<ManagementEntry> {
        self.management
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interface_count() == 0
            && self.neighbour_count() == 0
            && self.rule_count() == 0
            && self.management.is_none()
    }

    /// The interfaces by id, whichever order they were written in. Both orders
    /// exist because they answer different questions: a refusal names the first
    /// offending object an operator reads, and a comparison between two
    /// configurations must not see a moved line as a change at all.
    pub(crate) fn interfaces_by_id(&self) -> [Option<InterfaceEntry>; MAX_INTERFACES] {
        by_id(&self.interfaces, |entry| entry.id)
    }

    pub(crate) fn neighbours_by_id(&self) -> [Option<NeighbourEntry>; MAX_NEIGHBOURS] {
        by_id(&self.neighbours, |entry| entry.id)
    }

    /// The one-slot array shape the diff walks, so the same merge compares it.
    pub(crate) fn management_slot(&self) -> [Option<ManagementEntry>; 1] {
        [self.management]
    }

    /// Whether two configurations *are* the same one, whichever order each was
    /// written in — which is what "unchanged" means, and is exact.
    ///
    /// `PartialEq` is deliberately not this: it compares the arrays as written,
    /// answering the different question of whether two documents *said* the
    /// same thing.
    /// The rules are compared **as written** rather than by id, and that is the
    /// one asymmetry in this comparison. Two documents whose interfaces are the
    /// same set are the same configuration whichever order they were written
    /// in; two documents whose rules are the same set in a different order are
    /// two different policies, so a reordered `<rules>` section is a change and
    /// re-offering it commits a generation.
    #[must_use]
    pub fn has_same_content(&self, other: &Self) -> bool {
        self.interfaces_by_id() == other.interfaces_by_id()
            && self.neighbours_by_id() == other.neighbours_by_id()
            && self.rules == other.rules
            && self.management == other.management
    }
}

/// `entries` in key order with the empty slots behind them: a selection sort
/// walked through `split_first_mut` rather than by index, there being no
/// allocator to sort into and no index to get wrong. Bounded by `N`, a build
/// constant no document can move.
fn by_id<T: Copy, const N: usize>(
    entries: &[Option<T>; N],
    key: fn(&T) -> Identifier,
) -> [Option<T>; N] {
    fn rank<T>(slot: &Option<T>, key: fn(&T) -> Identifier) -> (bool, Option<Identifier>) {
        match slot {
            Some(entry) => (false, Some(key(entry))),
            None => (true, None),
        }
    }

    let mut sorted = *entries;
    let mut rest: &mut [Option<T>] = &mut sorted;
    while let Some((first, tail)) = core::mem::take(&mut rest).split_first_mut() {
        for candidate in tail.iter_mut() {
            if rank(candidate, key) < rank(first, key) {
                core::mem::swap(first, candidate);
            }
        }
        rest = tail;
    }
    sorted
}

impl Default for Model {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_headers::{Ipv4Address, MacAddress};
    use std::string::String;

    pub(crate) fn id(text: &str) -> Identifier {
        Identifier::new(text.as_bytes()).expect("the test uses the identifier alphabet")
    }

    pub(crate) fn interface(name: &str, port: u8) -> InterfaceEntry {
        InterfaceEntry {
            id: id(name),
            port,
            enabled: true,
            mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, port]),
            address: Ipv4Address::from_octets([10, 0, port, 1]),
            prefix_length: 24,
        }
    }

    pub(crate) fn neighbour(name: &str, interface: &str, host: u8) -> NeighbourEntry {
        NeighbourEntry {
            id: id(name),
            interface: id(interface),
            address: Ipv4Address::from_octets([10, 0, 0, host]),
            mac: MacAddress([0x52, 0x54, 0x00, 0x00, 0x01, host]),
        }
    }

    #[test]
    fn the_empty_model_holds_nothing_and_finds_nothing() {
        let model = Model::EMPTY;
        assert!(model.is_empty());
        assert_eq!(model.interface_count(), 0);
        assert_eq!(model.neighbour_count(), 0);
        assert_eq!(model.interfaces().count(), 0);
        assert_eq!(model.neighbours().count(), 0);
        assert!(model.interface(id("wan")).is_none());
        assert!(model.neighbour(id("gw")).is_none());
        assert_eq!(Model::default(), Model::EMPTY);
    }

    #[test]
    fn entries_come_back_in_the_order_they_were_pushed() {
        let mut model = Model::EMPTY;
        for (index, name) in ["wan", "lan", "dmz"].iter().enumerate() {
            model
                .push_interface(interface(name, index as u8))
                .expect("within capacity");
        }
        let ids: Vec<&str> = model.interfaces().map(|entry| entry.id.as_str()).collect();
        assert_eq!(ids, ["wan", "lan", "dmz"]);
        assert_eq!(model.interface_count(), 3);
        assert!(!model.is_empty());
    }

    #[test]
    fn an_entry_is_found_by_the_id_it_was_given() {
        let mut model = Model::EMPTY;
        model.push_interface(interface("wan", 0)).expect("capacity");
        model
            .push_neighbour(neighbour("gateway-a", "wan", 2))
            .expect("capacity");
        assert_eq!(model.interface(id("wan")).expect("wan").port, 0);
        assert_eq!(
            model
                .neighbour(id("gateway-a"))
                .expect("gateway-a")
                .interface,
            id("wan")
        );
        assert!(model.interface(id("lan")).is_none());
        assert!(model.neighbour(id("gateway-b")).is_none());
    }

    #[test]
    fn exactly_the_image_capacity_fits_and_one_more_is_refused() {
        let mut model = Model::EMPTY;
        for index in 0..MAX_INTERFACES {
            model
                .push_interface(interface("wan", index as u8))
                .expect("within capacity");
        }
        assert_eq!(model.interface_count(), MAX_INTERFACES);
        assert_eq!(model.push_interface(interface("wan", 0)), Err(Full));

        for index in 0..MAX_NEIGHBOURS {
            model
                .push_neighbour(neighbour("gw", "wan", index as u8))
                .expect("within capacity");
        }
        assert_eq!(model.neighbour_count(), MAX_NEIGHBOURS);
        assert_eq!(model.push_neighbour(neighbour("gw", "wan", 0)), Err(Full));
    }

    #[test]
    fn objects_come_back_by_id_whichever_order_they_were_written_in() {
        let ids = |slots: [Option<InterfaceEntry>; MAX_INTERFACES]| -> Vec<String> {
            slots
                .iter()
                .flatten()
                .map(|entry| String::from(entry.id.as_str()))
                .collect()
        };

        let mut forwards = Model::EMPTY;
        let mut backwards = Model::EMPTY;
        let names = ["wan", "dmz", "lan", "a"];
        for (index, name) in names.iter().enumerate() {
            forwards
                .push_interface(interface(name, index as u8))
                .expect("capacity");
        }
        for (index, name) in names.iter().enumerate().rev() {
            backwards
                .push_interface(interface(name, index as u8))
                .expect("capacity");
        }

        assert_eq!(ids(forwards.interfaces_by_id()), ["a", "dmz", "lan", "wan"]);
        assert_eq!(
            ids(forwards.interfaces_by_id()),
            ids(backwards.interfaces_by_id())
        );
        assert_ne!(
            forwards.interfaces().next().expect("one"),
            backwards.interfaces().next().expect("one"),
            "document order is what the sort had to be independent of"
        );
    }

    #[test]
    fn the_empty_slots_sort_behind_every_object() {
        let mut model = Model::EMPTY;
        model
            .push_neighbour(neighbour("gw", "wan", 2))
            .expect("one");
        let sorted = model.neighbours_by_id();
        assert_eq!(sorted.iter().flatten().count(), 1);
        assert!(sorted.first().expect("a slot").is_some());
        assert!(sorted.iter().skip(1).all(Option::is_none));
        assert!(Model::EMPTY.interfaces_by_id().iter().all(Option::is_none));
    }

    pub(crate) fn management() -> ManagementEntry {
        ManagementEntry {
            enabled: true,
            mac: MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x52]),
            address: Ipv4Address::from_octets([10, 0, 2, 15]),
            prefix_length: 24,
            gateway: Gateway::Stated(Ipv4Address::from_octets([10, 0, 2, 1])),
        }
    }

    #[test]
    fn one_management_interface_is_held_and_a_second_is_refused() {
        let mut model = Model::EMPTY;
        assert_eq!(model.management(), None);
        assert!(model.is_empty());
        model.set_management(management()).expect("the first");
        assert_eq!(model.management(), Some(management()));
        assert_eq!(model.set_management(management()), Err(Full));
        assert!(
            !model.is_empty(),
            "a configuration that addresses the management port is not empty"
        );
        assert_eq!(model.management_slot(), [Some(management())]);
        assert_eq!(Model::EMPTY.management_slot(), [None]);
    }

    #[test]
    fn a_model_is_copied_rather_than_moved_so_a_domain_can_hold_two() {
        let mut running = Model::EMPTY;
        running
            .push_interface(interface("wan", 0))
            .expect("capacity");
        let mut staged = running;
        staged
            .push_interface(interface("lan", 1))
            .expect("capacity");
        assert_eq!(running.interface_count(), 1);
        assert_eq!(staged.interface_count(), 2);
        assert_ne!(running, staged);
    }
}
