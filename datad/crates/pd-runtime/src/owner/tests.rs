use super::*;
use proptest::prelude::*;

/// A domain that has read nothing forwards nothing. The state a forwarder is in
/// between mapping the region and its first wakeup, and the only safe answer for
/// it.
#[test]
fn a_watch_that_has_never_polled_is_unowned() {
    assert_eq!(OwnershipWatch::new().ownership(), Ownership::Unowned);
}

#[test]
fn an_unpublished_region_leaves_the_watch_unowned() {
    let region = ApplianceOwnership::zero();
    let mut watch = OwnershipWatch::new();
    assert_eq!(watch.poll(&region), OwnershipChange::Unchanged);
    assert_eq!(watch.ownership(), Ownership::Unowned);
}

/// The one transition a boot can carry, reported exactly once so the record it
/// drives is emitted once however often the domain wakes.
#[test]
fn the_adoption_is_reported_on_the_reading_that_sees_it_and_no_other() {
    let region = ApplianceOwnership::zero();
    let mut watch = OwnershipWatch::new();
    assert_eq!(watch.poll(&region), OwnershipChange::Unchanged);

    region.publish(true);
    assert_eq!(watch.poll(&region), OwnershipChange::Adopted);
    assert_eq!(watch.ownership(), Ownership::Owned);

    for _ in 0..8 {
        assert_eq!(watch.poll(&region), OwnershipChange::Unchanged);
        assert_eq!(watch.ownership(), Ownership::Owned);
    }
}

/// The latch, stated against the adversary it exists for: the writing domain is
/// a peer, and a peer that could clear this word would hold a switch over the
/// whole dataplane.
#[test]
fn a_writer_that_clears_the_word_does_not_stop_forwarding() {
    let region = ApplianceOwnership::zero();
    let mut watch = OwnershipWatch::new();
    region.publish(true);
    assert_eq!(watch.poll(&region), OwnershipChange::Adopted);

    region.publish(false);
    assert_eq!(watch.poll(&region), OwnershipChange::Unchanged);
    assert_eq!(watch.ownership(), Ownership::Owned);
}

proptest! {
    /// Whatever a peer writes, in whatever order: the belief only ever goes
    /// unowned to owned, and the adoption is reported exactly once.
    #[test]
    fn ownership_is_monotone_and_adoption_is_reported_once(writes: Vec<bool>) {
        let region = ApplianceOwnership::zero();
        let mut watch = OwnershipWatch::new();
        let mut adoptions = 0usize;
        let mut previous = Ownership::Unowned;
        for write in &writes {
            region.publish(*write);
            if watch.poll(&region) == OwnershipChange::Adopted {
                adoptions += 1;
            }
            prop_assert!(
                previous != Ownership::Owned || watch.ownership() == Ownership::Owned,
                "the watch went back to unowned"
            );
            previous = watch.ownership();
        }
        prop_assert_eq!(adoptions, usize::from(writes.iter().any(|write| *write)));
        prop_assert_eq!(
            watch.ownership(),
            Ownership::of(writes.iter().any(|write| *write))
        );
    }
}
