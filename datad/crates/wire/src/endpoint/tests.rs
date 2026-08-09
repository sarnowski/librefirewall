use super::*;
use proptest::prelude::*;

/// The state a domain finds when it maps a region nobody has published into, and
/// the one an appliance nobody has onboarded leaves behind: nowhere to dial.
#[test]
fn a_zeroed_region_reads_as_nowhere() {
    assert_eq!(ManagementEndpoint::zero().destination(), None);
}

#[test]
fn a_published_destination_is_read_back() {
    let region = ManagementEndpoint::zero();
    let published = ManagementDestination {
        address: [10, 0, 2, 2],
        port: 8443,
    };
    region.publish(published);
    assert_eq!(region.destination(), Some(published));
}

/// The octets keep their order across the word, which is the one way this could
/// be wrong and still look right: an address read back byte-reversed is a
/// different host, and a certificate validated against it would fail somewhere
/// far from here.
#[test]
fn the_octets_keep_their_order() {
    let region = ManagementEndpoint::zero();
    region.publish(ManagementDestination {
        address: [1, 2, 3, 4],
        port: 1,
    });
    assert_eq!(
        region.destination(),
        Some(ManagementDestination {
            address: [1, 2, 3, 4],
            port: 1,
        })
    );
}

/// The writer can state the absence, and it reads back as the zeroed region does
/// — the two are one answer, which is what keeps the reader from having a third
/// case to decide about.
#[test]
fn a_cleared_region_reads_as_nowhere() {
    let region = ManagementEndpoint::zero();
    region.publish(ManagementDestination {
        address: [10, 0, 2, 2],
        port: 8443,
    });
    region.clear();
    assert_eq!(region.destination(), None);
}

/// A writer holding half a destination publishes the absence rather than a word
/// its own reader would reject, so the absence has one spelling in this region
/// whichever side put it there.
#[test]
fn half_a_destination_is_published_as_the_absence() {
    for half in [
        ManagementDestination {
            address: [10, 0, 2, 2],
            port: 0,
        },
        ManagementDestination {
            address: [0, 0, 0, 0],
            port: 8443,
        },
        ManagementDestination {
            address: [0, 0, 0, 0],
            port: 0,
        },
    ] {
        let region = ManagementEndpoint::zero();
        region.publish(ManagementDestination {
            address: [10, 0, 2, 2],
            port: 8443,
        });
        region.publish(half);
        assert_eq!(
            region.destination(),
            None,
            "{half:?} was published as somewhere to dial"
        );
    }
}

/// The three tests are independent, and each one alone answers nowhere. Stated
/// over words composed by hand rather than through `publish`, because a
/// compromised writer does not go through `publish`.
#[test]
fn each_test_alone_refuses_the_word() {
    let region = ManagementEndpoint::zero();
    let tagged = |port: u64, address: u64| {
        (u64::from(ENDPOINT_TAG) << (ADDRESS_BITS + PORT_BITS)) | (port << ADDRESS_BITS) | address
    };
    for (word, why) in [
        (tagged(8443, 0x0a00_0202) ^ (1 << 63), "an untagged word"),
        (tagged(0, 0x0a00_0202), "a port of zero under the tag"),
        (tagged(8443, 0), "an unspecified address under the tag"),
        (0x0a00_0202, "an address with no tag at all"),
        (u64::MAX, "every bit set"),
    ] {
        region.word.store(word, Ordering::Relaxed);
        assert_eq!(
            region.destination(),
            None,
            "{why} ({word:#x}) was read as somewhere to dial"
        );
    }
}

proptest! {
    /// The property stated over the whole input space: a compromised writer
    /// chooses this word, and its only reach is between a destination it could
    /// have published honestly and nowhere at all. In particular no word it can
    /// choose yields a port of zero or an unspecified address, which are the two
    /// plausible-looking nothings.
    #[test]
    fn any_word_reads_as_a_dialable_destination_or_as_nowhere(word: u64) {
        let region = ManagementEndpoint::zero();
        region.word.store(word, Ordering::Relaxed);
        match region.destination() {
            None => prop_assert!(true),
            Some(destination) => {
                prop_assert_ne!(destination.port, 0);
                prop_assert_ne!(u32::from_be_bytes(destination.address), 0);
                prop_assert_eq!(word >> (ADDRESS_BITS + PORT_BITS), u64::from(ENDPOINT_TAG));
            }
        }
    }

    /// Every destination a writer can honestly publish survives the round trip
    /// whole, which is the other half of the claim above: the fail-closed reading
    /// refuses nothing that was really published.
    #[test]
    fn a_dialable_destination_survives_the_round_trip(octets: [u8; 4], port in 1_u16..=u16::MAX) {
        prop_assume!(u32::from_be_bytes(octets) != 0);
        let region = ManagementEndpoint::zero();
        let published = ManagementDestination { address: octets, port };
        region.publish(published);
        prop_assert_eq!(region.destination(), Some(published));
    }

    /// A writer publishing repeatedly leaves the region saying what it last said,
    /// with no accumulated state — there being none to accumulate.
    #[test]
    fn the_region_carries_the_last_publication(
        destinations: Vec<([u8; 4], u16)>,
    ) {
        let region = ManagementEndpoint::zero();
        let mut last = None;
        for (address, port) in destinations {
            let destination = ManagementDestination { address, port };
            region.publish(destination);
            last = (port != 0 && u32::from_be_bytes(address) != 0).then_some(destination);
        }
        prop_assert_eq!(region.destination(), last);
    }
}
