//! `wire`'s configuration handover image under a byzantine neighbour PD.
//!
//! # The adversary and the surface
//!
//! The configuration domain writes the handover region and the forwarding
//! domain reads it (CONTRACTS.md §6). The reader maps it read-only, but nothing
//! makes the *writer* honest: a compromised or malfunctioning configuration
//! domain is CONCEPT §7.1's byzantine neighbour, and every byte of that region
//! is then a value of its choosing. [`ConfigImage::check`] is the whole of the
//! forwarding domain's defence, so it is what this drives.
//!
//! # What the adversary may express here
//!
//! The region is a fixed-layout POD, so the fuzzer's bytes *are* the region:
//! [`image_from_region`] lays the input over the ABI field for field and zeroes
//! what the input does not reach, which is what a partially written region
//! holds. Nothing is reduced into a plausible range on the way (TEST-8), so
//! counts far past capacity, `enabled` bytes that are neither 0 nor 1, ports
//! naming hardware that does not exist, prefix lengths above 32, multicast and
//! all-zero MACs, and arbitrary padding are all ordinary inputs — as is an
//! entirely well-formed image, which the seeds carry.
//!
//! A purely uniform 656-byte blob would however spend almost every run in the
//! two count refusals and rarely reach the per-entry rules behind them. The
//! harness therefore checks a **second** image whose counts are folded into the
//! band around capacity, in addition to — never instead of — the unmodified
//! one. That widens what is reached without narrowing what is reachable, which
//! is the distinction TEST-8 turns on; the adversary's full authority is still
//! exercised on every input by the first check.
//!
//! `port_count` is varied over its own edges for the same reason. It is not the
//! adversary's: it comes from the calling domain and is the one bound the
//! writer cannot move, which is exactly why the harness must not let it be
//! taken from the region.
//!
//! # What is asserted
//!
//! * **Exact semantics, against an independent model.** [`refusal`] restates
//!   the documented rules and their order from the ABI contract rather than
//!   from the code, and every outcome is compared with it. A *wrongly accepted*
//!   image — the failure that actually reaches the dataplane — fails here as
//!   loudly as a panic would, which a harness checking only for panics would
//!   have passed.
//! * **Capacity, not the peer's count.** The entries handed back are bounded by
//!   the array the image holds and never by the number the writer put in it.
//! * **Containment of a refusal.** Every accepted entry independently satisfies
//!   every rule, and carries the bytes of the slot at its own index — a decoded
//!   entry assembled from two slots would be a configuration nobody wrote.
//! * **The count is a bound, not a hint.** Rewriting every slot the counts do
//!   not cover changes nothing about the result. That is the claim that the
//!   reader stops where it was told to, asserted rather than inferred.
//! * **Determinism.** Checking one image twice yields one answer.
//! * **The region round-trips.** An image published through [`ConfigHandover`]
//!   and read back is the same image, byte for byte and padding included: the
//!   per-byte atomic mirror is a second copy of the layout, and a field that
//!   moved in one and not the other would put a MAC where an address goes.

use arbitrary::{Arbitrary as _, Unstructured};
use wire::{
    ConfigHandover, ConfigImage, ConfigImageError, InterfaceImage, MAX_INTERFACES, MAX_NEIGHBOURS,
    MAX_PREFIX_LENGTH, NeighbourImage,
};

/// Port counts the image is checked against.
///
/// A property of the build (`config::PORT_COUNT` is 2), varied over the edges
/// that make the `port >= port_count` comparison interesting: a build with no
/// dataplane at all, one port, the real one, and a build where every `u8` names
/// a port so the comparison can never be what refuses an image.
const PORT_COUNTS: [u8; 4] = [0, 1, config::PORT_COUNT, u8::MAX];

/// Bytes of one interface entry in the region.
const INTERFACE_BYTES: usize = 16;

/// Bytes of one neighbour entry in the region.
const NEIGHBOUR_BYTES: usize = 16;

/// Bytes of the four header words the entries follow.
const HEADER_BYTES: usize = 16;

/// The whole region image, which is what one corpus entry is.
pub const REGION_BYTES: usize =
    HEADER_BYTES + MAX_INTERFACES * INTERFACE_BYTES + MAX_NEIGHBOURS * NEIGHBOUR_BYTES;

/// Drive the handover reader against a region a byzantine writer filled.
pub fn handover_harness(data: &[u8]) {
    let image = image_from_region(data);

    for port_count in PORT_COUNTS {
        check_one(&image, port_count);
    }

    // The same bytes with the counts folded into the band around capacity, so
    // the rules *behind* the count check are reached on inputs that would
    // otherwise stop at it. Additive: the unmodified image above was already
    // checked under every port count.
    let mut narrowed = image;
    narrowed.interface_count = image.interface_count % (MAX_INTERFACES as u32 + 2);
    narrowed.neighbour_count = image.neighbour_count % (MAX_NEIGHBOURS as u32 + 2);
    for port_count in PORT_COUNTS {
        check_one(&narrowed, port_count);
    }

    assert_region_round_trips(&image);
}

/// Check one image under one port count, against the model.
fn check_one(image: &ConfigImage, port_count: u8) {
    let outcome = image.check(port_count);
    assert_eq!(
        outcome,
        image.check(port_count),
        "checking one image twice gave two answers"
    );
    assert_eq!(
        outcome.err(),
        refusal(image, port_count),
        "the reader and the ABI contract disagree about this image"
    );

    let Ok(checked) = outcome else {
        return;
    };

    // Bounded by the array, never by the number the writer supplied.
    assert!(
        checked.interface_count() <= MAX_INTERFACES,
        "{} interfaces came out of an image holding {MAX_INTERFACES} slots",
        checked.interface_count()
    );
    assert!(
        checked.neighbour_count() <= MAX_NEIGHBOURS,
        "{} neighbours came out of an image holding {MAX_NEIGHBOURS} slots",
        checked.neighbour_count()
    );
    assert_eq!(
        u32::try_from(checked.interface_count()),
        Ok(image.interface_count),
        "an accepted image yielded a different number of interfaces than it declared"
    );
    assert_eq!(
        u32::try_from(checked.neighbour_count()),
        Ok(image.neighbour_count),
        "an accepted image yielded a different number of neighbours than it declared"
    );
    assert_eq!(checked.generation(), image.generation);
    assert_eq!(checked.content_hash(), image.content_hash);

    for (index, interface) in checked.interfaces().enumerate() {
        let raw = image
            .interfaces
            .get(index)
            .expect("an entry is bounded by the array it came from");
        assert_eq!(interface.port(), raw.port);
        assert_eq!(interface.prefix_length(), raw.prefix_length);
        assert_eq!(interface.mac(), raw.mac);
        assert_eq!(interface.address(), raw.address);
        assert_eq!(u8::from(interface.enabled()), raw.enabled);

        assert!(
            interface.port() < port_count,
            "an unknown port was accepted"
        );
        assert!(
            interface.prefix_length() <= MAX_PREFIX_LENGTH,
            "a prefix length past {MAX_PREFIX_LENGTH} was accepted"
        );
        assert!(
            is_unicast(interface.mac()),
            "an interface would forward under a MAC that is not unicast"
        );
    }

    for (index, neighbour) in checked.neighbours().enumerate() {
        let raw = image
            .neighbours
            .get(index)
            .expect("an entry is bounded by the array it came from");
        assert_eq!(neighbour.port(), raw.port);
        assert_eq!(neighbour.mac(), raw.mac);
        assert_eq!(neighbour.address(), raw.address);

        assert!(
            neighbour.port() < port_count,
            "an unknown port was accepted"
        );
        assert!(
            is_unicast(neighbour.mac()),
            "a frame would be unicast to a MAC that is not one"
        );
    }

    assert_slots_past_the_counts_are_not_read(image, port_count, &checked);
}

/// Rewrite every slot the counts do not cover and assert the answer does not
/// move. A reader that walked its arrays instead of its counts would decode an
/// entry out of bytes the writer did not declare.
fn assert_slots_past_the_counts_are_not_read(
    image: &ConfigImage,
    port_count: u8,
    checked: &wire::CheckedConfig,
) {
    let mut scribbled = *image;
    let interfaces = image.interface_count as usize;
    let neighbours = image.neighbour_count as usize;
    for slot in scribbled.interfaces.iter_mut().skip(interfaces) {
        *slot = SCRIBBLED_INTERFACE;
    }
    for slot in scribbled.neighbours.iter_mut().skip(neighbours) {
        *slot = SCRIBBLED_NEIGHBOUR;
    }
    assert_eq!(
        scribbled.check(port_count).as_ref(),
        Ok(checked),
        "rewriting the slots past the counts changed what the reader decoded"
    );
}

/// A slot no rule admits, so reading one would be visible in the outcome
/// whatever else the region held: every field is refused by something.
const SCRIBBLED_INTERFACE: InterfaceImage = InterfaceImage {
    port: u8::MAX,
    enabled: 0xAA,
    prefix_length: u8::MAX,
    _pad: 0xAA,
    mac: [0xFF; 6],
    _pad2: [0xAA; 2],
    address: [0xAA; 4],
};

/// As [`SCRIBBLED_INTERFACE`], for a neighbour.
const SCRIBBLED_NEIGHBOUR: NeighbourImage = NeighbourImage {
    port: u8::MAX,
    _pad: [0xAA; 3],
    mac: [0xFF; 6],
    _pad2: [0xAA; 2],
    address: [0xAA; 4],
};

/// What the ABI contract says this image is refused for, derived from the image
/// alone — restated here so the harness is not checking the code against
/// itself. `None` is an image every rule admits.
///
/// The order is part of the contract and not an accident of the loop: the
/// counts are decided before any entry, interfaces before neighbours, and
/// within an interface `enabled`, then the port, then the prefix, then the MAC.
/// A reader that refused a different field first would still be refusing, and
/// an operator would be sent to the wrong line.
fn refusal(image: &ConfigImage, port_count: u8) -> Option<ConfigImageError> {
    let interfaces = usize::try_from(image.interface_count).ok()?;
    if interfaces > MAX_INTERFACES {
        return Some(ConfigImageError::InterfaceCountExceedsCapacity {
            count: image.interface_count,
        });
    }
    let neighbours = usize::try_from(image.neighbour_count).ok()?;
    if neighbours > MAX_NEIGHBOURS {
        return Some(ConfigImageError::NeighbourCountExceedsCapacity {
            count: image.neighbour_count,
        });
    }

    for (index, entry) in image.interfaces.iter().enumerate().take(interfaces) {
        if entry.enabled > 1 {
            return Some(ConfigImageError::InterfaceEnabledNotBoolean {
                index,
                enabled: entry.enabled,
            });
        }
        if entry.port >= port_count {
            return Some(ConfigImageError::InterfacePortUnknown {
                index,
                port: entry.port,
            });
        }
        if entry.prefix_length > MAX_PREFIX_LENGTH {
            return Some(ConfigImageError::InterfacePrefixLengthTooLong {
                index,
                prefix_length: entry.prefix_length,
            });
        }
        if !is_unicast(entry.mac) {
            return Some(ConfigImageError::InterfaceMacNotUnicast {
                index,
                mac: entry.mac,
            });
        }
    }

    for (index, entry) in image.neighbours.iter().enumerate().take(neighbours) {
        if entry.port >= port_count {
            return Some(ConfigImageError::NeighbourPortUnknown {
                index,
                port: entry.port,
            });
        }
        if !is_unicast(entry.mac) {
            return Some(ConfigImageError::NeighbourMacNotUnicast {
                index,
                mac: entry.mac,
            });
        }
    }

    None
}

/// A unicast MAC: the IEEE 802.3 group bit clear, and not the all-zero address.
/// Restated from the ABI contract rather than reached for in `wire`, which is
/// the code under test.
fn is_unicast(mac: [u8; 6]) -> bool {
    mac[0] & 0x01 == 0 && mac != [0; 6]
}

/// Publish an image into a handover region and read it back, which is the path
/// the two domains actually use.
fn assert_region_round_trips(image: &ConfigImage) {
    let region = ConfigHandover::zero();
    assert_eq!(region.offered_generation(), 0);
    assert_eq!(
        region.load_image(),
        ConfigImage::ZERO,
        "a zeroed region is not the fail-closed configuration"
    );

    region.publish(image);
    assert_eq!(
        region.offered_generation(),
        image.generation,
        "the region offered a generation other than the one written into it"
    );
    assert_eq!(
        region.load_image(),
        *image,
        "the image did not survive the region it crosses domains through"
    );

    region.publish_committed(image.content_hash);
    assert_eq!(region.committed_generation(), image.content_hash);
    assert_eq!(
        region.offered_generation(),
        image.generation,
        "committing a generation moved the offer"
    );
}

/// Lay the input over the region's ABI, field for field, zeroing whatever the
/// input does not reach.
///
/// Positional rather than derived through [`arbitrary`]'s own layout, for two
/// reasons: a corpus entry is then literally the region a writer left behind,
/// so a seed can be authored and read as one; and the mapping stays fixed
/// whatever `arbitrary` does internally, so a curated regression seed keeps
/// meaning the image it was committed for. Little-endian because the target is
/// x86_64 and nothing else (CON-4).
#[must_use]
pub fn image_from_region(data: &[u8]) -> ConfigImage {
    let mut unstructured = Unstructured::new(data);
    let mut image = ConfigImage {
        generation: word(&mut unstructured),
        interface_count: word(&mut unstructured),
        neighbour_count: word(&mut unstructured),
        content_hash: word(&mut unstructured),
        ..ConfigImage::ZERO
    };
    for slot in &mut image.interfaces {
        *slot = InterfaceImage {
            port: byte(&mut unstructured),
            enabled: byte(&mut unstructured),
            prefix_length: byte(&mut unstructured),
            _pad: byte(&mut unstructured),
            mac: bytes(&mut unstructured),
            _pad2: bytes(&mut unstructured),
            address: bytes(&mut unstructured),
        };
    }
    for slot in &mut image.neighbours {
        *slot = NeighbourImage {
            port: byte(&mut unstructured),
            _pad: bytes(&mut unstructured),
            mac: bytes(&mut unstructured),
            _pad2: bytes(&mut unstructured),
            address: bytes(&mut unstructured),
        };
    }
    image
}

/// The next region word, zero once the input is spent — which is what an
/// unwritten part of a freshly mapped region holds.
fn word(unstructured: &mut Unstructured<'_>) -> u32 {
    crate::any_u32(unstructured)
}

/// The next region byte; see [`word`].
fn byte(unstructured: &mut Unstructured<'_>) -> u8 {
    u8::arbitrary(unstructured).unwrap_or(0)
}

/// The next `N` region bytes; see [`word`].
fn bytes<const N: usize>(unstructured: &mut Unstructured<'_>) -> [u8; N] {
    let mut out = [0u8; N];
    for slot in &mut out {
        *slot = byte(unstructured);
    }
    out
}
