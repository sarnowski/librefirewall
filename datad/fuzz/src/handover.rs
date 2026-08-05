//! `wire`'s configuration handover image under a byzantine neighbour PD.
//!
//! # The adversary and the surface
//!
//! The configuration domain writes the handover region and the forwarding
//! domain reads it. The reader maps it read-only, but nothing
//! makes the *writer* honest: a compromised or malfunctioning configuration
//! domain is a byzantine neighbour, and every byte of that region
//! is then a value of its choosing. [`ConfigImage::check`] is the whole of the
//! forwarding domain's defence, so it is what this drives.
//!
//! # What the adversary may express here
//!
//! The region is a fixed-layout POD, so the fuzzer's bytes *are* the region:
//! [`image_from_region`] lays the input over the ABI field for field and zeroes
//! what the input does not reach, which is what a partially written region
//! holds. Nothing is reduced into a plausible range on the way, so
//! counts far past capacity, `enabled` bytes that are neither 0 nor 1, ports
//! naming hardware that does not exist, prefix lengths above 32, multicast and
//! all-zero MACs, and arbitrary padding are all ordinary inputs — as is an
//! entirely well-formed image, which the seeds carry.
//!
//! Every field means the management entry too. It is not a corner of the image:
//! it carries the address the appliance answers management traffic at, and the
//! two rules that keep that address and its L2 address off the dataplane are
//! the two the capability grants cannot express — so they are exactly the two a
//! compromised writer would have to itself if this harness did not reach them.
//!
//! A purely uniform region-sized blob would however spend almost every run in
//! the two count refusals and rarely reach the per-entry rules behind them. The
//! harness therefore checks a **second** image whose counts are folded into the
//! band around capacity, in addition to — never instead of — the unmodified
//! one. That widens what is reached without narrowing what is reachable —
//! the distinction that matters; the adversary's full authority is still
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
//!   have passed. The model covers every rule the reader applies, the ones
//!   about a *pair* of entries included: one port and one MAC per interface,
//!   disjoint prefixes, a neighbour on the link its port names, and the
//!   management port disjoint from every dataplane one. A model that stopped at
//!   the per-field rules would agree with a reader that had also stopped there,
//!   and the two agreeing is the whole of what this asserts.
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
    MAX_PREFIX_LENGTH, MAX_RULES, NeighbourImage, RuleCriterion, RuleImage,
};

/// Port counts the image is checked against.
///
/// A property of the build (`config::PORT_COUNT` is 2), varied over the edges
/// that make the `port >= port_count` comparison interesting: a build with no
/// dataplane at all, one port, the real one, and a build where every `u8` names
/// a port so the comparison can never be what refuses an image.
const PORT_COUNTS: [u8; 4] = [0, 1, config::PORT_COUNT, u8::MAX];

/// Bytes of one interface entry in the region: port, `enabled`, prefix length
/// and a pad byte; six of MAC and two of pad; four of address; then the
/// identifier's sixteen bytes, its length and three of pad.
const INTERFACE_BYTES: usize = 36;

/// Bytes of one neighbour entry in the region.
const NEIGHBOUR_BYTES: usize = 16;

/// Bytes of one rule entry: the action and the eight stated flags interleaved
/// with their one-byte values, the two networks, a pad, the four port halves,
/// and the identifier's twenty.
const RULE_BYTES: usize = 54;

/// Bytes of the count word the rules array follows.
const RULE_COUNT_BYTES: usize = 4;

/// Bytes of the management entry, which sits between the header and the
/// interfaces: the enable and prefix bytes, the gateway's stated flag, a pad,
/// the MAC and its pad, the address, and the gateway.
const MANAGEMENT_BYTES: usize = 20;

/// Bytes of the four header words the management entry follows.
const HEADER_BYTES: usize = 16;

/// The whole region image, which is what one corpus entry is.
pub const REGION_BYTES: usize = HEADER_BYTES
    + MANAGEMENT_BYTES
    + MAX_INTERFACES * INTERFACE_BYTES
    + MAX_NEIGHBOURS * NEIGHBOUR_BYTES
    + RULE_COUNT_BYTES
    + MAX_RULES * RULE_BYTES;

// The point of laying the input over the ABI positionally is that a corpus
// entry *is* the region a writer left behind. That only holds while the two
// agree byte for byte, and a seed authored against the wrong stride decodes as
// a different image than the one it was committed for — silently, because it
// still decodes as something. So the sum above is held to the type: a field
// added or a pad widened in `wire` breaks this build rather than the meaning of
// every file in the corpus.
const _: () = assert!(REGION_BYTES == core::mem::size_of::<ConfigImage>());

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
    narrowed.rule_count = image.rule_count % (MAX_RULES as u32 + 2);
    for port_count in PORT_COUNTS {
        check_one(&narrowed, port_count);
    }

    // And the same bytes *sealed*, which is what a publisher hands over. Without
    // it almost every input would stop at the digest and the whole per-entry half
    // of this harness would go unreached — while dropping the two unsealed checks
    // above would give up the adversary's authority to write any bytes at all, so
    // both are driven and neither replaces the other.
    let mut sealed = narrowed;
    sealed.seal();
    for port_count in PORT_COUNTS {
        check_one(&sealed, port_count);
    }

    assert_no_blend_is_taken_for_an_image(&sealed, &image);
    assert_region_round_trips(&sealed);
}

/// A copy assembled from two publications is refused, unless the fields taken
/// happen to make it one of them again.
///
/// This is the shape no per-field rule can catch: every entry of a blend is an
/// entry some publisher wrote, so each passes on its own. What refuses it is the
/// digest over the whole image, and this is where that claim is exercised on
/// arbitrary bytes rather than on a fixture.
fn assert_no_blend_is_taken_for_an_image(one: &ConfigImage, other: &ConfigImage) {
    let blends = [
        ConfigImage {
            interfaces: other.interfaces,
            ..*one
        },
        ConfigImage {
            rule_count: other.rule_count,
            ..*one
        },
        ConfigImage {
            rules: other.rules,
            ..*one
        },
        ConfigImage {
            management: other.management,
            ..*one
        },
    ];
    for blend in blends {
        if blend == *one || blend == *other {
            continue;
        }
        for port_count in PORT_COUNTS {
            assert_eq!(
                blend.check(port_count).err(),
                Some(ConfigImageError::DigestMismatch {
                    declared: blend.digest,
                    folded: blend.computed_digest(),
                }),
                "a copy assembled from two publications was taken for one image"
            );
        }
    }
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
    for slot in scribbled.rules.iter_mut().skip(image.rule_count as usize) {
        *slot = SCRIBBLED_RULE;
    }
    // Re-sealed, because the digest covers every byte of the image and a rewrite
    // past the counts is therefore a *different* image — refused for being one,
    // which is that check working rather than this claim failing. Sealing again
    // is what leaves the claim under test on its own: the reader stops where the
    // counts told it to, and the bytes beyond them decode nothing.
    scribbled.seal();
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
    _pad: [0xAA; 1],
    mac: [0xFF; 6],
    _pad2: [0xAA; 2],
    address: [0xAA; 4],
    // A length past the storage and bytes outside the alphabet, so this field is
    // refused twice over like every other one here.
    id: wire::TextImage {
        bytes: [0xAA; wire::LOG_IDENTIFIER_BYTES],
        len: u8::MAX,
        _pad: [0xAA; 3],
    },
};

/// As [`SCRIBBLED_INTERFACE`], for a rule: the action is unknown, every stated
/// flag is neither 0 nor 1, and the id is both too long and outside the
/// alphabet — so a reader that decoded one would refuse, whatever else the
/// region held.
const SCRIBBLED_RULE: RuleImage = RuleImage {
    action: 0xAA,
    ingress_stated: 0xAA,
    ingress_port: u8::MAX,
    egress_stated: 0xAA,
    egress_port: u8::MAX,
    source_stated: 0xAA,
    source_prefix_length: u8::MAX,
    destination_stated: 0xAA,
    source_network: [0xAA; 4],
    destination_network: [0xAA; 4],
    destination_prefix_length: u8::MAX,
    protocol_stated: 0xAA,
    protocol: 0xAA,
    icmp_type_stated: 0xAA,
    icmp_type: 0xAA,
    tracking_stated: 0xAA,
    tracking: 0xAA,
    source_port_stated: 0xAA,
    destination_port_stated: 0xAA,
    _pad: [0xAA; 1],
    source_port_low: u16::MAX,
    source_port_high: 0,
    destination_port_low: u16::MAX,
    destination_port_high: 0,
    id: wire::TextImage {
        bytes: [0xAA; wire::LOG_IDENTIFIER_BYTES],
        len: u8::MAX,
        _pad: [0xAA; 3],
    },
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
    // First, and before every count: an image that does not fold to the word it
    // carries is not one publication, so nothing else about it is a fact.
    let folded = image.computed_digest();
    if folded != image.digest {
        return Some(ConfigImageError::DigestMismatch {
            declared: image.digest,
            folded,
        });
    }
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
    let rules = usize::try_from(image.rule_count).ok()?;
    if rules > MAX_RULES {
        return Some(ConfigImageError::RuleCountExceedsCapacity {
            count: image.rule_count,
        });
    }
    let named: Vec<InterfaceImage> = image.interfaces.iter().copied().take(interfaces).collect();

    for (index, entry) in named.iter().enumerate() {
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
        if !is_unicast_address(entry.address) {
            return Some(ConfigImageError::InterfaceAddressNotUnicast {
                index,
                address: entry.address,
            });
        }
        if !is_host_address(entry.address, entry.prefix_length) {
            return Some(ConfigImageError::InterfaceAddressNotAHostAddress {
                index,
                address: entry.address,
            });
        }
        if let Some(fault) = identifier_fault(&entry.id) {
            return Some(ConfigImageError::InterfaceIdNotAnIdentifier { index, fault });
        }
    }

    // The rules about a pair of interfaces. A forwarding domain looks an
    // interface up by port and a frame up by MAC, so two entries agreeing on
    // either make the answer depend on table position.
    for (index, entry) in named.iter().enumerate() {
        for (other, earlier) in named.iter().enumerate().take(index) {
            if identifier_text(&earlier.id) == identifier_text(&entry.id) {
                return Some(ConfigImageError::InterfaceIdDuplicated { index, other });
            }
            if earlier.port == entry.port {
                return Some(ConfigImageError::InterfacePortDuplicated {
                    index,
                    other,
                    port: entry.port,
                });
            }
            if earlier.mac == entry.mac {
                return Some(ConfigImageError::InterfaceMacDuplicated {
                    index,
                    other,
                    mac: entry.mac,
                });
            }
            if prefixes_overlap(
                earlier.address,
                earlier.prefix_length,
                entry.address,
                entry.prefix_length,
            ) {
                return Some(ConfigImageError::InterfacePrefixesOverlap { index, other });
            }
        }
    }

    let hops: Vec<NeighbourImage> = image.neighbours.iter().copied().take(neighbours).collect();
    for (index, entry) in hops.iter().enumerate() {
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
        if !is_unicast_address(entry.address) {
            return Some(ConfigImageError::NeighbourAddressNotUnicast {
                index,
                address: entry.address,
            });
        }
        let Some(interface) = named.iter().find(|candidate| candidate.port == entry.port) else {
            return Some(ConfigImageError::NeighbourPortUnconfigured {
                index,
                port: entry.port,
            });
        };
        if entry.address == interface.address {
            return Some(ConfigImageError::NeighbourIsInterfaceAddress {
                index,
                address: entry.address,
            });
        }
        if !inside_prefix(entry.address, interface.address, interface.prefix_length) {
            return Some(ConfigImageError::NeighbourOutsidePrefix {
                index,
                address: entry.address,
            });
        }
        if !is_host_address(entry.address, interface.prefix_length) {
            return Some(ConfigImageError::NeighbourAddressNotAHostAddress {
                index,
                address: entry.address,
            });
        }
    }
    for (index, entry) in hops.iter().enumerate() {
        for (other, earlier) in hops.iter().enumerate().take(index) {
            if earlier.port == entry.port && earlier.address == entry.address {
                return Some(ConfigImageError::NeighbourAddressDuplicated { index, other });
            }
        }
    }

    let policy: Vec<RuleImage> = image.rules.iter().copied().take(rules).collect();
    for (index, entry) in policy.iter().enumerate() {
        if let Some(refusal) = rule_refusal(entry, index, port_count, &named) {
            return Some(refusal);
        }
        // The id is the last thing a rule is held to, so a duplicate is only
        // reached once both entries are well formed — which is why this sits
        // after the per-rule pass rather than inside it.
        for (other, earlier) in policy.iter().enumerate().take(index) {
            if rule_refusal(earlier, other, port_count, &named).is_none()
                && identifier_text(&earlier.id) == identifier_text(&entry.id)
            {
                return Some(ConfigImageError::RuleIdDuplicated { index, other });
            }
        }
    }

    let management = image.management;
    if management.enabled > 1 {
        return Some(ConfigImageError::ManagementEnabledNotBoolean {
            enabled: management.enabled,
        });
    }
    // A disabled entry is held to nothing: the reader interprets none of its
    // other fields, so there is no value for a rule to be about.
    if management.enabled == 1 {
        if management.prefix_length > MAX_PREFIX_LENGTH {
            return Some(ConfigImageError::ManagementPrefixLengthTooLong {
                prefix_length: management.prefix_length,
            });
        }
        if !is_unicast(management.mac) {
            return Some(ConfigImageError::ManagementMacNotUnicast {
                mac: management.mac,
            });
        }
        if !is_unicast_address(management.address) {
            return Some(ConfigImageError::ManagementAddressNotUnicast {
                address: management.address,
            });
        }
        if !is_host_address(management.address, management.prefix_length) {
            return Some(ConfigImageError::ManagementAddressNotAHostAddress {
                address: management.address,
            });
        }
        // The two the capability grants cannot express, and so the two a
        // compromised writer would otherwise have had to itself.
        for (index, interface) in named.iter().enumerate() {
            if prefixes_overlap(
                interface.address,
                interface.prefix_length,
                management.address,
                management.prefix_length,
            ) {
                return Some(ConfigImageError::ManagementPrefixCollidesWithInterface { index });
            }
            if interface.mac == management.mac {
                return Some(ConfigImageError::ManagementMacCollidesWithInterface { index });
            }
        }
        // The gateway last, and every one of these is about its relationship
        // to the address above rather than about the gateway alone.
        if management.gateway_stated > 1 {
            return Some(ConfigImageError::ManagementGatewayStatedNotBoolean {
                stated: management.gateway_stated,
            });
        }
        if management.gateway_stated == 1 {
            if !is_unicast_address(management.gateway) {
                return Some(ConfigImageError::ManagementGatewayNotUnicast {
                    gateway: management.gateway,
                });
            }
            if management.gateway == management.address {
                return Some(ConfigImageError::ManagementGatewayIsTheAddress {
                    gateway: management.gateway,
                });
            }
            if !inside_prefix(
                management.gateway,
                management.address,
                management.prefix_length,
            ) {
                return Some(ConfigImageError::ManagementGatewayOffLink {
                    gateway: management.gateway,
                });
            }
        }
    }

    None
}

/// What the ABI contract says one rule is refused for, in the reader's own order:
/// the action, then each criterion's stated flag and value in the order the image
/// lays them out, then the two rules *between* criteria, then the identity.
///
/// The order is the contract because an operator reading a refusal is sent to one
/// attribute of one rule. A reader that refused a different criterion first would
/// still be refusing, and would send them to the wrong line.
fn rule_refusal(
    raw: &RuleImage,
    index: usize,
    port_count: u8,
    interfaces: &[InterfaceImage],
) -> Option<ConfigImageError> {
    // Every stated flag, in the order the reader decodes them, because a flag
    // that is neither 0 nor 1 is refused before any value it guards is read.
    let flags = [
        (raw.ingress_stated, RuleCriterion::Ingress),
        (raw.egress_stated, RuleCriterion::Egress),
        (raw.source_stated, RuleCriterion::Source),
        (raw.destination_stated, RuleCriterion::Destination),
        (raw.protocol_stated, RuleCriterion::Protocol),
        (raw.source_port_stated, RuleCriterion::SourcePort),
        (raw.destination_port_stated, RuleCriterion::DestinationPort),
        (raw.icmp_type_stated, RuleCriterion::IcmpType),
    ];
    let stated = |criterion: RuleCriterion| {
        flags
            .iter()
            .find(|(_, named)| *named == criterion)
            .is_some_and(|(flag, _)| *flag == 1)
    };

    if raw.action > 1 {
        return Some(ConfigImageError::RuleActionUnknown {
            index,
            action: raw.action,
        });
    }
    // The interface criteria first, and each of them decodes its own flag before
    // the next criterion's is looked at.
    for (criterion, flag, port) in [
        (RuleCriterion::Ingress, raw.ingress_stated, raw.ingress_port),
        (RuleCriterion::Egress, raw.egress_stated, raw.egress_port),
    ] {
        if flag > 1 {
            return Some(ConfigImageError::RuleCriterionNotBoolean {
                index,
                criterion,
                stated: flag,
            });
        }
        if flag == 0 {
            continue;
        }
        if port >= port_count {
            return Some(ConfigImageError::RulePortUnknown {
                index,
                criterion,
                port,
            });
        }
        if !interfaces.iter().any(|entry| entry.port == port) {
            return Some(ConfigImageError::RulePortUnconfigured {
                index,
                criterion,
                port,
            });
        }
    }
    // Then the two address blocks: a length inside 32, and a network whose host
    // bits are clear — a block written `10.0.0.5/24` covers `10.0.0.0/24` and is
    // a line an operator wrote meaning something else.
    for (criterion, flag, network, prefix_length) in [
        (
            RuleCriterion::Source,
            raw.source_stated,
            raw.source_network,
            raw.source_prefix_length,
        ),
        (
            RuleCriterion::Destination,
            raw.destination_stated,
            raw.destination_network,
            raw.destination_prefix_length,
        ),
    ] {
        if flag > 1 {
            return Some(ConfigImageError::RuleCriterionNotBoolean {
                index,
                criterion,
                stated: flag,
            });
        }
        if flag == 0 {
            continue;
        }
        if prefix_length > MAX_PREFIX_LENGTH {
            return Some(ConfigImageError::RulePrefixLengthTooLong {
                index,
                criterion,
                prefix_length,
            });
        }
        if u32::from_be_bytes(network) & !prefix_mask(prefix_length) != 0 {
            return Some(ConfigImageError::RulePrefixNotCanonical {
                index,
                criterion,
                network,
            });
        }
    }
    if raw.protocol_stated > 1 {
        return Some(ConfigImageError::RuleCriterionNotBoolean {
            index,
            criterion: RuleCriterion::Protocol,
            stated: raw.protocol_stated,
        });
    }
    // Then the two port criteria: a range at all, which is a low no higher than
    // its high.
    for (criterion, flag, low, high) in [
        (
            RuleCriterion::SourcePort,
            raw.source_port_stated,
            raw.source_port_low,
            raw.source_port_high,
        ),
        (
            RuleCriterion::DestinationPort,
            raw.destination_port_stated,
            raw.destination_port_low,
            raw.destination_port_high,
        ),
    ] {
        if flag > 1 {
            return Some(ConfigImageError::RuleCriterionNotBoolean {
                index,
                criterion,
                stated: flag,
            });
        }
        if flag == 1 && low > high {
            return Some(ConfigImageError::RulePortRangeReversed {
                index,
                criterion,
                low,
                high,
            });
        }
    }
    if raw.icmp_type_stated > 1 {
        return Some(ConfigImageError::RuleCriterionNotBoolean {
            index,
            criterion: RuleCriterion::IcmpType,
            stated: raw.icmp_type_stated,
        });
    }

    // The two rules between criteria, both about a rule that would match
    // nothing: ports on ICMP, and an ICMP type on anything else.
    if stated(RuleCriterion::Protocol) && raw.protocol == ICMP_PROTOCOL {
        for criterion in [RuleCriterion::SourcePort, RuleCriterion::DestinationPort] {
            if stated(criterion) {
                return Some(ConfigImageError::RulePortCriterionOnIcmp { index, criterion });
            }
        }
    }
    if stated(RuleCriterion::IcmpType)
        && stated(RuleCriterion::Protocol)
        && raw.protocol != ICMP_PROTOCOL
    {
        return Some(ConfigImageError::RuleIcmpTypeOnNonIcmp {
            index,
            protocol: raw.protocol,
        });
    }

    identifier_fault(&raw.id).map(|fault| ConfigImageError::RuleIdNotAnIdentifier { index, fault })
}

/// The IANA number for ICMP, restated from the ABI contract for the reason every
/// other constant here is: reaching for `wire`'s would be checking the code
/// against itself.
const ICMP_PROTOCOL: u8 = 1;

/// The bytes an id names. Only reached once [`identifier_fault`] has admitted
/// both sides, so the stated length is inside the storage.
fn identifier_text(id: &wire::IdentifierImage) -> &[u8] {
    id.bytes.get(..usize::from(id.len)).unwrap_or_default()
}

/// A unicast IPv4 address, restated from the ABI contract: neither multicast,
/// the limited broadcast, loopback nor unspecified.
fn is_unicast_address(address: [u8; 4]) -> bool {
    let bits = u32::from_be_bytes(address);
    bits & 0xf000_0000 != 0xe000_0000
        && bits != u32::MAX
        && bits & 0xff00_0000 != 0x7f00_0000
        && bits != 0
}

/// The mask a prefix of `prefix_length` bits selects.
fn prefix_mask(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else if prefix_length >= MAX_PREFIX_LENGTH {
        u32::MAX
    } else {
        u32::MAX << MAX_PREFIX_LENGTH.saturating_sub(prefix_length)
    }
}

/// An address a host may hold under `prefix_length` rather than the prefix's
/// network or broadcast address. A `/31` and a `/32` reserve neither (RFC 3021).
fn is_host_address(address: [u8; 4], prefix_length: u8) -> bool {
    if prefix_length >= MAX_PREFIX_LENGTH.saturating_sub(1) {
        return true;
    }
    let bits = u32::from_be_bytes(address);
    let mask = prefix_mask(prefix_length);
    let network = bits & mask;
    bits != network && bits != (network | !mask)
}

/// Whether `address` falls inside the prefix `network`/`prefix_length` names.
fn inside_prefix(address: [u8; 4], network: [u8; 4], prefix_length: u8) -> bool {
    let mask = prefix_mask(prefix_length);
    u32::from_be_bytes(address) & mask == u32::from_be_bytes(network) & mask
}

/// Whether two prefixes cover a common address, decided by the shorter of them.
fn prefixes_overlap(left: [u8; 4], left_length: u8, right: [u8; 4], right_length: u8) -> bool {
    inside_prefix(left, right, left_length.min(right_length))
}

/// A unicast MAC: the IEEE 802.3 group bit clear, and not the all-zero address.
/// Restated from the ABI contract rather than reached for in `wire`, which is
/// the code under test.
fn is_unicast(mac: [u8; 6]) -> bool {
    mac[0] & 0x01 == 0 && mac != [0; 6]
}

/// The rule an interface id is held to, restated here for the same reason: the
/// bytes become a Prometheus label value an operator's dashboard renders, so an
/// id outside `[a-z0-9-]` is a byte a peer could paint into a scrape.
fn identifier_fault(id: &wire::IdentifierImage) -> Option<wire::TextFault> {
    let len = usize::from(id.len);
    let Some(value) = id.bytes.get(..len) else {
        return Some(wire::TextFault::TooLong { len });
    };
    if value.is_empty() {
        return Some(wire::TextFault::Empty);
    }
    value
        .iter()
        .position(|byte| !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        .map(|offset| wire::TextFault::NotInAlphabet { offset })
}

/// Publish an image into a handover region and read it back, which is the path
/// the two domains actually use.
fn assert_region_round_trips(image: &ConfigImage) {
    let region = ConfigHandover::zero();
    // Read into a caller's own buffer rather than returned by value: the image is
    // pages long at `MAX_RULES`, and the domains that read one are the ones whose
    // stacks cannot hold a second copy of it.
    let mut read = ConfigImage::ZERO;
    assert_eq!(region.offered_generation(), 0);
    assert_eq!(
        region.load_offer(&mut read),
        Some(0),
        "a settled region is one nothing is publishing into"
    );
    assert_eq!(
        read,
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
        region.load_offer(&mut read),
        Some(image.generation),
        "a settled region did not answer the generation it offers"
    );
    assert_eq!(
        read, *image,
        "the image did not survive the region it crosses domains through"
    );

    region.publish_committed(image.digest);
    assert_eq!(region.committed_generation(), image.digest);
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
/// x86_64 and nothing else.
#[must_use]
pub fn image_from_region(data: &[u8]) -> ConfigImage {
    let mut unstructured = Unstructured::new(data);
    let mut image = ConfigImage {
        generation: word(&mut unstructured),
        interface_count: word(&mut unstructured),
        neighbour_count: word(&mut unstructured),
        digest: word(&mut unstructured),
        // Read in the position the ABI puts it, between the header and the
        // interfaces, and every byte of it the peer's: the management entry
        // carries the address the appliance answers management traffic at and
        // the two rules that keep it off the dataplane, so a harness leaving it
        // zeroed would drive the one arm of the reader that decides those and
        // never enter it.
        management: wire::ManagementImage {
            enabled: byte(&mut unstructured),
            prefix_length: byte(&mut unstructured),
            gateway_stated: byte(&mut unstructured),
            _pad: [byte(&mut unstructured); 1],
            mac: bytes(&mut unstructured),
            _pad2: bytes(&mut unstructured),
            address: bytes(&mut unstructured),
            gateway: bytes(&mut unstructured),
        },
        ..ConfigImage::ZERO
    };
    for slot in &mut image.interfaces {
        *slot = InterfaceImage {
            port: byte(&mut unstructured),
            enabled: byte(&mut unstructured),
            prefix_length: byte(&mut unstructured),
            _pad: [byte(&mut unstructured); 1],
            mac: bytes(&mut unstructured),
            _pad2: bytes(&mut unstructured),
            address: bytes(&mut unstructured),
            // Every byte of the identity, and its stated length, are the peer's:
            // a harness that only produced admissible ids would never reach
            // the alphabet check.
            id: wire::TextImage {
                bytes: bytes(&mut unstructured),
                len: byte(&mut unstructured),
                _pad: bytes(&mut unstructured),
            },
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
    // The rules, in the position the ABI puts them and every byte of them the
    // peer's. This is the region a compromised publisher would use to hand the
    // forwarder a policy: a stated flag that is neither 0 nor 1, a range whose
    // ends run backwards, a port criterion on ICMP, a block with host bits set,
    // and an id whose bytes would become a Prometheus label. A harness that left
    // them zeroed would leave every one of the twelve rules the reader applies
    // to them unreached — and a zeroed rule is an accepting wildcard, which is
    // the last shape to take on trust.
    image.rule_count = word(&mut unstructured);
    for slot in &mut image.rules {
        *slot = RuleImage {
            action: byte(&mut unstructured),
            ingress_stated: byte(&mut unstructured),
            ingress_port: byte(&mut unstructured),
            egress_stated: byte(&mut unstructured),
            egress_port: byte(&mut unstructured),
            source_stated: byte(&mut unstructured),
            source_prefix_length: byte(&mut unstructured),
            destination_stated: byte(&mut unstructured),
            source_network: bytes(&mut unstructured),
            destination_network: bytes(&mut unstructured),
            destination_prefix_length: byte(&mut unstructured),
            protocol_stated: byte(&mut unstructured),
            protocol: byte(&mut unstructured),
            icmp_type_stated: byte(&mut unstructured),
            icmp_type: byte(&mut unstructured),
            source_port_stated: byte(&mut unstructured),
            destination_port_stated: byte(&mut unstructured),
            tracking_stated: byte(&mut unstructured),
            tracking: byte(&mut unstructured),
            _pad: [byte(&mut unstructured); 1],
            source_port_low: half(&mut unstructured),
            source_port_high: half(&mut unstructured),
            destination_port_low: half(&mut unstructured),
            destination_port_high: half(&mut unstructured),
            id: wire::TextImage {
                bytes: bytes(&mut unstructured),
                len: byte(&mut unstructured),
                _pad: bytes(&mut unstructured),
            },
        };
    }
    image
}

/// The next region word, zero once the input is spent — which is what an
/// unwritten part of a freshly mapped region holds.
fn word(unstructured: &mut Unstructured<'_>) -> u32 {
    crate::any_u32(unstructured)
}

/// The next region half-word; see [`word`].
fn half(unstructured: &mut Unstructured<'_>) -> u16 {
    crate::any_u16(unstructured)
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
