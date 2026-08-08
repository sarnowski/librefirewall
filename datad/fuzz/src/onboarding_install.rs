//! `lfw_store`'s install path under the management-plane attacker, with a
//! byzantine neighbour behind them.
//!
//! # The adversary and the surface
//!
//! Two parties choose these bytes and neither is trusted. An administrator
//! uploads an archive over a session that authenticates the appliance to them
//! and nobody to the appliance; the domain that terminated that session then
//! writes it into a shared region and states, in a word of a separate request,
//! how many bytes of it there are. So the input here is **a region and a claim
//! about it** — not an archive — and the harness models exactly that: the first
//! four bytes of every input are the stated length, unreduced and unclamped, and
//! the rest is the region.
//!
//! Splitting the length out rather than deriving it from the input is the whole
//! point. A length equal to what was staged is the polite case; the adversarial
//! ones are a length past the region, a length short of the archive, and a
//! length of zero over a region full of a real package — and a harness that
//! computed the length from the bytes would have made all three unreachable.
//!
//! # What the adversary does not choose
//!
//! The appliance's own key, and its ownership. Both come from the state record
//! the store domain holds, so both are fixed here: the key is the one the seed
//! package's device certificate was issued over, and the appliance is unowned,
//! which is the only state an install has anything to do. An owned appliance is
//! driven too, as the one case that must refuse before a byte is read.
//!
//! # What is asserted
//!
//! * **Totality and determinism.** Every (length, region) pair is answered —
//!   one typed refusal or one ownership — and the same pair is answered the same
//!   way twice.
//! * **The claim is ranged, never believed.** A stated length past the region is
//!   refused by that rule and nothing else, and what is read is bounded by the
//!   region rather than by the claim.
//! * **Nothing is adopted unless every rule passed.** An accepted install is
//!   taken apart again: the endpoint names a host that can be dialled, the
//!   anchor's fingerprint is the digest over the anchor's own
//!   `SubjectPublicKeyInfo`, and the record that results is owned, one
//!   generation on, and carries both certificates and the endpoint.
//! * **The key comparison is against the appliance's own record.** The same
//!   input read against an appliance holding a different point yields ownership
//!   never, whatever else was right about it — which is what makes "somebody
//!   else's identity has nothing to match" a property rather than an ordering.
//! * **An owned appliance is not re-owned.** The same input against an owned
//!   record is refused for that and for nothing else.

use lfw_crypto::sha256;
use lfw_package::subject_public_key_info;
use lfw_store::{InstallError, State, StoredCertificate, StoredEndpoint, read_package};

/// The public point the seed package's device certificate binds — the appliance
/// this harness plays. Fixed, because the adversary does not choose it.
const APPLIANCE_POINT: &[u8; 65] =
    include_bytes!("../../crates/package/fixtures/appliance-public-key.bin");

/// A point no package here was ever issued over, for the appliance that must
/// match nothing.
const OTHER_POINT: &[u8; 65] = &other_point();

/// The seed package's point with one coordinate byte moved, which leaves an
/// uncompressed point and changes the key it names.
const fn other_point() -> [u8; 65] {
    let mut point = *APPLIANCE_POINT;
    point[64] ^= 1;
    point
}

/// Bytes of the staging region this harness models. The appliance's is 128 KiB;
/// what matters to every rule here is that the region is a fixed extent the
/// stated length is judged against, and a corpus of 128 KiB entries would spend
/// the whole run on memcpy.
const REGION: usize = 8 * 1024;

/// An appliance with no owner, holding `point`.
///
/// The scalar is a fixed non-zero pattern and nothing here signs: what the rules
/// compare against is the public half.
fn appliance(point: &[u8; 65]) -> State {
    State::minted([9; 16], [1; 32], *point, StoredCertificate::ABSENT)
}

/// Read one staged region under one stated length, and hold whatever came back
/// to every rule.
pub fn onboarding_install_harness(input: &[u8]) {
    let (stated, region) = split(input);

    let state = appliance(APPLIANCE_POINT);
    let answer = read_package(stated, region, &state);

    // The claim is ranged against the region and never believed: past it, the
    // rule that refuses is that one and no other.
    if stated as usize > region.len() {
        match answer {
            Err(InstallError::ArchivePastRegion { len, staged }) => {
                assert_eq!(len, stated, "the refusal restated another length");
                assert_eq!(staged, region.len(), "the refusal restated another region");
            }
            _ => panic!("a stated length past the region was read anyway"),
        }
        return;
    }

    if let Ok(adoption) = answer {
        let endpoint = adoption.endpoint();
        let fingerprint = adoption.anchor_fingerprint();
        assert_dialable(endpoint);

        let mut owned = appliance(APPLIANCE_POINT);
        let before = owned.generation();
        adoption.take_ownership(&mut owned);
        assert!(
            matches!(owned.onboarding(), lfw_store::Onboarding::Onboarded),
            "an accepted package left the appliance unowned"
        );
        assert_eq!(
            owned.generation(),
            before + 1,
            "taking ownership did not advance the generation"
        );
        assert!(
            !owned.device_certificate().is_empty() && !owned.anchor_certificate().is_empty(),
            "an owned record is missing one of the two certificates"
        );
        assert!(
            !owned.endpoint().is_absent(),
            "an owned record has nowhere to dial"
        );
        // The fingerprint is the digest over the anchor's own key, taken by
        // the walk that binds it rather than over bytes found by a search.
        let spki = subject_public_key_info(owned.anchor_certificate().as_bytes())
            .expect("an adopted anchor is shaped like a certificate");
        assert_eq!(
            fingerprint,
            sha256(spki),
            "the reported fingerprint is not the anchor's own key"
        );

        // And an appliance that already has an owner refuses this very
        // package, which is what makes a factory reset the only way back.
        assert!(
            matches!(
                read_package(stated, region, &owned),
                Err(InstallError::AlreadyOwned)
            ),
            "an owned appliance took a second package"
        );
    }

    // Determinism: one region under one claim answers the same way twice.
    let first = read_package(stated, region, &appliance(APPLIANCE_POINT));
    let second = read_package(stated, region, &appliance(APPLIANCE_POINT));
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "one staged region read twice gave two answers"
    );
    assert_eq!(
        first.err(),
        second.err(),
        "two refusals for one staged region"
    );

    // The comparison is against this appliance's own record: against another
    // key, nothing is ever adopted.
    assert!(
        read_package(stated, region, &appliance(OTHER_POINT)).is_err(),
        "a package was adopted by an appliance whose key it does not bind"
    );
}

/// The stated length and the region behind it, which is the shape the store
/// domain really sees: a word of the request, and a window it snapshotted.
fn split(input: &[u8]) -> (u32, &[u8]) {
    let (head, rest) = input.split_at(input.len().min(4));
    let mut claim = [0_u8; 4];
    for (slot, byte) in claim.iter_mut().zip(head) {
        *slot = *byte;
    }
    let bounded = rest.get(..rest.len().min(REGION)).unwrap_or_default();
    (u32::from_le_bytes(claim), bounded)
}

/// An adopted endpoint names a host something can answer at — which is more than
/// well-formed: five ranges name no host at all, and an appliance told to dial
/// one would spend its life reporting an unreachable next hop.
fn assert_dialable(endpoint: StoredEndpoint) {
    assert!(!endpoint.is_absent(), "an absent endpoint was adopted");
    let leading = endpoint.address[0];
    assert!(endpoint.port != 0, "an endpoint with no port was adopted");
    assert!(
        u32::from_be_bytes(endpoint.address) != 0,
        "the unspecified address was adopted"
    );
    assert!(leading != 127, "a loopback address was adopted");
    assert!(leading & 0xf0 != 224, "a multicast address was adopted");
    assert!(
        leading & 0xf0 != 240,
        "an address in the reserved top of the space was adopted"
    );
    assert!(
        endpoint.address != [255; 4],
        "the broadcast address was adopted"
    );
}
