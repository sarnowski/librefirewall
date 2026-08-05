//! The store formats held to their own rules, and to the ones a medium written
//! by somebody else would break.

use proptest::prelude::*;
use std::{vec, vec::Vec};

use crate::state::{Copies, StateWrite, encode_state};
use crate::*;

const COPIES_BYTES: usize = 2 * STATE_COPY_BYTES;

/// A recognisable identity: every field distinct, so a field written into
/// another's offset shows up as a wrong value rather than as a plausible one.
fn minted() -> State {
    State::minted(
        [0x11; DEVICE_ID_BYTES],
        [0x22; SECRET_LEN],
        public_key(),
        StoredCertificate::new(&[0xAB; 300]).expect("inside the bound"),
    )
}

fn public_key() -> [u8; 65] {
    let mut key = [0x33_u8; 65];
    key[0] = 0x04;
    key
}

fn endpoint() -> StoredEndpoint {
    StoredEndpoint {
        address: [10, 1, 2, 3],
        port: 8443,
    }
}

fn entry(generation: u64, len: usize) -> SlotEntry {
    SlotEntry {
        generation,
        len,
        digest: [generation as u8; 32],
    }
}

fn round_trip(state: &State) -> State {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, state, Copies::Both);
    decode_state(&region)
        .expect("a copy this writer produced decodes")
        .check()
        .expect("written under this build's layout")
        .into_inner()
}

fn slot(index: usize) -> SlotIndex {
    SlotIndex::new(index).expect("inside the array")
}

// ---------------------------------------------------------------------------
// The layout
// ---------------------------------------------------------------------------

#[test]
fn every_structure_the_layout_places_is_disjoint_from_its_neighbours() {
    let mut claimed: Vec<(u64, u64)> = vec![
        (STATE_A_SECTOR, STATE_COPY_SECTORS),
        (STATE_B_SECTOR, STATE_COPY_SECTORS),
        (RESET_REQUEST_SECTOR, 1),
    ];
    for index in 0..SLOT_COUNT {
        claimed.push((slot_sector(slot(index)), SLOT_SECTORS));
    }
    claimed.sort_unstable();
    for pair in claimed.windows(2) {
        let [(start, sectors), (next, _)] = [pair[0], pair[1]];
        assert!(
            start + sectors <= next,
            "the structure at sector {start} runs into the one at {next}"
        );
    }
    let (last, sectors) = *claimed.last().expect("the array is not empty");
    assert_eq!(
        last + sectors,
        STORE_SECTORS,
        "the claimed sector count must end exactly where the last structure does"
    );
}

#[test]
fn the_whole_store_stays_under_a_megabyte() {
    assert!(STORE_SECTORS as usize * SECTOR_SIZE < 1024 * 1024);
    assert_eq!(SLOT_SECTORS as usize * SECTOR_SIZE, DOCUMENT_BYTES);
}

#[test]
fn a_slots_first_sector_follows_from_its_index_alone() {
    for index in 0..SLOT_COUNT {
        assert_eq!(
            slot_sector(slot(index)),
            SLOTS_START_SECTOR + SLOT_SECTORS * index as u64
        );
    }
    assert!(SlotIndex::new(SLOT_COUNT).is_none());
}

// ---------------------------------------------------------------------------
// The state record
// ---------------------------------------------------------------------------

#[test]
fn a_minted_identity_survives_a_round_trip_field_for_field() {
    let state = minted();
    let back = round_trip(&state);
    assert_eq!(back.generation(), 1);
    assert_eq!(back.onboarding(), Onboarding::Unowned);
    assert_eq!(back.device_id(), [0x11; DEVICE_ID_BYTES]);
    assert_eq!(back.secret_scalar(), [0x22; SECRET_LEN]);
    assert_eq!(back.public_key(), public_key());
    assert_eq!(back.device_certificate().as_bytes(), &[0xAB; 300][..]);
    assert!(back.anchor_certificate().is_empty());
    assert!(back.endpoint().is_absent());
    assert_eq!(back.slots().occupied(), 0);
}

#[test]
fn an_adopted_appliance_carries_its_certificate_anchor_and_endpoint_together() {
    let mut state = minted();
    let device = StoredCertificate::new(&[0xC1; 400]).expect("inside the bound");
    let anchor = StoredCertificate::new(&[0xC2; 500]).expect("inside the bound");
    state.adopt(device, anchor, endpoint());
    assert_eq!(state.generation(), 2);

    let back = round_trip(&state);
    assert_eq!(back.onboarding(), Onboarding::Onboarded);
    assert_eq!(back.device_certificate().as_bytes(), &[0xC1; 400][..]);
    assert_eq!(back.anchor_certificate().as_bytes(), &[0xC2; 500][..]);
    assert_eq!(back.endpoint(), endpoint());
}

#[test]
fn a_document_recorded_in_a_slot_comes_back_as_the_running_configuration() {
    let mut state = minted();
    state.record_document(slot(3), entry(7, 1234), true);
    let back = round_trip(&state);
    assert_eq!(back.slots().running(), Some(slot(3)));
    assert_eq!(back.slots().candidate(), None);
    assert_eq!(back.slots().entry(slot(3)), Some(entry(7, 1234)));
    assert_eq!(back.slots().newest_generation(), 7);
}

#[test]
fn a_fresh_medium_reads_as_a_fresh_medium_rather_than_as_an_error() {
    assert!(decode_state(&[0; COPIES_BYTES]).is_none());
}

#[test]
fn the_newer_of_two_valid_copies_is_the_one_adopted() {
    let mut region = [0_u8; COPIES_BYTES];
    let older = minted();
    encode_state(&mut region, &older, Copies::Both);

    let mut newer = minted();
    // Two advances, so the parity write lands in copy A and the generation is
    // above what both copies hold.
    newer.record_document(slot(0), entry(1, 512), true);
    newer.record_document(slot(1), entry(2, 512), true);
    // Generation 3 is odd, so the parity write lands in copy B — which is the
    // one holding generation 1 and so the one it is safe to overwrite.
    let write = encode_state(&mut region, &newer, Copies::Parity);
    assert_eq!(
        write,
        StateWrite {
            sector: STATE_B_SECTOR,
            sectors: STATE_COPY_SECTORS
        }
    );

    let decoded = decode_state(&region).expect("both copies are valid");
    assert_eq!(decoded.generation(), 3);
}

#[test]
fn a_parity_write_never_touches_the_copy_the_appliance_is_relying_on() {
    let mut state = minted();
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &state, Copies::Both);

    // Generation 1 is odd, so its own copy is B; the next commit is even and
    // must land in A. Every commit thereafter alternates.
    for expected in [STATE_A_SECTOR, STATE_B_SECTOR, STATE_A_SECTOR] {
        state.record_document(slot(0), entry(state.generation(), 512), true);
        let mut fresh = [0_u8; COPIES_BYTES];
        let write = encode_state(&mut fresh, &state, Copies::Parity);
        assert_eq!(write.sector, expected);
        assert_eq!(write.sectors, STATE_COPY_SECTORS);
    }
}

#[test]
fn a_power_cut_that_loses_the_newer_copy_leaves_the_older_one_valid() {
    let mut region = [0_u8; COPIES_BYTES];
    let first = minted();
    encode_state(&mut region, &first, Copies::Both);

    let mut second = minted();
    second.record_document(slot(2), entry(4, 900), true);
    let write = encode_state(&mut region, &second, Copies::Parity);

    // The device took the write and lost it: the sector it addressed is
    // whatever a torn write leaves, so it is filled with rubbish here.
    let at = (write.sector - STATE_A_SECTOR) as usize * SECTOR_SIZE;
    for byte in region.iter_mut().skip(at).take(STATE_COPY_BYTES) {
        *byte = 0x5A;
    }
    let survived = decode_state(&region)
        .expect("the copy that was not written is still valid")
        .check()
        .expect("this build's layout")
        .into_inner();
    assert_eq!(survived.generation(), 1);
    assert_eq!(survived.slots().occupied(), 0);
}

#[test]
fn a_copy_whose_digest_does_not_cover_it_is_refused() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    // One byte of the payload of each copy.
    region[24] ^= 1;
    region[STATE_COPY_BYTES + 24] ^= 1;
    assert!(decode_state(&region).is_none());
}

#[test]
fn a_byte_in_a_span_the_layout_does_not_name_is_refused() {
    // Every reserved run this writer zeroes, one at a time, so a copy carrying
    // meaning in a byte this writer does not write is refused.
    let padding = [
        137_usize, // between the public key and the endpoint
        146,       // between the endpoint and the certificate lengths
        900,       // inside the device certificate's unused tail
        2100,      // the reserved run before the digest
    ];
    for at in padding {
        let mut region = [0_u8; COPIES_BYTES];
        encode_state(&mut region, &minted(), Copies::Both);
        for copy in 0..2 {
            let offset = copy * STATE_COPY_BYTES + at;
            region[offset] = 0xFF;
            // Re-digest so the refusal is the zero rule and not the digest.
            redigest(&mut region, copy);
        }
        assert!(
            decode_state(&region).is_none(),
            "a non-zero byte at {at} was accepted"
        );
    }
}

#[test]
fn a_record_written_under_another_layout_is_decoded_and_never_adopted() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    // The stored slot count, lowered: a smaller array than this build has, so
    // every slot index would name a different sector.
    for copy in 0..2 {
        region[copy * STATE_COPY_BYTES + 164] = 4;
        redigest(&mut region, copy);
    }
    let image = decode_state(&region).expect("internally consistent");
    assert_eq!(
        image.check().err(),
        Some(StateError::LayoutMismatch {
            stored_slots: 4,
            stored_slot_sectors: SLOT_SECTORS as u16,
        })
    );
}

#[test]
fn a_slot_count_above_this_builds_array_is_refused_before_an_entry_is_read() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    for copy in 0..2 {
        region[copy * STATE_COPY_BYTES + 164] = (SLOT_COUNT + 1) as u8;
        redigest(&mut region, copy);
    }
    assert!(decode_state(&region).is_none());
}

#[test]
fn a_claim_of_ownership_with_nothing_delivered_is_refused() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    // The onboarding word alone, flipped: a record saying "owned" with no
    // anchor and no endpoint is one no commit of this appliance's produced.
    for copy in 0..2 {
        region[copy * STATE_COPY_BYTES + 12] = 1;
        redigest(&mut region, copy);
    }
    assert!(decode_state(&region).is_none());
}

#[test]
fn an_unowned_record_carrying_an_anchor_or_an_endpoint_is_refused() {
    let mut state = minted();
    state.adopt(
        StoredCertificate::new(&[0xC1; 100]).expect("inside the bound"),
        StoredCertificate::new(&[0xC2; 100]).expect("inside the bound"),
        endpoint(),
    );
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &state, Copies::Both);
    for copy in 0..2 {
        region[copy * STATE_COPY_BYTES + 12] = 0;
        redigest(&mut region, copy);
    }
    assert!(decode_state(&region).is_none());
}

#[test]
fn a_generation_of_zero_is_a_copy_nothing_wrote() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    for copy in 0..2 {
        for at in 16..24 {
            region[copy * STATE_COPY_BYTES + at] = 0;
        }
        redigest(&mut region, copy);
    }
    assert!(decode_state(&region).is_none());
}

#[test]
fn a_magic_or_a_version_that_is_not_this_writers_is_refused() {
    for at in [0_usize, 8] {
        let mut region = [0_u8; COPIES_BYTES];
        encode_state(&mut region, &minted(), Copies::Both);
        for copy in 0..2 {
            region[copy * STATE_COPY_BYTES + at] ^= 0xFF;
            redigest(&mut region, copy);
        }
        assert!(decode_state(&region).is_none(), "the field at {at}");
    }
}

#[test]
fn a_named_slot_that_holds_nothing_is_refused() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    // Running names slot 0 and the table is empty.
    for copy in 0..2 {
        for (offset, byte) in 0_u32.to_le_bytes().into_iter().enumerate() {
            region[copy * STATE_COPY_BYTES + 156 + offset] = byte;
        }
        redigest(&mut region, copy);
    }
    assert!(decode_state(&region).is_none());
}

#[test]
fn a_slot_index_outside_the_array_is_refused_rather_than_clamped() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    for copy in 0..2 {
        for (offset, byte) in (SLOT_COUNT as u32).to_le_bytes().into_iter().enumerate() {
            region[copy * STATE_COPY_BYTES + 156 + offset] = byte;
        }
        redigest(&mut region, copy);
    }
    assert!(decode_state(&region).is_none());
}

#[test]
fn a_slot_entry_claiming_a_document_longer_than_the_slot_is_refused() {
    let mut state = minted();
    state.record_document(slot(0), entry(1, 512), true);
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &state, Copies::Both);
    for copy in 0..2 {
        let at = copy * STATE_COPY_BYTES + 168 + 8;
        for (offset, byte) in ((DOCUMENT_BYTES + 1) as u32)
            .to_le_bytes()
            .into_iter()
            .enumerate()
        {
            region[at + offset] = byte;
        }
        redigest(&mut region, copy);
    }
    assert!(decode_state(&region).is_none());
}

#[test]
fn an_empty_slot_entry_carrying_a_length_or_a_digest_is_refused() {
    for at in [168_usize + 8, 168 + 16] {
        let mut region = [0_u8; COPIES_BYTES];
        encode_state(&mut region, &minted(), Copies::Both);
        for copy in 0..2 {
            region[copy * STATE_COPY_BYTES + at] = 1;
            redigest(&mut region, copy);
        }
        assert!(decode_state(&region).is_none(), "the byte at {at}");
    }
}

#[test]
fn a_certificate_length_past_the_records_buffer_is_refused() {
    for at in [148_usize, 152] {
        let mut region = [0_u8; COPIES_BYTES];
        encode_state(&mut region, &minted(), Copies::Both);
        for copy in 0..2 {
            for (offset, byte) in ((MAX_STORED_CERTIFICATE + 1) as u32)
                .to_le_bytes()
                .into_iter()
                .enumerate()
            {
                region[copy * STATE_COPY_BYTES + at + offset] = byte;
            }
            redigest(&mut region, copy);
        }
        assert!(decode_state(&region).is_none(), "the length at {at}");
    }
}

#[test]
fn a_certificate_longer_than_the_record_holds_is_refused_at_construction() {
    assert_eq!(
        StoredCertificate::new(&[0; MAX_STORED_CERTIFICATE + 1]).err(),
        Some(StateError::CertificateTooLong {
            len: MAX_STORED_CERTIFICATE + 1
        })
    );
    let widest = StoredCertificate::new(&[7; MAX_STORED_CERTIFICATE]).expect("exactly the bound");
    assert_eq!(widest.len(), MAX_STORED_CERTIFICATE);
    assert!(!widest.is_empty());
    assert!(StoredCertificate::ABSENT.is_empty());
    assert_eq!(StoredCertificate::ABSENT.len(), 0);
}

#[test]
fn certificates_compare_by_content_and_not_by_their_unused_tail() {
    // Compared through the type's own equality rather than through a `Debug`
    // rendering: a certificate is 768 bytes of buffer and printing it would be
    // noise, so this type deliberately has no `Debug` to lean on.
    let short = StoredCertificate::new(&[1, 2, 3]).expect("inside the bound");
    assert!(short == StoredCertificate::new(&[1, 2, 3]).expect("valid"));
    assert!(short != StoredCertificate::new(&[1, 2, 3, 0]).expect("valid"));
}

#[test]
fn an_onboarding_word_outside_the_two_states_names_nothing() {
    assert_eq!(Onboarding::from_bits(0), Some(Onboarding::Unowned));
    assert_eq!(Onboarding::from_bits(1), Some(Onboarding::Onboarded));
    assert!(Onboarding::from_bits(2).is_none());
    assert_eq!(Onboarding::Unowned.to_bits(), 0);
    assert_eq!(Onboarding::Onboarded.to_bits(), 1);
}

#[test]
fn an_endpoint_is_absent_when_either_half_of_it_is() {
    assert!(StoredEndpoint::ABSENT.is_absent());
    assert!(
        StoredEndpoint {
            address: [10, 0, 0, 1],
            port: 0
        }
        .is_absent()
    );
    assert!(
        StoredEndpoint {
            address: [0, 0, 0, 0],
            port: 443
        }
        .is_absent()
    );
    assert!(!endpoint().is_absent());
}

#[test]
fn the_checked_handle_reads_the_state_it_was_built_from() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    let checked = decode_state(&region)
        .expect("valid")
        .check()
        .expect("this build");
    assert_eq!(checked.get().device_id(), [0x11; DEVICE_ID_BYTES]);
    assert_eq!(checked.into_inner().generation(), 1);
}

// ---------------------------------------------------------------------------
// The slot array
// ---------------------------------------------------------------------------

#[test]
fn reuse_takes_an_empty_slot_before_it_displaces_anything() {
    let mut slots = Slots::empty();
    assert_eq!(slots.next_for_reuse(), Some(Reuse::Empty(slot(0))));
    slots.place(slot(0), entry(1, 512), true);
    assert_eq!(slots.next_for_reuse(), Some(Reuse::Empty(slot(1))));
    assert_eq!(slots.occupied(), 1);
}

#[test]
fn reuse_never_takes_the_running_or_the_candidate_slot() {
    let mut slots = Slots::empty();
    // Fill every slot, oldest generation in the slot that will be running.
    for index in 0..SLOT_COUNT {
        slots.place(slot(index), entry(index as u64 + 1, 512), false);
    }
    // Slot 0 holds generation 1, the lowest, and is made the running one; slot
    // 1 holds generation 2 and is the candidate. Reuse must skip both and take
    // slot 2's generation 3.
    slots.place(slot(0), entry(1, 512), true);
    slots.place(slot(1), entry(2, 512), false);
    assert_eq!(slots.running(), Some(slot(0)));
    assert_eq!(slots.candidate(), Some(slot(1)));
    assert_eq!(
        slots.next_for_reuse(),
        Some(Reuse::Displaces {
            slot: slot(2),
            generation: 3
        })
    );
}

#[test]
fn reuse_displaces_the_lowest_generation_the_array_holds() {
    let mut slots = Slots::empty();
    let generations = [40_u64, 10, 30, 20, 70, 60, 50, 80];
    for (index, generation) in generations.into_iter().enumerate() {
        slots.place(slot(index), entry(generation, 512), false);
    }
    // The last `place` made slot 7 the candidate; nothing is running.
    let reuse = slots.next_for_reuse().expect("every slot is full");
    assert_eq!(
        reuse,
        Reuse::Displaces {
            slot: slot(1),
            generation: 10
        }
    );
    assert_eq!(reuse.slot(), slot(1));
    assert_eq!(slots.newest_generation(), 80);
}

#[test]
fn committing_a_running_configuration_clears_the_candidate() {
    let mut slots = Slots::empty();
    slots.place(slot(4), entry(9, 512), false);
    assert_eq!(slots.candidate(), Some(slot(4)));
    slots.place(slot(4), entry(9, 512), true);
    assert_eq!(slots.running(), Some(slot(4)));
    assert_eq!(slots.candidate(), None);
}

#[test]
fn clearing_the_array_forgets_every_document_and_both_named_slots() {
    let mut slots = Slots::empty();
    slots.place(slot(0), entry(1, 512), true);
    slots.place(slot(1), entry(2, 512), false);
    slots.clear();
    assert_eq!(slots, Slots::empty());
    assert_eq!(slots.newest_generation(), 0);
    assert_eq!(slots.occupied(), 0);
    assert_eq!(slots.entry(slot(0)), None);
}

#[test]
fn a_decoded_array_naming_one_slot_twice_is_refused() {
    let mut entries = [None; SLOT_COUNT];
    entries[2] = Some(entry(5, 512));
    assert_eq!(
        Slots::decoded(entries, Some(slot(2)), Some(slot(2))).err(),
        Some(StateError::SlotNamedTwice { slot: 2 })
    );
    assert_eq!(
        Slots::decoded(entries, Some(slot(3)), None).err(),
        Some(StateError::NamedSlotEmpty { slot: 3 })
    );
    assert!(Slots::decoded(entries, Some(slot(2)), None).is_ok());
    assert!(Slots::decoded(entries, None, None).is_ok());
}

// ---------------------------------------------------------------------------
// The factory-reset request
// ---------------------------------------------------------------------------

#[test]
fn the_reset_token_is_the_only_sector_that_asks_for_a_reset() {
    let token = reset_token();
    assert!(ResetRequest::read(&token).is_requested());
    assert_eq!(ResetRequest::read(&token), ResetRequest::Requested);
    // The ordinary state of the sector, and what the appliance leaves behind.
    assert_eq!(
        ResetRequest::read(&[0; RESET_REQUEST_BYTES]),
        ResetRequest::Absent
    );
    assert!(!ResetRequest::read(&[0; RESET_REQUEST_BYTES]).is_requested());
}

#[test]
fn one_byte_off_the_token_is_not_a_request() {
    for at in [0_usize, 7, 8, 11, 12, RESET_REQUEST_BYTES - 1] {
        let mut sector = reset_token();
        sector[at] ^= 1;
        assert_eq!(
            ResetRequest::read(&sector),
            ResetRequest::Absent,
            "a sector differing at {at} was honoured"
        );
    }
}

#[test]
fn composing_a_request_over_a_dirty_sector_leaves_only_the_token() {
    let mut sector = [0xAB_u8; RESET_REQUEST_BYTES];
    write_reset_request(&mut sector);
    assert_eq!(sector, reset_token());
}

/// What a reset reports is read off the state it is about to destroy: the
/// generation that appliance stood at, how many configuration versions go with
/// it, and whether there was an owner to give up.
#[test]
fn a_reset_reports_the_appliance_it_is_about_to_destroy() {
    let mut state = minted();
    assert_eq!(
        Cleared::of(Some(&state)),
        Cleared {
            generation: 1,
            documents: 0,
            was_owned: false,
        }
    );

    state.adopt(
        StoredCertificate::new(&[0xCD; 400]).expect("inside the bound"),
        StoredCertificate::new(&[0xEF; 500]).expect("inside the bound"),
        endpoint(),
    );
    state.record_document(slot(0), entry(1, 4096), true);
    state.record_document(slot(3), entry(2, 8192), false);
    assert_eq!(
        Cleared::of(Some(&state)),
        Cleared {
            generation: 4,
            documents: 2,
            was_owned: true,
        }
    );
}

/// And a medium carrying no record this build can read reports nothing rather
/// than refusing the reset: a record the appliance will not act on is exactly the
/// state a reset is the remedy for.
#[test]
fn a_reset_over_a_record_this_build_cannot_read_reports_nothing() {
    assert_eq!(
        Cleared::of(None),
        Cleared {
            generation: 0,
            documents: 0,
            was_owned: false,
        }
    );
    assert_eq!(Cleared::of(None), Cleared::default());
}

/// The window a proof of erasure has to name, read positionally so it works on a
/// region whose record no longer decodes.
#[test]
fn the_stored_secret_window_is_the_scalar_wherever_the_record_stands() {
    let mut region = [0_u8; COPIES_BYTES];
    encode_state(&mut region, &minted(), Copies::Both);
    assert_eq!(stored_secret_window(&region), [0x22; SECRET_LEN]);

    // A region neither copy of which decodes any more is still a region the
    // window can be read out of, which is the whole reason this reads no fields.
    region[0] ^= 0xFF;
    region[STATE_COPY_BYTES] ^= 0xFF;
    assert!(decode_state(&region).is_none());
    assert_eq!(stored_secret_window(&region), [0x22; SECRET_LEN]);
    // And a zeroed medium carries no scalar at all, which is what makes an
    // all-zero window worth refusing as a proof.
    assert_eq!(stored_secret_window(&[0; COPIES_BYTES]), [0; SECRET_LEN]);
}

// ---------------------------------------------------------------------------
// Properties over arbitrary media
// ---------------------------------------------------------------------------

/// Rewrite one copy's digest so a test can perturb a field and still exercise
/// the rule it is aiming at rather than the digest that covers it.
fn redigest(region: &mut [u8; COPIES_BYTES], copy: usize) {
    let base = copy * STATE_COPY_BYTES;
    let digest_at = base + STATE_COPY_BYTES - 32;
    let digest = lfw_crypto::sha256(&region[base..digest_at]);
    region[digest_at..digest_at + 32].copy_from_slice(&digest);
}

proptest! {
    /// Total over arbitrary media: every input is either refused or a state
    /// that re-encodes to the bytes it was decoded from. Nothing panics, and
    /// nothing is coerced into range.
    #[test]
    fn decoding_arbitrary_bytes_is_total_and_lossless(
        bytes in proptest::collection::vec(any::<u8>(), COPIES_BYTES..=COPIES_BYTES),
    ) {
        let mut region = [0_u8; COPIES_BYTES];
        region.copy_from_slice(&bytes);
        if let Some(image) = decode_state(&region) {
            prop_assert!(image.generation() > 0);
            // A record arbitrary bytes happened to form is refused by `check`
            // unless it also carries this build's layout, and either way the
            // decode did not panic and did not index.
            if let Ok(checked) = image.check() {
                let state = checked.into_inner();
                let mut again = [0_u8; COPIES_BYTES];
                encode_state(&mut again, &state, Copies::Both);
                let back = decode_state(&again)
                    .expect("re-encoding a decoded state decodes")
                    .check()
                    .expect("this build's layout")
                    .into_inner();
                prop_assert_eq!(back.generation(), state.generation());
                prop_assert_eq!(back.device_id(), state.device_id());
                prop_assert_eq!(back.secret_scalar(), state.secret_scalar());
                prop_assert_eq!(back.onboarding(), state.onboarding());
                prop_assert_eq!(back.slots(), state.slots());
            }
        }
    }

    /// One arbitrary sector is either the token or absent, and never a panic.
    #[test]
    fn reading_an_arbitrary_reset_sector_is_total(
        bytes in proptest::collection::vec(any::<u8>(), RESET_REQUEST_BYTES..=RESET_REQUEST_BYTES),
    ) {
        let mut sector = [0_u8; RESET_REQUEST_BYTES];
        sector.copy_from_slice(&bytes);
        let request = ResetRequest::read(&sector);
        prop_assert_eq!(request.is_requested(), sector == reset_token());
    }

    /// Reuse never names the running slot, whatever the array holds.
    #[test]
    fn reuse_is_never_the_running_slot(
        generations in proptest::collection::vec(1_u64..1000, SLOT_COUNT..=SLOT_COUNT),
        running in 0_usize..SLOT_COUNT,
    ) {
        let mut slots = Slots::empty();
        for (index, generation) in generations.into_iter().enumerate() {
            slots.place(slot(index), entry(generation, 512), false);
        }
        let held = slots.entry(slot(running)).expect("every slot is full");
        slots.place(slot(running), held, true);
        let reuse = slots.next_for_reuse().expect("more than two slots");
        prop_assert_ne!(reuse.slot(), slot(running));
        prop_assert_eq!(slots.running(), Some(slot(running)));
    }

    /// Every document length the bound admits round-trips through the record.
    #[test]
    fn any_admissible_document_length_survives_the_record(len in 1_usize..=DOCUMENT_BYTES) {
        let mut state = minted();
        state.record_document(slot(5), entry(11, len), false);
        let back = round_trip(&state);
        prop_assert_eq!(back.slots().candidate(), Some(slot(5)));
        prop_assert_eq!(back.slots().entry(slot(5)).map(|held| held.len), Some(len));
    }

    /// Every certificate length the record holds round-trips, tail included.
    /// From one rather than zero: an owned appliance with no device certificate
    /// is a state the decode refuses, which
    /// `a_claim_of_ownership_with_nothing_delivered_is_refused` is what covers.
    #[test]
    fn any_admissible_certificate_length_survives_the_record(
        len in 1_usize..=MAX_STORED_CERTIFICATE,
    ) {
        let der = vec![0x9E_u8; len];
        let mut state = minted();
        state.adopt(
            StoredCertificate::new(&der).expect("inside the bound"),
            StoredCertificate::new(&[0xC2; 64]).expect("inside the bound"),
            endpoint(),
        );
        let back = round_trip(&state);
        prop_assert_eq!(back.device_certificate().as_bytes(), &der[..]);
    }
}

// ── The identity the record carries ─────────────────────────────────────────

/// A fixed generator, so minting is reproducible and a test can say what the
/// identity *is* rather than only that there was one.
///
/// A counter rather than a real DRBG: what is under test is the composition —
/// which draw becomes the name, which becomes the key, which becomes the serial,
/// and whether the certificate binds the key — and a fixed sequence is what makes
/// that visible. Two of the appliance's own generators are proved elsewhere; this
/// one is a fixture.
struct Counted {
    next: core::sync::atomic::AtomicU8,
}

impl Counted {
    fn new(from: u8) -> Self {
        Self {
            next: core::sync::atomic::AtomicU8::new(from),
        }
    }
}

impl lfw_crypto::Entropy for Counted {
    fn fill(&self, out: &mut [u8]) {
        for slot in out {
            *slot = self
                .next
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Seconds at the start of 2026, the same floor the appliance uses where no
/// clock has published.
const NOW: i64 = 1_767_225_600;

#[test]
fn a_minted_identity_is_generation_one_unowned_and_carries_its_certificate() {
    let minted = mint(&Counted::new(1), NOW).expect("a working generator mints");
    let state = &minted.state;
    assert_eq!(state.generation(), 1);
    assert_eq!(state.onboarding(), Onboarding::Unowned);
    assert!(state.endpoint().is_absent());
    assert!(state.anchor_certificate().is_empty());
    assert!(!state.device_certificate().is_empty());
    assert_eq!(state.slots().occupied(), 0);
    // The first draw is the name, so the identifier is the counter's own first
    // sixteen bytes — which is what makes "the name comes from entropy and not
    // from the key" a checked claim rather than a comment.
    let mut expected = [0_u8; DEVICE_ID_BYTES];
    for (at, byte) in expected.iter_mut().enumerate() {
        *byte = at as u8 + 1;
    }
    assert_eq!(state.device_id(), expected);
    assert_eq!(
        minted.identity.device,
        lfw_x509::DeviceId::from_bytes(expected)
    );
}

/// The claim the whole scheme rests on: what was minted verifies, and the
/// fingerprint verification answers is the one minting reported.
#[test]
fn a_minted_identity_verifies_and_reports_the_fingerprint_it_was_minted_with() {
    let minted = mint(&Counted::new(7), NOW).expect("a working generator mints");
    let verified = verify(&minted.state).expect("what was just minted is coherent");
    assert_eq!(verified, minted.identity);
    // And it still verifies after crossing the medium, which is the only path a
    // second boot reaches it by.
    let reloaded = round_trip(&minted.state);
    assert_eq!(
        verify(&reloaded).expect("a round trip preserves it"),
        verified
    );
}

/// Two different generators mint two different appliances, so the identity is
/// drawn rather than derived from anything the build carries.
#[test]
fn two_mints_from_different_draws_are_two_different_appliances() {
    let first = mint(&Counted::new(1), NOW).expect("mints");
    let second = mint(&Counted::new(2), NOW).expect("mints");
    assert_ne!(first.identity.device, second.identity.device);
    assert_ne!(first.identity.fingerprint, second.identity.fingerprint);
    assert_ne!(
        first.state.public_key().as_slice(),
        second.state.public_key().as_slice()
    );
    assert_ne!(
        first.state.device_certificate().as_bytes(),
        second.state.device_certificate().as_bytes()
    );
}

/// The fingerprint is the profile's own definition, taken from the one place
/// that holds it — so a change to either side moves both and this comparison
/// still holds.
#[test]
fn the_fingerprint_is_the_digest_over_the_stored_keys_own_encoding() {
    let minted = mint(&Counted::new(3), NOW).expect("mints");
    let public = minted.state.public_key();
    assert_eq!(
        minted.identity.fingerprint,
        lfw_x509::spki_fingerprint(&public).expect("a fixed-length encoding")
    );
    // Sixty-four lowercase hexadecimal characters, which is the whole of how one
    // is ever written.
    let rendered = lfw_x509::fingerprint_hex(&minted.identity.fingerprint);
    assert_eq!(rendered.len(), 64);
    assert!(
        rendered
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    );
}

/// A record whose public point is not its scalar's is a record this appliance
/// never wrote, and it is refused rather than repaired from either half.
#[test]
fn a_stored_public_point_that_is_not_the_scalars_is_refused() {
    let minted = mint(&Counted::new(5), NOW).expect("mints");
    let other = mint(&Counted::new(90), NOW).expect("mints");
    let swapped = State::minted(
        minted.state.device_id(),
        minted.state.secret_scalar(),
        other.state.public_key(),
        *minted.state.device_certificate(),
    );
    assert_eq!(verify(&swapped), Err(IdentityError::PublicKeyMismatch));
}

/// And one whose certificate binds a different key: a peer validating it would
/// trust a key this node cannot sign with.
#[test]
fn a_stored_certificate_binding_another_key_is_refused() {
    let minted = mint(&Counted::new(11), NOW).expect("mints");
    let other = mint(&Counted::new(140), NOW).expect("mints");
    let mismatched = State::minted(
        minted.state.device_id(),
        minted.state.secret_scalar(),
        minted.state.public_key(),
        *other.state.device_certificate(),
    );
    assert_eq!(
        verify(&mismatched),
        Err(IdentityError::CertificateKeyMismatch)
    );
}

#[test]
fn a_record_carrying_no_certificate_at_all_is_refused() {
    let minted = mint(&Counted::new(13), NOW).expect("mints");
    let bare = State::minted(
        minted.state.device_id(),
        minted.state.secret_scalar(),
        minted.state.public_key(),
        StoredCertificate::ABSENT,
    );
    assert_eq!(verify(&bare), Err(IdentityError::CertificateAbsent));
}

/// The zero scalar is not a private key, and neither is a value at or above the
/// group order. Both are values a physically present attacker can write, and
/// both are refused before any point is derived from them.
#[test]
fn a_stored_scalar_that_is_no_private_key_is_refused() {
    let minted = mint(&Counted::new(17), NOW).expect("mints");
    for scalar in [[0_u8; SECRET_LEN], [0xff_u8; SECRET_LEN]] {
        let broken = State::minted(
            minted.state.device_id(),
            scalar,
            minted.state.public_key(),
            *minted.state.device_certificate(),
        );
        assert_eq!(verify(&broken), Err(IdentityError::ScalarUnusable));
    }
}

/// A generator that answers nothing usable refuses the mint rather than
/// producing a key nobody drew.
#[test]
fn a_generator_that_never_yields_a_scalar_refuses_the_mint() {
    struct Zeroes;
    impl lfw_crypto::Entropy for Zeroes {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0);
        }
    }
    assert!(matches!(
        mint(&Zeroes, NOW),
        Err(IdentityError::KeyUnusable)
    ));
}

/// Every refusal reads differently, so a console line names one cause and not a
/// class of them.
#[test]
fn every_identity_refusal_carries_its_own_cause_token() {
    let causes = [
        IdentityError::KeyUnusable,
        IdentityError::Certificate(lfw_x509::ProfileError::Signature),
        IdentityError::Fingerprint(lfw_x509::DerError::OutOfSpace { needed: 1 }),
        IdentityError::Storage(StateError::CertificateTooLong { len: 1 }),
        IdentityError::ScalarUnusable,
        IdentityError::PublicKeyMismatch,
        IdentityError::CertificateKeyMismatch,
        IdentityError::CertificateAbsent,
    ]
    .map(IdentityError::cause);
    let mut sorted: Vec<&str> = causes.to_vec();
    sorted.sort_unstable();
    let count = sorted.len();
    sorted.dedup();
    assert_eq!(sorted.len(), count, "two refusals share a cause token");
    for cause in causes {
        assert!(!cause.is_empty());
        assert!(cause.len() <= 40, "{cause} is wider than a cause token");
        assert!(
            cause
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-')),
            "{cause} is outside the console alphabet"
        );
    }
}

proptest! {
    /// Minting is total over the instant: every second a clock could name either
    /// mints or refuses with a reason, and never faults.
    #[test]
    fn minting_is_total_over_the_instant_the_clock_reports(
        now in any::<i64>(),
        seed in any::<u8>(),
    ) {
        match mint(&Counted::new(seed), now) {
            Ok(minted) => {
                prop_assert_eq!(verify(&minted.state), Ok(minted.identity));
            }
            // The one refusal an instant can cause: a year a `UTCTime` cannot
            // name without ambiguity, which is a certificate refused rather than
            // one dated by a clock nobody believes.
            Err(error) => prop_assert!(
                matches!(error, IdentityError::Certificate(lfw_x509::ProfileError::Undatable { .. })),
                "{error:?}"
            ),
        }
    }
}
