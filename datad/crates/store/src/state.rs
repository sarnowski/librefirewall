//! The transactional double-buffered state record: what the appliance is, as it
//! sits on the medium.
//!
//! One copy is [`STATE_COPY_BYTES`] of canonical little-endian fields at fixed
//! offsets, with a SHA-256 digest as the last 32 bytes covering everything before
//! it, and every byte the layout does not name held at zero. A copy carrying
//! meaning in a byte this writer zeroes is not a copy this writer produced, and
//! deciding that now is cheaper than deciding later what it meant.
//! [`STATE_VERSION`] is how the layout changes; there is no compatibility path.

use lfw_crypto::{DIGEST_LEN, sha256};

use crate::layout::{SECTOR_SIZE, SLOT_COUNT, SLOT_SECTORS, STATE_COPY_BYTES};
use crate::slots::{DOCUMENT_BYTES, SlotEntry, SlotIndex, Slots};

/// `LFWSTORE` in ASCII, leading every copy.
pub const STATE_MAGIC: u64 = u64::from_le_bytes(*b"LFWSTORE");

pub const STATE_VERSION: u32 = 1;

/// Bytes of the 128-bit device identifier, before it is rendered as hexadecimal.
pub const DEVICE_ID_BYTES: usize = 16;

/// Bytes of a P-256 private scalar, `lfw_crypto::P256_SECRET_LEN` restated so
/// this module's offsets are arithmetic over its own constants.
pub const SECRET_LEN: usize = 32;

/// Bytes of the uncompressed SEC1 public point.
const PUBLIC_LEN: usize = 65;

/// Bytes a stored certificate may occupy: the widest the certificate profile
/// produces. Two of them fit the record, which is what makes the device
/// certificate and the delivered anchor fields of the state rather than objects
/// somewhere else that could go missing separately.
pub const MAX_STORED_CERTIFICATE: usize = 768;

/// Bytes an endpoint occupies: four octets of address and a port.
pub const ENDPOINT_LEN: usize = 6;

const MAGIC_AT: usize = 0;
const VERSION_AT: usize = 8;
const ONBOARDING_AT: usize = 12;
const GENERATION_AT: usize = 16;
const DEVICE_ID_AT: usize = 24;
const SECRET_AT: usize = 40;
const PUBLIC_AT: usize = 72;
const ENDPOINT_AT: usize = 140;
const DEVICE_CERT_LEN_AT: usize = 148;
const ANCHOR_CERT_LEN_AT: usize = 152;
const RUNNING_AT: usize = 156;
const CANDIDATE_AT: usize = 160;
const SLOT_COUNT_AT: usize = 164;
const SLOT_SECTORS_AT: usize = 166;
const SLOT_TABLE_AT: usize = 168;
const SLOT_ENTRY_BYTES: usize = 48;
const SLOT_GENERATION_AT: usize = 0;
const SLOT_LEN_AT: usize = 8;
const SLOT_DIGEST_AT: usize = 16;
const DEVICE_CERT_AT: usize = 552;
const ANCHOR_CERT_AT: usize = 1320;

/// The digest is last so the range it covers is the single contiguous prefix
/// before it — magic and version included, which a digest placed among the fields
/// would have had to skip around.
const DIGEST_AT: usize = STATE_COPY_BYTES - DIGEST_LEN;

/// The value a slot index takes when no slot is named. Every bit set rather than
/// zero, because zero is a slot.
const NO_SLOT: u32 = u32::MAX;

// The on-medium ABI of an appliance that must still be itself after a rebuild: a
// field moving or growing has to be a compile error here, not a record that
// decodes to a plausible other identity.
const _: () = {
    assert!(SLOT_TABLE_AT + SLOT_COUNT * SLOT_ENTRY_BYTES <= DEVICE_CERT_AT);
    assert!(SLOT_DIGEST_AT + DIGEST_LEN == SLOT_ENTRY_BYTES);
    assert!(DEVICE_CERT_AT + MAX_STORED_CERTIFICATE <= ANCHOR_CERT_AT);
    assert!(ANCHOR_CERT_AT + MAX_STORED_CERTIFICATE <= DIGEST_AT);
    assert!(DIGEST_AT + DIGEST_LEN == STATE_COPY_BYTES);
    assert!(SECRET_AT + SECRET_LEN <= PUBLIC_AT);
    assert!(PUBLIC_AT + PUBLIC_LEN <= ENDPOINT_AT);
    assert!(ENDPOINT_AT + ENDPOINT_LEN <= DEVICE_CERT_LEN_AT);
    assert!(SLOT_SECTORS_AT + 2 <= SLOT_TABLE_AT);
    // Every stored length is written as a `u32` and read back as a `usize`,
    // which is exact only while a `usize` is at least as wide.
    assert!(size_of::<usize>() >= size_of::<u32>());
    assert!(MAX_STORED_CERTIFICATE <= u32::MAX as usize);
    assert!(DOCUMENT_BYTES <= u32::MAX as usize);
    assert!(SLOT_COUNT <= u16::MAX as usize);
    assert!(SLOT_SECTORS <= u16::MAX as u64);
    // `NO_SLOT` must not name a slot, which is what makes "no candidate" a
    // representable answer rather than slot 4294967295.
    assert!(SLOT_COUNT < NO_SLOT as usize);
};

/// Whether this appliance has an owner.
///
/// Two values and nothing between them, which is the whole of the onboarding
/// state machine: an appliance is unowned or owned, and factory reset is the only
/// transition back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Onboarding {
    /// No management plane has adopted this appliance. It forwards nothing and
    /// serves only onboarding.
    Unowned,
    /// A management plane has delivered a signed certificate, a trust anchor and
    /// an endpoint.
    Onboarded,
}

impl Onboarding {
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        match self {
            Self::Unowned => 0,
            Self::Onboarded => 1,
        }
    }

    /// `None` for every other bit pattern: the word is off a medium, so an
    /// undecodable value is input to reject rather than one to coerce toward the
    /// safe answer. Coercing to `Unowned` would look safe and would silently
    /// discard an owner.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(Self::Unowned),
            1 => Some(Self::Onboarded),
            _ => None,
        }
    }
}

/// A certificate as the record holds it: a fixed buffer and the length in use.
///
/// Fixed rather than a slice, because the record has nowhere to point and the
/// domain has no allocator. Bytes past `len` are zero on the medium and are
/// refused non-zero, so the same certificate always encodes to the same bytes.
#[derive(Clone, Copy)]
pub struct StoredCertificate {
    bytes: [u8; MAX_STORED_CERTIFICATE],
    len: usize,
}

impl StoredCertificate {
    /// The absent certificate, which is what an unowned appliance's anchor is.
    pub const ABSENT: Self = Self {
        bytes: [0; MAX_STORED_CERTIFICATE],
        len: 0,
    };

    /// # Errors
    /// [`StateError::CertificateTooLong`] for more bytes than the record holds.
    pub fn new(der: &[u8]) -> Result<Self, StateError> {
        let len = der.len();
        if len > MAX_STORED_CERTIFICATE {
            return Err(StateError::CertificateTooLong { len });
        }
        let mut bytes = [0_u8; MAX_STORED_CERTIFICATE];
        for (slot, byte) in bytes.iter_mut().zip(der) {
            *slot = *byte;
        }
        Ok(Self { bytes, len })
    }

    /// The fallback is unreachable: [`Self::new`] is what sets `len`, and only
    /// after comparing it against the array's own size.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl PartialEq for StoredCertificate {
    /// By content, so the unused tail cannot make two equal certificates
    /// compare different.
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for StoredCertificate {}

/// The management endpoint the appliance dials: an address literal and a port,
/// which is what keeps DNS off the path an unauthenticated party could steer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredEndpoint {
    pub address: [u8; 4],
    pub port: u16,
}

impl StoredEndpoint {
    /// The absent endpoint: an unowned appliance dials nothing.
    pub const ABSENT: Self = Self {
        address: [0; 4],
        port: 0,
    };

    /// Whether this names somewhere to dial. Port zero is not a port and an
    /// all-zero address is not a host, so either alone says absent.
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        self.port == 0 || u32::from_be_bytes(self.address) == 0
    }
}

/// Why a copy is not this appliance's state, or not a state at all. Each variant
/// carries the value that disagreed, never a byte a writer of the medium chose
/// to put in a text field — there are none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    CertificateTooLong {
        len: usize,
    },
    DocumentTooLong {
        len: usize,
    },
    /// A slot named twice, so "which slot is running" would have two answers.
    SlotNamedTwice {
        slot: usize,
    },
    /// The record names a slot the array does not hold.
    SlotOutsideArray {
        slot: u32,
    },
    /// The candidate is named and holds no document, or the running slot is.
    NamedSlotEmpty {
        slot: usize,
    },
    /// The record was written under a different compiled-in layout, so its slot
    /// indices name sectors this build would read something else at.
    LayoutMismatch {
        stored_slots: u16,
        stored_slot_sectors: u16,
    },
}

/// The appliance's whole persistent state.
///
/// No `Debug` and no `Clone` accessor for the scalar: the only things that leave
/// are a public key, a certificate, an endpoint and a slot table. Key material
/// has no representation on any surface, and a type that could print it would be
/// the first step toward one.
pub struct State {
    generation: u64,
    onboarding: Onboarding,
    device_id: [u8; DEVICE_ID_BYTES],
    secret: [u8; SECRET_LEN],
    public: [u8; PUBLIC_LEN],
    endpoint: StoredEndpoint,
    device_certificate: StoredCertificate,
    anchor_certificate: StoredCertificate,
    slots: Slots,
}

impl State {
    /// The state a first boot mints: an identity and nothing delivered.
    ///
    /// Generation one rather than zero, so a decoded generation of zero is a
    /// copy nothing wrote — which is what a zeroed medium reads as.
    #[must_use]
    pub const fn minted(
        device_id: [u8; DEVICE_ID_BYTES],
        secret: [u8; SECRET_LEN],
        public: [u8; PUBLIC_LEN],
        onboarding_certificate: StoredCertificate,
    ) -> Self {
        Self {
            generation: 1,
            onboarding: Onboarding::Unowned,
            device_id,
            secret,
            public,
            endpoint: StoredEndpoint::ABSENT,
            device_certificate: onboarding_certificate,
            anchor_certificate: StoredCertificate::ABSENT,
            slots: Slots::empty(),
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn onboarding(&self) -> Onboarding {
        self.onboarding
    }

    #[must_use]
    pub const fn device_id(&self) -> [u8; DEVICE_ID_BYTES] {
        self.device_id
    }

    #[must_use]
    pub const fn public_key(&self) -> [u8; PUBLIC_LEN] {
        self.public
    }

    /// The private scalar, for the one caller that may have it: the domain that
    /// owns this medium, building the signing key it never emits.
    ///
    /// It is `pub` because the type cannot express "only my own protection
    /// domain", and it is the narrowest shape that works: the scalar leaves as a
    /// value with no `Debug`, no `Display` and no `Copy` of the surrounding
    /// state, and every other accessor here answers something public.
    #[must_use]
    pub const fn secret_scalar(&self) -> [u8; SECRET_LEN] {
        self.secret
    }

    #[must_use]
    pub const fn endpoint(&self) -> StoredEndpoint {
        self.endpoint
    }

    #[must_use]
    pub const fn device_certificate(&self) -> &StoredCertificate {
        &self.device_certificate
    }

    #[must_use]
    pub const fn anchor_certificate(&self) -> &StoredCertificate {
        &self.anchor_certificate
    }

    #[must_use]
    pub const fn slots(&self) -> &Slots {
        &self.slots
    }

    /// Take ownership: the issued certificate, the delivered anchor and the
    /// endpoint, all at once and under one new generation.
    ///
    /// One call rather than three setters, because an appliance holding an anchor
    /// and no endpoint — or an endpoint under no anchor — is a state no boot
    /// should be able to reach. The generation advances here, which is what makes
    /// the next write land in the other copy.
    pub fn adopt(
        &mut self,
        device_certificate: StoredCertificate,
        anchor_certificate: StoredCertificate,
        endpoint: StoredEndpoint,
    ) {
        self.device_certificate = device_certificate;
        self.anchor_certificate = anchor_certificate;
        self.endpoint = endpoint;
        self.onboarding = Onboarding::Onboarded;
        self.advance();
    }

    /// Record a configuration document in `slot`, under one new generation.
    pub fn record_document(&mut self, slot: SlotIndex, entry: SlotEntry, running: bool) {
        self.slots.place(slot, entry, running);
        self.advance();
    }

    /// Step the generation, which is what selects the copy the next write goes
    /// to. Saturating: a store that reached `u64::MAX` commits would have
    /// outlived every medium, and a wrap would let an old copy outrank a new one.
    fn advance(&mut self) {
        self.generation = self.generation.saturating_add(1);
    }
}

/// A [`State`] checked against the layout this build compiles against, and
/// therefore the only thing the appliance acts on.
///
/// The distinction is the whole defence against a medium describing some other
/// appliance's store: a [`StateImage`] is internally consistent, which a forger
/// can also arrange, while a `CheckedState` additionally agrees with numbers that
/// came from the build rather than from the device.
pub struct CheckedState(State);

impl CheckedState {
    #[must_use]
    pub const fn get(&self) -> &State {
        &self.0
    }

    /// Consume the check to get a state that can be advanced and rewritten.
    /// Consumed rather than borrowed, so a caller cannot keep the checked handle
    /// and mutate the state behind it.
    #[must_use]
    pub fn into_inner(self) -> State {
        self.0
    }
}

/// A decoded copy: internally consistent and not yet this build's.
pub struct StateImage {
    state: State,
    slot_count: u16,
    slot_sectors: u16,
}

impl StateImage {
    /// Accept the stored state as describing the store this build compiles
    /// against.
    ///
    /// # Errors
    /// [`StateError::LayoutMismatch`], naming both stored numbers. A mismatch is
    /// a store the medium is holding for a different build — the array is a
    /// different size or its slots are — and adopting it would read a slot at a
    /// sector this build believes something else is at.
    pub fn check(self) -> Result<CheckedState, StateError> {
        let owed_count = SLOT_COUNT as u16;
        let owed_sectors = SLOT_SECTORS as u16;
        if self.slot_count != owed_count || self.slot_sectors != owed_sectors {
            return Err(StateError::LayoutMismatch {
                stored_slots: self.slot_count,
                stored_slot_sectors: self.slot_sectors,
            });
        }
        Ok(CheckedState(self.state))
    }

    /// The generation the copy claims, for a caller reporting what it found
    /// before deciding whether to adopt it.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.state.generation
    }
}

/// Which copies of the record one write replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Copies {
    /// The one the generation's parity selects, leaving the copy the appliance
    /// is currently relying on untouched. The steady state.
    Parity,
    /// Both, for a store with nothing of its own on the medium: there is no copy
    /// of *this* appliance's state to preserve, and one left behind is another's.
    Both,
}

/// Where in the region [`encode_state`] wrote and how much — both numbers, so a
/// transfer follows the [`Copies`] decision rather than restating it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateWrite {
    /// The medium sector the write starts at.
    pub sector: u64,
    /// Sectors from `sector`, a whole number of copies.
    pub sectors: u64,
}

/// Compose `state` into the copies `copies` names, inside a buffer holding both.
///
/// `out` is exactly both copies and nothing else, so the short-buffer case is a
/// type nobody can construct.
pub fn encode_state(
    out: &mut [u8; 2 * STATE_COPY_BYTES],
    state: &State,
    copies: Copies,
) -> StateWrite {
    let mut image = [0_u8; STATE_COPY_BYTES];

    write_u64(&mut image, MAGIC_AT, STATE_MAGIC);
    write_u32(&mut image, VERSION_AT, STATE_VERSION);
    write_u32(&mut image, ONBOARDING_AT, state.onboarding.to_bits());
    write_u64(&mut image, GENERATION_AT, state.generation);
    write_bytes(&mut image, DEVICE_ID_AT, &state.device_id);
    write_bytes(&mut image, SECRET_AT, &state.secret);
    write_bytes(&mut image, PUBLIC_AT, &state.public);
    write_bytes(&mut image, ENDPOINT_AT, &state.endpoint.address);
    write_u16(&mut image, ENDPOINT_AT + 4, state.endpoint.port);
    write_u32(
        &mut image,
        DEVICE_CERT_LEN_AT,
        state.device_certificate.len as u32,
    );
    write_u32(
        &mut image,
        ANCHOR_CERT_LEN_AT,
        state.anchor_certificate.len as u32,
    );
    write_u32(&mut image, RUNNING_AT, encode_slot(state.slots.running()));
    write_u32(
        &mut image,
        CANDIDATE_AT,
        encode_slot(state.slots.candidate()),
    );
    write_u16(&mut image, SLOT_COUNT_AT, SLOT_COUNT as u16);
    write_u16(&mut image, SLOT_SECTORS_AT, SLOT_SECTORS as u16);
    for (index, entry) in state.slots.entries().iter().enumerate() {
        // `index < SLOT_COUNT`, so the last byte touched is the one the
        // `SLOT_TABLE_AT + SLOT_COUNT * SLOT_ENTRY_BYTES <= DEVICE_CERT_AT`
        // assertion pins inside the image.
        let at = SLOT_TABLE_AT + index * SLOT_ENTRY_BYTES;
        let (generation, len, digest) = match entry {
            Some(entry) => (entry.generation, entry.len as u32, entry.digest),
            None => (0, 0, [0_u8; DIGEST_LEN]),
        };
        write_u64(&mut image, at + SLOT_GENERATION_AT, generation);
        write_u32(&mut image, at + SLOT_LEN_AT, len);
        write_bytes(&mut image, at + SLOT_DIGEST_AT, &digest);
    }
    write_bytes(
        &mut image,
        DEVICE_CERT_AT,
        state.device_certificate.as_bytes(),
    );
    write_bytes(
        &mut image,
        ANCHOR_CERT_AT,
        state.anchor_certificate.as_bytes(),
    );

    let digest = digest_of(&image);
    write_bytes(&mut image, DIGEST_AT, &digest);

    let (first, second) = out.split_at_mut(STATE_COPY_BYTES);
    match copies {
        // Identical rather than one blanked, so the torn-write defence holds
        // from the first commit.
        Copies::Both => {
            first.copy_from_slice(&image);
            second.copy_from_slice(&image);
            StateWrite {
                sector: crate::STATE_A_SECTOR,
                sectors: 2 * crate::STATE_COPY_SECTORS,
            }
        }
        Copies::Parity => {
            if state.generation.is_multiple_of(2) {
                first.copy_from_slice(&image);
                StateWrite {
                    sector: crate::STATE_A_SECTOR,
                    sectors: crate::STATE_COPY_SECTORS,
                }
            } else {
                second.copy_from_slice(&image);
                StateWrite {
                    sector: crate::STATE_B_SECTOR,
                    sectors: crate::STATE_COPY_SECTORS,
                }
            }
        }
    }
}

/// Decode the newer of the two valid copies.
///
/// `None` where neither is valid — a fresh medium, or one whose record is beyond
/// use. That is not an error: a first boot mints an identity, and the caller that
/// would rather refuse than overwrite is the one holding the policy.
///
/// A tie in generation resolves to the first copy. Two valid copies at one
/// generation are two writes of the same state and are byte-identical, so the
/// rule exists to make the choice total rather than because the outcome differs —
/// except for a forgery that arranged the tie, where a fixed answer is the point.
#[must_use]
pub fn decode_state(bytes: &[u8; 2 * STATE_COPY_BYTES]) -> Option<StateImage> {
    let (first, second) = bytes.split_at(STATE_COPY_BYTES);
    match (decode_copy(first), decode_copy(second)) {
        (Some(first), Some(second)) => Some(if second.generation() > first.generation() {
            second
        } else {
            first
        }),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// One copy, or `None` for anything this writer would not have produced.
///
/// `copy` is exactly [`STATE_COPY_BYTES`] long, from [`decode_state`]'s split of
/// the region, and every offset read is a constant the assertions above pin
/// inside it.
fn decode_copy(copy: &[u8]) -> Option<StateImage> {
    if read_u64(copy, MAGIC_AT) != STATE_MAGIC {
        return None;
    }
    if read_u32(copy, VERSION_AT) != STATE_VERSION {
        return None;
    }
    let stored_digest = read_digest(copy, DIGEST_AT);
    if stored_digest != digest_of_prefix(copy) {
        return None;
    }
    let generation = read_u64(copy, GENERATION_AT);
    // Zero is what a zeroed medium reads as, and a state is minted at one, so a
    // copy claiming it is a copy nothing this appliance runs wrote.
    if generation == 0 {
        return None;
    }
    let onboarding = Onboarding::from_bits(read_u32(copy, ONBOARDING_AT))?;

    let device_len = read_u32(copy, DEVICE_CERT_LEN_AT) as usize;
    let anchor_len = read_u32(copy, ANCHOR_CERT_LEN_AT) as usize;
    if device_len > MAX_STORED_CERTIFICATE || anchor_len > MAX_STORED_CERTIFICATE {
        return None;
    }
    // Every byte the layout does not name for these lengths, in three spans: the
    // tail of each certificate buffer and the reserved run before the digest.
    if !is_zero(
        copy,
        DEVICE_CERT_AT + device_len,
        DEVICE_CERT_AT + MAX_STORED_CERTIFICATE,
    ) || !is_zero(
        copy,
        ANCHOR_CERT_AT + anchor_len,
        ANCHOR_CERT_AT + MAX_STORED_CERTIFICATE,
    ) || !is_zero(copy, ANCHOR_CERT_AT + MAX_STORED_CERTIFICATE, DIGEST_AT)
    {
        return None;
    }
    // The three alignment runs the fields leave between them.
    if !is_zero(copy, PUBLIC_AT + PUBLIC_LEN, ENDPOINT_AT)
        || !is_zero(copy, ENDPOINT_AT + ENDPOINT_LEN, DEVICE_CERT_LEN_AT)
        || !is_zero(
            copy,
            SLOT_TABLE_AT + SLOT_COUNT * SLOT_ENTRY_BYTES,
            DEVICE_CERT_AT,
        )
    {
        return None;
    }

    let stored_count = read_u16(copy, SLOT_COUNT_AT);
    let stored_sectors = read_u16(copy, SLOT_SECTORS_AT);
    // Bounded by this build's array before a single entry is read: the loop below
    // walks `SLOT_COUNT` slots of the image, and a stored count above it would
    // name entries the image does not hold. A count *below* it is a layout
    // mismatch `check` reports, not a short walk.
    if stored_count as usize > SLOT_COUNT {
        return None;
    }

    let mut entries = [None; SLOT_COUNT];
    for (index, slot) in entries.iter_mut().enumerate() {
        let at = SLOT_TABLE_AT + index * SLOT_ENTRY_BYTES;
        let generation = read_u64(copy, at + SLOT_GENERATION_AT);
        let len = read_u32(copy, at + SLOT_LEN_AT) as usize;
        // The four bytes between the length and the digest are this writer's
        // padding and are covered by the digest, so a value in them is another
        // writer's meaning.
        if read_u32(copy, at + SLOT_LEN_AT + 4) != 0 {
            return None;
        }
        if generation == 0 {
            // An empty slot names nothing, so every byte of its entry is this
            // writer's zero.
            if len != 0 || read_digest(copy, at + SLOT_DIGEST_AT) != [0_u8; DIGEST_LEN] {
                return None;
            }
            continue;
        }
        if len == 0 || len > DOCUMENT_BYTES {
            return None;
        }
        *slot = Some(SlotEntry {
            generation,
            len,
            digest: read_digest(copy, at + SLOT_DIGEST_AT),
        });
    }

    let running = decode_slot(read_u32(copy, RUNNING_AT))?;
    let candidate = decode_slot(read_u32(copy, CANDIDATE_AT))?;
    let slots = Slots::decoded(entries, running, candidate).ok()?;

    let mut device_id = [0_u8; DEVICE_ID_BYTES];
    copy_from(copy, DEVICE_ID_AT, &mut device_id);
    let mut secret = [0_u8; SECRET_LEN];
    copy_from(copy, SECRET_AT, &mut secret);
    let mut public = [0_u8; PUBLIC_LEN];
    copy_from(copy, PUBLIC_AT, &mut public);
    let mut address = [0_u8; 4];
    copy_from(copy, ENDPOINT_AT, &mut address);

    let device_certificate = stored_certificate(copy, DEVICE_CERT_AT, device_len)?;
    let anchor_certificate = stored_certificate(copy, ANCHOR_CERT_AT, anchor_len)?;
    // An owner is a certificate, an anchor and an endpoint together. A record
    // claiming ownership with any of the three missing is one no commit of this
    // appliance's produced, and believing it would leave a node that thinks it is
    // owned and has nowhere to dial.
    let endpoint = StoredEndpoint {
        address,
        port: read_u16(copy, ENDPOINT_AT + 4),
    };
    let owned = !device_certificate.is_empty() && !anchor_certificate.is_empty();
    match onboarding {
        Onboarding::Onboarded if !owned || endpoint.is_absent() => return None,
        Onboarding::Unowned if !anchor_certificate.is_empty() || !endpoint.is_absent() => {
            return None;
        }
        Onboarding::Onboarded | Onboarding::Unowned => {}
    }

    Some(StateImage {
        state: State {
            generation,
            onboarding,
            device_id,
            secret,
            public,
            endpoint,
            device_certificate,
            anchor_certificate,
            slots,
        },
        slot_count: stored_count,
        slot_sectors: stored_sectors,
    })
}

/// The private scalar as the first copy of `bytes` carries it, for the one caller
/// that must name the window a factory reset has to erase.
///
/// Positional and decoding nothing, because the proof it serves has to work on a
/// medium whose record no longer decodes — and because the offset of that field
/// is the one thing about this record only its own layout knows. **No production
/// path calls this**: the appliance reaches a scalar through [`decode_state`],
/// which holds the whole copy to its digest first.
#[must_use]
pub fn stored_secret_window(bytes: &[u8; 2 * STATE_COPY_BYTES]) -> [u8; SECRET_LEN] {
    let mut secret = [0_u8; SECRET_LEN];
    copy_from(bytes, SECRET_AT, &mut secret);
    secret
}

fn stored_certificate(copy: &[u8], at: usize, len: usize) -> Option<StoredCertificate> {
    let mut bytes = [0_u8; MAX_STORED_CERTIFICATE];
    let source = copy.get(at..at.checked_add(len)?)?;
    for (slot, byte) in bytes.iter_mut().zip(source) {
        *slot = *byte;
    }
    Some(StoredCertificate { bytes, len })
}

const fn encode_slot(slot: Option<SlotIndex>) -> u32 {
    match slot {
        Some(slot) => slot.get() as u32,
        None => NO_SLOT,
    }
}

/// `None` where the word names neither a slot of this array nor "no slot" —
/// which is a value refused rather than clamped, an index off a medium being the
/// one thing that must not be coerced into range.
fn decode_slot(bits: u32) -> Option<Option<SlotIndex>> {
    if bits == NO_SLOT {
        return Some(None);
    }
    SlotIndex::new(bits as usize).map(Some)
}

/// SHA-256 over a copy's whole prefix, which is what the digest covers.
fn digest_of(image: &[u8; STATE_COPY_BYTES]) -> [u8; DIGEST_LEN] {
    sha256(image.get(..DIGEST_AT).unwrap_or_default())
}

fn digest_of_prefix(copy: &[u8]) -> [u8; DIGEST_LEN] {
    sha256(copy.get(..DIGEST_AT).unwrap_or_default())
}

/// Whether every byte of `from..to` is zero. A range outside the slice reads as
/// empty and so as zero, which no caller here can produce: every bound is a
/// constant the assertions above pin inside a copy, or a length already compared
/// against one.
fn is_zero(copy: &[u8], from: usize, to: usize) -> bool {
    copy.get(from..to)
        .unwrap_or_default()
        .iter()
        .all(|byte| *byte == 0)
}

fn write_bytes(image: &mut [u8; STATE_COPY_BYTES], at: usize, bytes: &[u8]) {
    for (slot, byte) in image.iter_mut().skip(at).zip(bytes) {
        *slot = *byte;
    }
}

fn write_u16(image: &mut [u8; STATE_COPY_BYTES], at: usize, value: u16) {
    write_bytes(image, at, &value.to_le_bytes());
}

fn write_u32(image: &mut [u8; STATE_COPY_BYTES], at: usize, value: u32) {
    write_bytes(image, at, &value.to_le_bytes());
}

fn write_u64(image: &mut [u8; STATE_COPY_BYTES], at: usize, value: u64) {
    write_bytes(image, at, &value.to_le_bytes());
}

/// Copy `into.len()` bytes from `at`. A short source leaves the tail as it was,
/// which no caller here reaches: every offset is a constant inside a copy.
fn copy_from(copy: &[u8], at: usize, into: &mut [u8]) {
    for (slot, byte) in into.iter_mut().zip(copy.iter().skip(at)) {
        *slot = *byte;
    }
}

fn read_u16(copy: &[u8], at: usize) -> u16 {
    let mut bytes = [0_u8; 2];
    copy_from(copy, at, &mut bytes);
    u16::from_le_bytes(bytes)
}

fn read_u32(copy: &[u8], at: usize) -> u32 {
    let mut bytes = [0_u8; 4];
    copy_from(copy, at, &mut bytes);
    u32::from_le_bytes(bytes)
}

fn read_u64(copy: &[u8], at: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    copy_from(copy, at, &mut bytes);
    u64::from_le_bytes(bytes)
}

fn read_digest(copy: &[u8], at: usize) -> [u8; DIGEST_LEN] {
    let mut bytes = [0_u8; DIGEST_LEN];
    copy_from(copy, at, &mut bytes);
    bytes
}

// A sector-addressed structure must be a whole number of sectors, or a write of
// it would leave a partial sector nobody owns.
const _: () = assert!(STATE_COPY_BYTES.is_multiple_of(SECTOR_SIZE));
