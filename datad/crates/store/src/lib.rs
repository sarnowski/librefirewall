#![cfg_attr(not(test), no_std)]

//! The appliance's own persistent state as it sits on the store medium: the
//! transactional double-buffered state record ([`state`]), the fixed
//! configuration slot array it names ([`slots`]), the sector layout both are
//! placed by ([`layout`]), and the factory-reset request a physically present
//! operator leaves on the medium ([`reset`]).
//!
//! It also mints and verifies the identity that record carries ([`identity`]):
//! the device name, the keypair, the self-signed onboarding certificate and the
//! fingerprint. That is here rather than in the domain for the same reason the
//! formats are — given the same randomness and the same instant it is the same
//! arithmetic on a host as on the appliance.
//!
//! And it takes the ownership an onboarding package delivers ([`install`]): the
//! whole package contract re-applied, the device certificate held to the key this
//! record already carries, and one signature verified under one profile. Here for
//! the same reason again — every rule of it is arithmetic over a byte string a
//! host test can hold, and what the protection domain keeps is the region the
//! bytes crossed in and the device they are written to.
//!
//! Nothing here touches a device. What a transfer is and how one is submitted
//! belongs to `lfw_blk`, and which sector to move belongs to the protection
//! domain that owns the medium; this crate decides what the bytes mean, so all
//! of it is reachable by a host test.
//!
//! # The adversary
//!
//! Two, and only one of them arrives off the medium.
//!
//! **A hostile or malfunctioning device**, and behind it a physical attacker who
//! wrote the medium at leisure. Every byte decoded here arrived off a disk: a
//! sector the device mis-addressed, a record the other image slot wrote, or a
//! whole store an offline attacker composed. So a copy is a state record only if
//! it carries the magic, the version, a digest over itself, lengths inside their
//! bounds, slot indices inside the array, and zero in every byte the layout does
//! not name — and even then only [`state::StateImage::check`], against the
//! layout this build compiles against, turns it into something the appliance may
//! act on. There is no panicking construct, no bare index and no unbounded loop
//! on any path from those bytes.
//!
//! The key material this record carries is the one thing on the medium that is
//! not merely data: it is plaintext there, deliberately and for want of anywhere
//! to keep a wrapping key, so physical possession of the medium is identity
//! theft. Nothing in this crate renders, formats or `Debug`s a private scalar,
//! and [`state::State`] derives no `Debug` for that reason.
//!
//! And, on the install path alone, a **management-plane attacker** with a
//! **byzantine neighbour protection domain** behind them: an onboarding package
//! is authenticated by the session it arrived in and by nothing else, and it
//! reaches [`install`] across a region a second domain writes. Those bytes are
//! held to the package contract and to nothing weaker, and the same three rules
//! hold on that path as on this one — no panicking construct, no bare index, no
//! unbounded loop.
//!
//! # Why a double buffer and not a ring
//!
//! A ring overwrites by design, which is the right nature for a temporary
//! recording buffer and the wrong one for an identity. The record is two copies
//! at fixed sectors, each with its own generation and digest, and a change
//! composes the **whole** new state into the copy the generation's parity
//! selects — so the copy the appliance is currently relying on is never the copy
//! being written, and a power cut mid-write costs the newer copy while the older
//! still decodes. That "either the old state or the new one, never a torn one"
//! property is structural rather than argued, and it is the reason a flush is
//! issued between the write and anything that depends on it.
//!
//! What is reused from the recording superblock is only its proven primitives:
//! two copies at a fixed location, a checksum covering everything, unnamed bytes
//! held at zero, both copies invalid meaning a fresh medium rather than an
//! error, and a typestate boundary where only a checked state may be acted on.
//! The checksum is SHA-256 rather than that superblock's CRC-32 because this
//! record is security state: a CRC detects rot and is trivially forgeable, and a
//! digest at least makes a forged record a preimage problem rather than an
//! arithmetic one. It is not a signature and does not pretend to be — there is
//! nowhere on this medium to keep a key that would make one mean anything.
//!
//! # The slot table lives in one place
//!
//! A configuration slot is document bytes and nothing else: its generation, its
//! length and its digest are in the state record's slot table, not repeated in a
//! header on the slot. Two copies of one fact are two things that can disagree,
//! and the record is the copy a reader would have to believe anyway — so the
//! slot carries no self-description at all.

mod identity;
mod install;
mod layout;
mod reset;
mod slots;
mod state;

#[cfg(test)]
mod tests;

pub use identity::{Identity, IdentityError, Minted, mint, verify};
pub use install::{Adoption, ChainFault, InstallError, read as read_package};
pub use layout::{
    RESET_REQUEST_SECTOR, SECTOR_SIZE, SLOT_COUNT, SLOT_SECTORS, SLOTS_START_SECTOR,
    STATE_A_SECTOR, STATE_B_SECTOR, STATE_COPY_BYTES, STATE_COPY_SECTORS, STORE_SECTORS,
    slot_sector,
};
pub use reset::{Cleared, RESET_REQUEST_BYTES, ResetRequest, reset_token, write_reset_request};
pub use slots::{DOCUMENT_BYTES, Reuse, SlotEntry, SlotIndex, Slots};
pub use state::{
    CheckedState, Copies, DEVICE_ID_BYTES, ENDPOINT_LEN, MAX_STORED_CERTIFICATE, Onboarding,
    SECRET_LEN, STATE_MAGIC, STATE_VERSION, State, StateError, StateImage, StateWrite,
    StoredCertificate, StoredEndpoint, decode_state, encode_state, stored_secret_window,
};
