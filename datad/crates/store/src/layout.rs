//! Where every structure sits on the store medium, as compiled-in constants.
//!
//! Compiled in rather than discovered, on the recording extents' terms: hardware
//! topology is fixed at build time, so a layout read off the medium would be a
//! layout the medium gets to choose. What the medium *does* carry is which layout
//! it was written under, and [`crate::StateImage::check`] refuses a record whose
//! answer disagrees with these numbers — adopting one would place a slot read
//! over another object's bytes.

/// A block, in bytes, on `lfw_blk::SECTOR_SIZE`'s terms and declined as a
/// dependency for one integer: this crate touches no device.
pub const SECTOR_SIZE: usize = 512;

/// Sectors one copy of the state record occupies, and so the size of the image
/// [`crate::encode_state`] composes.
///
/// Eight, which is one mapped page. The record needs a little over four sectors
/// for its fields and its two certificates, and the rest is the reserved tail a
/// field can be added into without moving the slot array — which is what a fixed
/// layout buys and what a tightly-sized record would spend on every change.
pub const STATE_COPY_SECTORS: u64 = 8;

/// Bytes one copy occupies. Every offset in the record is checked against this.
pub const STATE_COPY_BYTES: usize = STATE_COPY_SECTORS as usize * SECTOR_SIZE;

/// The first copy's sector. Zero, so the store identifies itself in a hex dump
/// of the medium's first sector without a decoder.
pub const STATE_A_SECTOR: u64 = 0;

/// The second copy's sector, immediately behind the first. Two whole-copy writes
/// rather than two halves of one sector, because the tear this guards against is
/// the sector and independence needs two of them.
pub const STATE_B_SECTOR: u64 = STATE_A_SECTOR + STATE_COPY_SECTORS;

/// The sector a physically present operator writes to ask for a factory reset,
/// and the only sector of this medium anything outside the store domain is ever
/// expected to have written.
///
/// It sits between the record and the slot array rather than inside either,
/// because a reset request is not state: a record that could carry one would be
/// a record the appliance rewrites on every commit, and the request must survive
/// exactly one boot and no commits.
pub const RESET_REQUEST_SECTOR: u64 = STATE_B_SECTOR + STATE_COPY_SECTORS;

/// The slot array's first sector.
///
/// Twenty-four rather than seventeen: it is the first multiple of a mapped page
/// past the reset request, so every slot transfer starts on a page boundary of
/// the staging window it crosses. The seven sectors between are unused and stay
/// unused — the medium's spare room is not something to grow into.
pub const SLOTS_START_SECTOR: u64 = 24;

/// Sectors one configuration slot occupies: exactly the document bound, and no
/// header. See the crate header on why a slot describes nothing about itself.
pub const SLOT_SECTORS: u64 = (crate::DOCUMENT_BYTES / SECTOR_SIZE) as u64;

/// Slots the array holds.
///
/// Eight, which is 512 KiB of documents and keeps the whole store under a
/// megabyte. It is a version history rather than an archive: what it must hold is
/// the running configuration, the candidate, and enough previous versions for a
/// rollback an operator would actually reach for.
pub const SLOT_COUNT: usize = 8;

/// Sectors this build claims of the medium. Everything past it is unused, and a
/// device larger than this is not grown into.
pub const STORE_SECTORS: u64 = SLOTS_START_SECTOR + SLOT_SECTORS * SLOT_COUNT as u64;

/// The first sector of slot `index`.
///
/// Takes a [`crate::SlotIndex`], which is `< SLOT_COUNT` by construction, so the
/// answer is inside the array by arithmetic rather than by a check.
#[must_use]
pub const fn slot_sector(index: crate::SlotIndex) -> u64 {
    SLOTS_START_SECTOR + SLOT_SECTORS * index.get() as u64
}

// The layout, decided when the program is compiled rather than argued about in
// prose. A structure that overlapped its neighbour would be one write silently
// destroying another object.
const _: () = {
    assert!(STATE_COPY_BYTES == 4096);
    assert!(STATE_A_SECTOR + STATE_COPY_SECTORS <= STATE_B_SECTOR);
    assert!(STATE_B_SECTOR + STATE_COPY_SECTORS <= RESET_REQUEST_SECTOR);
    assert!(RESET_REQUEST_SECTOR < SLOTS_START_SECTOR);
    // The slot array starts on a mapped page, which is what keeps a slot's
    // transfer aligned to the staging window it crosses.
    assert!((SLOTS_START_SECTOR as usize * SECTOR_SIZE).is_multiple_of(0x1000));
    assert!(SLOT_SECTORS as usize * SECTOR_SIZE == crate::DOCUMENT_BYTES);
    // Under a megabyte, which is the whole store's budget.
    assert!(STORE_SECTORS as usize * SECTOR_SIZE < 1024 * 1024);
    // Copy selection is generation parity, which needs exactly two copies.
    assert!(STATE_B_SECTOR - STATE_A_SECTOR == STATE_COPY_SECTORS);
};
