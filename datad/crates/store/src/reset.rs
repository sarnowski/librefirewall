//! The factory-reset request: one sector of the store medium, and the only
//! mechanism by which an appliance with no shell and no input path can be told to
//! give up its owner.
//!
//! # Why this and not something a running node could hear
//!
//! Factory reset revokes a management plane's ownership, so it must not be
//! reachable *by* one. Every other path into a running appliance was considered
//! and each is either remote or absent: a channel operation and a configuration
//! document are both the management plane's; the console is output-only and giving
//! it an input path would add an input surface to the domain that owns the serial
//! controller; and a jumper has no representation in a virtual machine.
//!
//! What is left is the medium itself, and it is the right answer rather than the
//! only one: writing this sector requires possession of the store device, which is
//! exactly the physical-access boundary the ownership model already rests on. The
//! argument that it cannot be reached remotely is a capability argument and not a
//! claim about code — **one protection domain in the system maps the store device
//! at all**, that domain holds no network region, no configuration region and no
//! channel from the domain that terminates a connection, and nothing anywhere
//! writes this sector except the reset's own clearing of it. So there is no path
//! from a packet to these bytes, whatever a compromise reaches.
//!
//! # The token, and why the request is cleared before the reset runs
//!
//! The sector must hold [`RESET_REQUEST_BYTES`] of exactly one pattern: a magic,
//! the version the appliance would accept, and zero everywhere else. A stray
//! sector, a mis-addressed write and a previous deployment's bytes all fail it.
//!
//! The request is cleared *first*, before the key is overwritten, and the order is
//! deliberate: a power cut between the two leaves an appliance whose identity is
//! partly gone and which will not reset again on the next boot — which is a node
//! an operator must re-onboard, and is recoverable. The opposite order leaves a
//! node that resets on every boot forever, which is a bricked appliance nobody
//! can onboard.
//!
//! # The request alone decides, not the record
//!
//! A reset is honoured on the strength of this sector and nothing else — before
//! the state record is judged, and whether or not it decodes. That is deliberate
//! too: a record this build refuses is exactly the case an operator reaches for a
//! reset to fix, and an appliance that demanded a coherent identity before it
//! would give one up could never be recovered.
//!
//! # Each medium carries its own request
//!
//! This sector resets *this* medium, and no other. The appliance's persistent
//! state and its recordings sit on two devices owned by two protection domains,
//! neither of which maps a byte of the other's — which is what keeps the domain
//! holding the private scalar unable to reach a recording and the domain
//! answering a download unable to read the scalar. Reaching across from here
//! would breach exactly that property, so it is not reached across: each medium
//! holding an owner's data carries its own request and its own overwrite. The
//! boundary stays exact, because the visit that writes this sector reaches every
//! medium in the appliance.

use crate::layout::SECTOR_SIZE;
use crate::state::{Onboarding, State};

/// Bytes the request occupies: one sector, because the sector is the unit the
/// device promises to write whole.
pub const RESET_REQUEST_BYTES: usize = SECTOR_SIZE;

/// `LFWRESET` in ASCII, leading the sector.
const RESET_MAGIC: u64 = u64::from_le_bytes(*b"LFWRESET");

/// The version of the request this build honours. A request naming another
/// version is refused rather than honoured: a reset is destructive and
/// irreversible, so an ambiguous request is one to ignore.
const RESET_VERSION: u32 = 1;

const MAGIC_AT: usize = 0;
const VERSION_AT: usize = 8;
const NAMED_END: usize = 12;

/// What the reset sector says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetRequest {
    /// The sector holds the token: a physically present operator asked for a
    /// factory reset.
    Requested,
    /// Anything else, including the zeroes the appliance leaves after honouring
    /// one. Not an error and never reported as one — the ordinary state of this
    /// sector is "nothing asked".
    Absent,
}

/// The exact bytes a request is, so a harness or an operator's tool writes the
/// appliance's own definition rather than a second copy of it.
#[must_use]
pub fn reset_token() -> [u8; RESET_REQUEST_BYTES] {
    let mut sector = [0_u8; RESET_REQUEST_BYTES];
    write_reset_request(&mut sector);
    sector
}

/// Compose a request into `sector`, leaving every unnamed byte zero.
pub fn write_reset_request(sector: &mut [u8; RESET_REQUEST_BYTES]) {
    *sector = [0; RESET_REQUEST_BYTES];
    for (slot, byte) in sector
        .iter_mut()
        .skip(MAGIC_AT)
        .zip(RESET_MAGIC.to_le_bytes())
    {
        *slot = byte;
    }
    for (slot, byte) in sector
        .iter_mut()
        .skip(VERSION_AT)
        .zip(RESET_VERSION.to_le_bytes())
    {
        *slot = byte;
    }
}

impl ResetRequest {
    /// Read the sector.
    ///
    /// Every byte is the medium's, so the token is the whole of what is accepted:
    /// the magic, this build's version, and zero in every byte the layout does not
    /// name. There is nothing here to parse and nothing to bound — the answer is a
    /// comparison against one constant pattern.
    #[must_use]
    pub fn read(sector: &[u8; RESET_REQUEST_BYTES]) -> Self {
        if *sector == reset_token() {
            Self::Requested
        } else {
            Self::Absent
        }
    }

    #[must_use]
    pub const fn is_requested(self) -> bool {
        matches!(self, Self::Requested)
    }
}

/// What a factory reset destroyed, as the one console record of it reports.
///
/// Read off the state the medium carried *before* the overwrite, so the numbers
/// describe the appliance being given up rather than the one minted over it.
///
/// Everything is zero or `false` where the medium carried no record this build
/// could read — a reset runs on the request alone, and a store whose record is
/// beyond use is the case a reset is the remedy for. Nothing here is key
/// material: what is reported is a position, a count and a flag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cleared {
    /// The generation the destroyed record stood at, which is where this
    /// appliance's state history ends.
    pub generation: u64,
    /// How many configuration slots that record named as holding a document.
    /// **The whole array is overwritten regardless** — this is how many versions
    /// were lost, not how many sectors were written.
    pub documents: usize,
    /// Whether the appliance had an owner, which is what says whether a delivered
    /// certificate, a trust anchor and an endpoint were among the bytes
    /// destroyed. An unowned appliance's reset destroys only what it minted for
    /// itself.
    pub was_owned: bool,
}

impl Cleared {
    /// What a reset is about to destroy, from the state it found — or nothing,
    /// where it found no state this build could read.
    #[must_use]
    pub fn of(state: Option<&State>) -> Self {
        match state {
            Some(state) => Self {
                generation: state.generation(),
                documents: state.slots().occupied(),
                was_owned: matches!(state.onboarding(), Onboarding::Onboarded),
            },
            None => Self::default(),
        }
    }
}

const _: () = {
    assert!(NAMED_END <= RESET_REQUEST_BYTES);
    assert!(VERSION_AT + 4 == NAMED_END);
    // The magic must not be the state record's, or a mis-addressed write of one
    // structure would read as a request for the other.
    assert!(RESET_MAGIC != crate::STATE_MAGIC);
};
