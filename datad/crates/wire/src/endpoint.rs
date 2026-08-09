//! Where this appliance dials its management plane: one word, written by the
//! domain that holds the state record and read by the domain that will open the
//! channel.
//!
//! Faces the byzantine neighbour protection domain, on
//! [`ApplianceOwnership`](crate::ApplianceOwnership)'s terms exactly. The reader
//! maps this region read-only and the writer is a peer whose behaviour it may not
//! assume, so every bit pattern reaching
//! [`ManagementEndpoint::destination`] is peer-written input. What makes that
//! safe is that the answer is an [`Option`] and three independent tests have to
//! agree before it is `Some`: the word must carry [`ENDPOINT_TAG`], the port must
//! not be zero, and the address must not be all zeroes. A zeroed region — which
//! is what the kernel hands a domain that maps one, and what an appliance nobody
//! has onboarded leaves here — fails all three. **The undecodable answer is
//! therefore nowhere to dial rather than somewhere**, which is the direction a
//! firewall's uncertainty has to fall: an appliance that cannot learn where its
//! management plane is opens no session at all, instead of opening one to
//! whatever address a half-written region happened to spell.
//!
//! # One word, and why the two values share it
//!
//! An address and a port are meaningful only together: a reader that observed a
//! new address beside an old port would dial somewhere nobody published.
//! [`ClockCalibration`](crate::ClockCalibration) brackets such a group with a
//! seqlock counter. That is the wrong instrument here, because a torn pair would
//! not merely be undetectable — it would be *dangerous* in the one way this
//! region exists to prevent, a published tag standing over a stale or zeroed
//! address being exactly the plausible destination the fail-closed reading must
//! never produce. So the pair does not tear: a naturally aligned `u64` store is
//! one access, and a reader observes the value before the write or the value
//! after it and never a blend. The address takes 32 bits and the port 16, which
//! leaves 16 for the tag — the width is what one word has left after the two
//! values that must travel together, and buying a wider tag with a second word
//! would reintroduce the tear.
//!
//! # The word only ever gains a destination
//!
//! An appliance learns where to dial when it takes an owner, and gives that up
//! only by a factory reset — which is asked for by writing a sector of the store
//! medium and takes effect on the boot after it. So within one boot the only
//! transition this region can honestly carry is absent to published. Nothing here
//! enforces that, because a region cannot; what a reader does with a sequence of
//! readings is the reader's, and this type answers one reading at a time.

use core::{
    mem::{align_of, offset_of, size_of},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::MAPPING_ALIGN;

/// The mark that says the word carries a published destination.
///
/// A recognisable constant rather than a set bit, on
/// [`OWNED_TOKEN`](crate::OWNED_TOKEN)'s terms: the region's zeroed state and a
/// value chosen by a compromised writer are then the same answer — nothing to
/// dial — rather than each needing its own reading. It is not a secret and
/// authenticates nothing: it separates *published* from *anything else*, and a
/// domain that may write this region may write it.
pub const ENDPOINT_TAG: u16 = 0x4550;

/// Bits the address occupies at the foot of the word.
const ADDRESS_BITS: u32 = 32;
/// Bits the port occupies above it.
const PORT_BITS: u32 = 16;

/// Somewhere to dial: an address literal and a port.
///
/// An address and never a name, which is what keeps DNS off a path an
/// unauthenticated party could steer — the appliance validates its management
/// server's certificate against the literal it dialled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagementDestination {
    /// The four octets, most significant first, as an address is written.
    pub address: [u8; 4],
    pub port: u16,
}

/// The region: one word, and the two operations over it.
///
/// The field is private and the only ways in are [`publish`](Self::publish),
/// [`clear`](Self::clear) and [`destination`](Self::destination), so a reader
/// cannot come to treat some other bit pattern as a destination and a writer
/// cannot publish a word that is neither.
#[repr(C)]
pub struct ManagementEndpoint {
    word: AtomicU64,
}

impl ManagementEndpoint {
    /// A zeroed region, which is what the kernel hands a domain that maps one —
    /// and which reads as nowhere to dial, so a reader that runs before the
    /// holder of the record has published anything dials nothing.
    ///
    /// A function rather than a `const` for
    /// [`ConfigHandover::zero`](crate::ConfigHandover::zero)'s reason: a `const`
    /// holding an atomic is copied at every mention.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            word: AtomicU64::new(0),
        }
    }

    /// State where this appliance dials.
    ///
    /// `Release`, so everything the writer made durable before calling this — the
    /// state record carrying the endpoint — is ordered before the word a reader
    /// acts on.
    ///
    /// A destination whose port is zero or whose address is all zeroes is
    /// published as the absent one rather than tagged, so the writer cannot put a
    /// word into this region that its own reader would have to reject: the
    /// absence is spelled one way, here, and not left to the reading to
    /// discover.
    pub fn publish(&self, destination: ManagementDestination) {
        let address = u32::from_be_bytes(destination.address);
        if destination.port == 0 || address == 0 {
            self.clear();
            return;
        }
        let word = (u64::from(ENDPOINT_TAG) << (ADDRESS_BITS + PORT_BITS))
            | (u64::from(destination.port) << ADDRESS_BITS)
            | u64::from(address);
        self.word.store(word, Ordering::Release);
    }

    /// State that this appliance has nowhere to dial, which is what an appliance
    /// nobody owns has.
    ///
    /// Written rather than left alone, on the ownership word's terms: the region
    /// already reads this way zeroed, and stating it anyway means the region's own
    /// reading and the writer's cannot differ by an omission.
    pub fn clear(&self) {
        self.word.store(0, Ordering::Release);
    }

    /// Where to dial, or nowhere.
    ///
    /// Three tests, each of which alone is enough to answer `None`: the tag, a
    /// port of zero — which is not a port — and an all-zero address, which names
    /// no host. They are not redundant with each other, because a compromised
    /// writer chooses the whole word: the tag alone would let it publish a tagged
    /// zero, and the two value tests alone would let a zeroed region read as an
    /// address.
    #[must_use]
    pub fn destination(&self) -> Option<ManagementDestination> {
        let word = self.word.load(Ordering::Acquire);
        let tag = (word >> (ADDRESS_BITS + PORT_BITS)) as u16;
        if tag != ENDPOINT_TAG {
            return None;
        }
        let port = (word >> ADDRESS_BITS) as u16;
        let address = word as u32;
        if port == 0 || address == 0 {
            return None;
        }
        Some(ManagementDestination {
            address: address.to_be_bytes(),
            port,
        })
    }
}

/// Bytes the system description reserves for the region, derived rather than
/// chosen: the fewest [`MAPPING_ALIGN`] pages that hold the type.
pub const ENDPOINT_REGION_SIZE: usize =
    size_of::<ManagementEndpoint>().next_multiple_of(MAPPING_ALIGN);

// The layout two protection domains agree on, fixed at build time. One maps this
// region read-write and the other read-only, and neither can see the other's view
// of it, so a width change or a field appearing in front of the word must be a
// compile error here rather than a reader acting on the wrong eight bytes.
const _: () = {
    assert!(size_of::<ManagementEndpoint>() == 8);
    assert!(align_of::<ManagementEndpoint>() == 8);
    assert!(offset_of!(ManagementEndpoint, word) == 0);

    // Naturally aligned, which is what makes the store and the load single
    // accesses — and so what makes the address and the port a pair no reader can
    // observe half of.
    assert!(offset_of!(ManagementEndpoint, word).is_multiple_of(align_of::<u64>()));

    // The three fields tile the word exactly: 32 of address, 16 of port, 16 of
    // tag. A width that overlapped would put one value's bits inside another's
    // and make a published destination read as a different one.
    assert!(ADDRESS_BITS + PORT_BITS + (u16::BITS) == u64::BITS);

    // The tag is not a value either other field can spell into it, which is what
    // keeps a zeroed region and an untagged one the same answer.
    assert!(ENDPOINT_TAG != 0);

    assert!(ENDPOINT_REGION_SIZE >= size_of::<ManagementEndpoint>());
    assert!(ENDPOINT_REGION_SIZE.is_multiple_of(MAPPING_ALIGN));
};

#[cfg(test)]
mod tests;
