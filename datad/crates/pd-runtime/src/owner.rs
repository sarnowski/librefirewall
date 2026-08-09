//! The forwarding domain's reading of whether this appliance has an owner.
//!
//! # Adversary
//!
//! A **byzantine neighbour protection domain**. The region is written by the
//! domain that holds the identity and mapped read-only here, so the word is a
//! peer's to choose at any instant. `wire::ApplianceOwnership` decides which
//! single pattern means owned; what this module decides is what a *sequence* of
//! readings means, which is the part a region cannot answer.
//!
//! # The reading is latched, and that is the whole of this module
//!
//! An appliance takes an owner once. It gives one up only by factory reset,
//! which is asked for on the store medium and takes effect on the boot after
//! it — so within a boot the honest transitions are none and unowned-to-owned.
//! A reader that simply mirrored the word every wakeup would give a compromised
//! writer a switch over the whole dataplane: forwarding on, forwarding off, at
//! whatever rate it liked, with the console reporting each flip. Latching the
//! first owned reading removes that reach entirely — a peer can bring this
//! appliance's forwarding up, which it can already do by installing a package,
//! and it can never take it back down.
//!
//! What that costs is that a writer clearing the word mid-boot is not obeyed.
//! That is the correct reading of a state the appliance cannot legitimately
//! reach, and the boot after it starts from the medium and so from the truth.

use pipeline::Ownership;
use wire::ApplianceOwnership;

/// What one reading of the region did to what this domain believes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipChange {
    /// The reading agreed with what was already believed, which is every reading
    /// but at most one per boot.
    Unchanged,
    /// The appliance was taken while this domain was running: the one transition
    /// a boot can carry, and the one an operator is told about.
    Adopted,
}

/// The forwarding domain's belief about ownership, and the latch that keeps it
/// monotone.
///
/// Constructed unowned rather than from a first reading, so a domain that is
/// asked for its belief before it has ever polled the region answers the
/// fail-closed one.
#[derive(Clone, Copy, Debug, Default)]
pub struct OwnershipWatch {
    ownership: Ownership,
}

impl OwnershipWatch {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ownership: Ownership::Unowned,
        }
    }

    /// What the chain decides under.
    #[must_use]
    pub const fn ownership(&self) -> Ownership {
        self.ownership
    }

    /// Read the region and answer whether this reading changed anything.
    ///
    /// Once owned, nothing here reads the region's answer as authority to go
    /// back: the load still happens, and its result is discarded, because the
    /// alternative is a branch whose fast path depends on what a peer wrote.
    pub fn poll(&mut self, region: &ApplianceOwnership) -> OwnershipChange {
        if matches!(self.ownership, Ownership::Owned) {
            return OwnershipChange::Unchanged;
        }
        if region.owned() {
            self.ownership = Ownership::Owned;
            return OwnershipChange::Adopted;
        }
        OwnershipChange::Unchanged
    }
}

#[cfg(test)]
mod tests;
