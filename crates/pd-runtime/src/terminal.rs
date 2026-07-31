//! The consuming end of a pipeline that has no onward pipeline: a port whose
//! frames stop where they arrive.
//!
//! # Adversary
//!
//! The byzantine peer protection domain (CONCEPT §7.1). Every descriptor read
//! here was written by the driver that owns the pool, so its buffer index, its
//! span and its verdict word are all that domain's choice, and none of them is
//! trusted.
//!
//! # Why a role of its own rather than a [`RouteStage`](crate::RouteStage)
//!
//! In the routed dataplane a frame's descriptor travels *onward*: the stage
//! hands it to the egress driver, and that driver is what puts the buffer back
//! on the ingress driver's `free` ring. The buffer is therefore returned by a
//! domain the stage never has to be granted the ring of, which is the whole
//! reason the forwarder can be denied both `free` rings.
//!
//! A terminal port has no egress driver to inherit that obligation, so the
//! descriptor's journey ends in this domain and there is exactly one way the
//! buffer can go back: this domain produces the return itself. That is the same
//! producer/consumer split the dataplane already has between its two drivers —
//! the pool's owner consumes returns (`PoolOwner::reclaim`), a domain that has
//! finished with a buffer produces one — with this domain standing where the
//! egress driver stands. It needs the `free` ring read-write and it does *not*
//! become the pool's owner: the owner is the driver, which alone decides whether
//! a returned index is one it lent.
//!
//! # No pool, and that absence is the grant
//!
//! Nothing here dereferences a frame. A count of frames and of the bytes they
//! carried is read entirely off the descriptors, so this role borrows no
//! [`Pool`](crate::Pool) — the mirror of the receiving driver, which holds its
//! pool's physical address and no mapping. Whether the *domain* is granted one is
//! the system description's business and `xtask::sysdesc`'s to check.

use crate::{
    DRAIN_LIMIT, ForwardRings, RING_SLOTS, ReturnRing, RingConsumer, RingProducer, bump,
    descriptor_in_bounds,
};

/// What a terminal endpoint has seen, in the shape the metrics endpoint
/// (CONCEPT §11) will scrape.
///
/// Monotonic for the domain's life and saturating, on
/// [`PoolCounters`](crate::PoolCounters)'s terms: there is no reset, because a
/// scrape differences successive samples and a reset would forge a negative
/// rate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TerminalCounters {
    /// Frames taken off the pipeline whose descriptor named a span inside one
    /// pool buffer.
    pub frames: u64,
    /// Bytes those frames carried, as the descriptors named them. It is the
    /// *ingress driver's* measurement — that domain clamped the length its
    /// device reported to the buffer behind it — and never a length this domain
    /// derived, which is why `malformed_descriptor` is counted separately
    /// rather than folded in.
    pub bytes: u64,
    /// Descriptors naming a span outside the pool. Their bytes are counted
    /// nowhere: a span this domain cannot believe is not a frame length it may
    /// add to a total an operator reads.
    pub malformed_descriptor: u64,
    /// Returns the pool owner's ring would not take. Each loses its buffer to
    /// that owner's ledger for good, so a rising count is a shrinking pool.
    pub return_ring_full: u64,
}

/// A pipeline's consuming end where the descriptor goes no further: it counts
/// each frame and hands the buffer straight back to the pool's owner.
pub struct TerminalStage<'ring> {
    from: RingConsumer<'ring, RING_SLOTS>,
    free: RingProducer<'ring, RING_SLOTS>,
    counters: TerminalCounters,
}

impl<'ring> TerminalStage<'ring> {
    /// Take `rings`' `rx` consumer handle and `returns`' `free` producer handle.
    ///
    /// **Unenforced precondition (DOC-7):** call once per protection domain per
    /// pipeline. Each handle is this domain's own position in a ring, so a
    /// second stage over the same pipeline re-consumes descriptors the first
    /// already returned and produces a second return for each — which is
    /// refused by [`PoolOwner::reclaim`](crate::PoolOwner::reclaim)'s lent set
    /// and counted there, so the damage is a lost buffer rather than a
    /// double-owned one. No type refuses the second call; `queue`'s crate
    /// header states that single-handle rule and why nothing enforces it.
    #[must_use]
    pub fn attach(rings: &'ring ForwardRings, returns: &'ring ReturnRing) -> Self {
        Self {
            from: rings.rx.consumer(),
            free: returns.free.producer(),
            counters: TerminalCounters::default(),
        }
    }

    /// Take frames off the pipeline until it is observed empty, the return ring
    /// refuses one, or [`DRAIN_LIMIT`] descriptors have been handled. Returns
    /// how many **frames** were counted, which is the quantity a caller acts
    /// on: a pass that moved only malformed descriptors has nothing new to say
    /// about the port.
    ///
    /// Every descriptor is returned, malformed ones included. The index is
    /// peer-supplied and this domain has no ledger to judge it against, so
    /// judging it is the owner's job and not a second, weaker copy of it here;
    /// withholding a return instead would lose the buffer behind every
    /// descriptor whose *span* was wrong while its index was perfectly good.
    ///
    /// Draining stops on the first refused return for
    /// [`RouteStage::poll`](crate::RouteStage::poll)'s reason: the ring is
    /// sized above the pool, so a refusal means accounting has already broken,
    /// and every further dequeue would strand another buffer.
    pub fn poll(&mut self) -> usize {
        let Self {
            from,
            free,
            counters,
        } = self;
        let mut frames = 0;
        for descriptor in from.drain(DRAIN_LIMIT) {
            if descriptor_in_bounds(&descriptor) {
                bump(&mut counters.frames);
                // Saturating: the rate is attacker-controlled, and a wrapped
                // total turns a sustained flood back into a small number.
                counters.bytes = counters.bytes.saturating_add(u64::from(descriptor.len));
                frames += 1;
            } else {
                bump(&mut counters.malformed_descriptor);
            }
            if free.try_enqueue(descriptor).is_err() {
                bump(&mut counters.return_ring_full);
                break;
            }
        }
        frames
    }

    #[must_use]
    pub fn counters(&self) -> TerminalCounters {
        self.counters
    }
}

#[cfg(test)]
mod tests;
