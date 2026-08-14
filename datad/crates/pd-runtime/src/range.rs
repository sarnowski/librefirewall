//! One recording range read, from the extent a peer asked for to the frames
//! that answer it.
//!
//! # Adversary
//!
//! A **management-plane attacker up to and including a compromised management
//! server**, and behind it a **byzantine neighbour protection domain**. The
//! extent's three numbers are the peer's; the bytes and the outcome that come
//! back are the neighbour's. Neither decides how much work this appliance does:
//! every bound below is a constant of this file, and the request is finished — or
//! ended with a stated reason — after a fixed number of frames whatever either
//! of them sends.
//!
//! # A range read is this appliance reading its own medium because a peer said so
//!
//! That is why this type exists rather than the crypto domain forwarding an extent
//! to the reader. Three quantities have to be bounded and none of them by a number
//! on the wire: how large an extent may be, how many frames one answer may spend,
//! and how much of the medium's read bandwidth an answer may take. This file owns
//! the first two; the third is the reader's.
//!
//! # Ending is not truncating
//!
//! An answer that cannot be served says so and carries no bytes. A short read
//! dressed as a complete one is indistinguishable from a complete one to whoever
//! ingests it, so every path out of [`RangeRequest::took`] either advances the
//! extent or ends the answer with an outcome naming why.

use wire::{DownloadSink, RangeOutcome, RangeWant};

use crate::relay::ANSWER_ROOM;

/// Bytes of channel-frame header, and of the ring, status and position in front
/// of a range answer's bytes.
///
/// Restated rather than taken from the framing crate, on
/// [`crate::SHIPPED_RING_BYTES`]'s terms: every protection domain links this
/// crate. What keeps the numbers together is that the composing domain refuses an
/// answer frame it cannot encode.
const CHANNEL_HEADER_LEN: usize = 8;
const RANGE_PREFIX_LEN: usize = 1 + 1 + 8;

/// Bytes a TLS 1.3 record adds to the plaintext inside it.
const TLS_RECORD_OVERHEAD: usize = 5 + 1 + 16;

/// Extent bytes one answer frame may carry.
///
/// The same arithmetic [`crate::SHIPPED_RING_BYTES`] runs and for the same
/// reason — the bound is the single answer buffer the terminating end holds, so
/// one whole frame's ciphertext must fit it — over a prefix two bytes wider,
/// a range answer stating its ring and its status where a shipment states
/// neither.
pub const RANGE_ANSWER_BYTES: usize =
    ANSWER_ROOM - (TLS_RECORD_OVERHEAD + CHANNEL_HEADER_LEN + RANGE_PREFIX_LEN);

/// Bytes of one recording a single request may ask for.
///
/// One mebibyte — a recording segment, and what one frame of this protocol
/// carries: an operator pulling a slice of a recording asks for at most a
/// segment's worth at a time, and the medium reads one request can cause are a
/// bounded burst rather than an open-ended scan. **A constant of this file and
/// never a number the peer chooses** — the peer states a length and this is what
/// that length is judged against, an extent past it being refused outright rather
/// than clamped, so a refused request cannot be mistaken for a served one that
/// happened to stop early.
pub const MAX_RANGE_LENGTH: u64 = 1024 * 1024;

/// Answer frames one request may spend.
///
/// Comfortably over what a maximal extent needs at [`RANGE_ANSWER_BYTES`] a
/// frame — around four times — so
/// a reader handing back short chunks — a segment boundary, a partial window —
/// still completes every admissible extent, while a neighbour that hands back
/// one byte at a time is cut off having cost this many frames rather than
/// having cost the session. Reaching it with bytes still owed **ends the
/// answer**; it never shortens one silently.
pub const MAX_RANGE_FRAMES: u32 = 1024;

const _: () = {
    assert!(RANGE_ANSWER_BYTES > 0);
    assert!(RANGE_ANSWER_BYTES == crate::SHIPPED_RING_BYTES - 2);
    // A maximal extent completes well inside the frame budget when the reader
    // fills its frames, which is what makes an exhausted budget evidence about
    // the reader rather than about the size of the request.
    assert!(MAX_RANGE_LENGTH.div_ceil(RANGE_ANSWER_BYTES as u64) < MAX_RANGE_FRAMES as u64);
    assert!(MAX_RANGE_LENGTH > 0);
};

/// Why an extent a peer asked for is not one this appliance will read.
///
/// One variant per broken rule, because each sends an operator somewhere
/// different: more than this appliance serves in one request, a request for no
/// bytes at all, and an extent whose end does not fit the ring's own coordinate —
/// a server's arithmetic rather than a position on any medium.
///
/// **Typed and named, never a clamp.** An extent quietly cut to the bound would
/// answer a question nobody asked, indistinguishably from a complete one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeRefusal {
    /// The length is past [`MAX_RANGE_LENGTH`].
    LengthTooLong { asked: u64 },
    /// The length is zero. An extent of no bytes is not an extent, and a `Data`
    /// frame carrying none would state a position and convey nothing.
    Empty,
    /// `start + length` does not fit a ring position, so the extent has no end on
    /// any medium.
    EndPastSpace { start: u64, length: u64 },
}

impl RangeRefusal {
    /// The console token naming this cause.
    ///
    /// One token per cause, held here rather than at each emitting site so the
    /// vocabulary has one home.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::LengthTooLong { .. } => "channel-range-too-long",
            Self::Empty => "channel-range-empty",
            Self::EndPastSpace { .. } => "channel-range-end-past-space",
        }
    }
}

/// What taking one fetched chunk left the wire owing.
///
/// Always exactly one frame: a request advances by one frame per chunk or ends
/// with one, so an answer's frame count is the number of times this was produced
/// and there is no path that produces none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "a frame nothing sends is an answer the requester waits forever for"]
pub struct RangeTaken {
    /// The position the frame states: where its bytes begin in the ring's own
    /// append space. Stated even where the outcome carries no bytes, so a
    /// requester reading an ended answer knows how far it got.
    pub position: u64,
    /// Extent bytes the frame carries, from the front of the chunk that was
    /// taken. Zero wherever the outcome ends the answer.
    pub len: usize,
    /// The status the frame states.
    pub status: RangeOutcome,
    /// Whether the answer is complete once this frame has gone.
    pub finished: bool,
    /// The console token naming why the answer ended, where it ended for a reason
    /// other than being served whole. Separate from `status` because the two answer
    /// different readers: the wire has three statuses and the console needs the
    /// cause.
    pub token: Option<&'static str>,
}

/// One extent still owed, and what may still be spent answering it.
///
/// Neither `Copy` nor `Clone`: an answer in progress is a single obligation, and
/// a duplicate of one would be two answers to a request that asked once.
#[derive(Debug, PartialEq, Eq)]
pub struct RangeRequest {
    recording: DownloadSink,
    /// Where the next frame of the answer begins. Moves only on a chunk that was
    /// taken, so a frame that never went leaves it where it was.
    position: u64,
    /// Extent bytes still owed. Only ever decreases, which with the frame budget
    /// is what makes the answer terminate: a chunk that advanced nothing ends the
    /// answer rather than being asked for again.
    remaining: u64,
    /// Frames still available. Only ever decreases.
    budget: u32,
}

impl RangeRequest {
    /// Take an extent a peer asked for, or refuse it.
    ///
    /// # Errors
    /// [`RangeRefusal`], one variant per rule the three numbers broke. Every
    /// bound they are judged against is a constant of this file.
    pub const fn accept(
        recording: DownloadSink,
        start: u64,
        length: u64,
    ) -> Result<Self, RangeRefusal> {
        if length == 0 {
            return Err(RangeRefusal::Empty);
        }
        if length > MAX_RANGE_LENGTH {
            return Err(RangeRefusal::LengthTooLong { asked: length });
        }
        // Checked rather than saturating: an extent whose end saturates is one
        // whose end is not where the peer said, and serving it would answer a
        // different question.
        if start.checked_add(length).is_none() {
            return Err(RangeRefusal::EndPastSpace { start, length });
        }
        Ok(Self {
            recording,
            position: start,
            remaining: length,
            budget: MAX_RANGE_FRAMES,
        })
    }

    /// The extent still owed, as the reader is told it.
    #[must_use]
    pub const fn wanted(&self) -> RangeWant {
        RangeWant {
            recording: self.recording,
            start: self.position,
            length: self.remaining,
        }
    }

    #[must_use]
    pub const fn recording(&self) -> DownloadSink {
        self.recording
    }

    /// Extent bytes still owed.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Answer frames still available.
    #[must_use]
    pub const fn budget(&self) -> u32 {
        self.budget
    }

    /// Take one fetched chunk: `outcome` is how the read went and `len` is how
    /// many bytes came back.
    ///
    /// `len` is the reader's number, so it is cut to what was owed and to what one
    /// frame carries before anything is stated — a neighbour that answered with
    /// more than either would otherwise have this end compose a frame it would
    /// then refuse, or state an extent past the one the peer asked for.
    pub fn took(&mut self, outcome: RangeOutcome, len: usize) -> RangeTaken {
        let position = self.position;
        // Spent on every frame including the one that ends the answer, so a
        // neighbour cannot buy a frame by ending and reopening.
        self.budget = self.budget.saturating_sub(1);
        if outcome.ends_the_answer() {
            self.remaining = 0;
            return RangeTaken {
                position,
                len: 0,
                status: outcome,
                finished: true,
                token: Some(match outcome {
                    RangeOutcome::Overwritten => "channel-range-overwritten",
                    // `Data` cannot reach here, the branch being the negation of
                    // it, and is folded in with the refusal it cannot be
                    // distinguished from on the wire rather than asserted away:
                    // this runs on a path a neighbour drives.
                    RangeOutcome::MediumRefused | RangeOutcome::Data => {
                        "channel-range-medium-refused"
                    }
                }),
            };
        }
        let owed = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let carried = len.min(owed).min(RANGE_ANSWER_BYTES);
        if carried == 0 {
            // A read that produced nothing while bytes were owed. It cannot be
            // asked for again — a request that can be re-asked with no progress
            // is a loop a neighbour paces — and it cannot be reported as data,
            // there being none. So the answer ends, stating on the wire the only
            // status that fits and on the console the cause that is true.
            self.remaining = 0;
            return RangeTaken {
                position,
                len: 0,
                status: RangeOutcome::MediumRefused,
                finished: true,
                token: Some("channel-range-no-progress"),
            };
        }
        // `carried` is at most `remaining` by the line above, so this cannot go
        // below zero and the widening of it is exact.
        let left = self.remaining.saturating_sub(carried as u64);
        if left > 0 && self.budget == 0 {
            // The frame budget is spent and the extent is not served. The chunk
            // in hand is **dropped rather than sent**: a data frame with nothing
            // after it is a short answer the requester cannot tell from a gap,
            // and this end states that it could not serve the extent instead.
            // The position is left where it was, so the frame names the first byte
            // of what was not served.
            self.remaining = 0;
            return RangeTaken {
                position,
                len: 0,
                status: RangeOutcome::MediumRefused,
                finished: true,
                token: Some("channel-range-frames-exhausted"),
            };
        }
        self.remaining = left;
        self.position = self.position.saturating_add(carried as u64);
        RangeTaken {
            position,
            len: carried,
            status: RangeOutcome::Data,
            finished: left == 0,
            token: None,
        }
    }
}

#[cfg(test)]
mod tests;
