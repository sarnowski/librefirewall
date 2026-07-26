//! `packet_buffer` under a byzantine neighbour PD.
//!
//! # The adversary and the surface
//!
//! `FreeList::reclaim` is the crate's own stated trust boundary (CONCEPT §7.1,
//! byzantine neighbour PD): an index handed to a peer leaves as a plain number
//! on a shared ring and comes back as one *of the peer's choosing*. The peer
//! may return an index it was never given, return the same index twice, return
//! one the domain still holds, or invent one outside the pool entirely. Each
//! must be refused as a typed [`ReturnError`] with the ledger unchanged, because
//! accepting one hands a live buffer to a second owner while losing another for
//! good — the exact bug the identity-based ledger replaced a counter to fix.
//!
//! `BufferPool::write` is the second surface: a length the caller does not
//! control must be refused rather than truncated. The length is drawn from a
//! full, unreduced `u32` and spread over `MAX_PAYLOAD` below, which is a limit on
//! what a `&[u8]` can be *made* to be rather than on what an adversary may ask
//! for — see that constant.
//!
//! # What the adversary may express here
//!
//! Every `reclaim` takes a **full, unreduced `u32`**. Duplicates, indices never
//! allocated, indices still held, and values far outside the pool are all
//! reachable, and a share of the stream is biased into `0..N` so the *most*
//! interesting rejections — a duplicate return and a return of a still-held
//! buffer — are reached often rather than only by luck. Held tokens are
//! returned by an arbitrary position in the held vector, so a token whose index
//! was reclaimed out from under it is returned too.
//!
//! # What is asserted
//!
//! * **Exact semantics.** Every `pop`, `push`, and `reclaim` outcome is compared
//!   with an independent model, so a *wrongly accepted* return fails as loudly
//!   as a panic. A harness that only checked for panics would have passed the
//!   double-return bug.
//! * **Conservation, continuously.** `len()` tracks the model's free count and
//!   `is_empty()` never contradicts it, after every single operation.
//! * **Conservation, definitively.** At the end the ledger is drained: the
//!   indices it hands out must be pairwise distinct, all inside the pool, and
//!   exactly the model's free set. That is the "no buffer invented, none lost,
//!   no index free twice" claim checked against the code rather than the model.
//! * **The write boundary.** `write` returns `Ok(len)` exactly when the data
//!   fits and `WriteOutsideBuffer` otherwise, and never truncates.

use std::collections::BTreeSet;

use arbitrary::Unstructured;
use packet_buffer::{
    BUFFER_SIZE, BufferPool, FreeList, OwnedBuffer, ReturnError, WriteOutsideBuffer,
};

use crate::{MAX_OPERATIONS, any_index, any_u32, next_op};

/// Pool size the harness drives. Small enough that a fuzzer reaches full
/// exhaustion and the wrap-around cases quickly, large enough that the free
/// stack's LIFO ordering is exercised rather than degenerate.
const POOL: usize = 8;

/// The longest payload this harness materialises for `BufferPool::write`.
///
/// **A materialisation limit, not a capability filter.** `write`'s length is
/// `data.len()` of a slice the caller must already hold, so the lengths a
/// caller can present are bounded by the memory it owns, not by a `u32` — a
/// four-gigabyte `&[u8]` is not a value any caller of this API, adversarial or
/// otherwise, can produce, and fabricating one from a pointer would be
/// undefined behaviour of the harness's own making. What matters is that the
/// *decision* boundary is covered from both sides with room to spare: `write`
/// splits exactly at `BUFFER_SIZE` and reports the rejected length verbatim, so
/// eight buffers' worth of spread reaches every length below the boundary, the
/// boundary itself, and a wide band above it. Listed in this crate's header
/// among the limits that are not capability filters.
const MAX_PAYLOAD: usize = 8 * BUFFER_SIZE;

/// What the ledger must answer for a return of `index`, derived from the model
/// alone — the same predicate the crate's own property test uses, restated here
/// so the harness is not checking the code against itself.
///
/// `ListFull` never appears: an outstanding index implies a free slot, and that
/// implication is asserted rather than assumed.
fn expected(index: u32, outstanding: &[bool; POOL], free_len: usize) -> Result<(), ReturnError> {
    let slot = index as usize;
    if slot >= POOL {
        return Err(ReturnError::OutOfRange(index));
    }
    if !outstanding[slot] {
        return Err(ReturnError::NotOutstanding(index));
    }
    assert!(
        free_len < POOL,
        "an outstanding index implies a free slot, so ListFull must be unreachable"
    );
    Ok(())
}

/// Drive the ownership ledger and the pool's write boundary against an
/// arbitrary peer.
pub fn free_list_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let mut ledger = FreeList::<POOL>::full();
    let pool = BufferPool::<POOL>::new();

    // The model: which indices are free, in LIFO order, and which are handed
    // out — tracked by identity, independently of the code.
    let mut free: Vec<u32> = (0..POOL as u32).collect();
    let mut outstanding = [false; POOL];
    // Tokens physically in hand. A token stays here after its index is
    // reclaimed from under it, so returning it later must be refused.
    let mut held: Vec<OwnedBuffer<POOL>> = Vec::new();
    // One allocation for every write, sliced to the length under test: the
    // lengths vary, the allocation does not, so the operation budget cannot
    // turn into a quadratic allocation budget.
    let payload = vec![0xA5u8; MAX_PAYLOAD];

    for _ in 0..MAX_OPERATIONS {
        let Some(op) = next_op(&mut unstructured) else {
            break;
        };
        match op % 6 {
            0 => match ledger.pop() {
                Some(buffer) => {
                    let index = buffer.index();
                    assert!(
                        (index as usize) < POOL,
                        "pop handed out index {index}, outside the pool"
                    );
                    assert_eq!(
                        Some(index),
                        free.pop(),
                        "pop did not hand out the model's next free index"
                    );
                    assert!(
                        !outstanding[index as usize],
                        "index {index} was handed out while already outstanding"
                    );
                    outstanding[index as usize] = true;
                    held.push(buffer);
                }
                None => assert!(
                    free.is_empty(),
                    "pop refused while the model had free buffers"
                ),
            },
            1 => {
                if held.is_empty() {
                    continue;
                }
                let buffer = held.remove(any_index(&mut unstructured, held.len()));
                let index = buffer.index();
                let outcome = expected(index, &outstanding, free.len());
                assert_eq!(ledger.push(buffer), outcome, "push of held index {index}");
                if outcome.is_ok() {
                    outstanding[index as usize] = false;
                    free.push(index);
                }
            }
            // The trust boundary, twice over: an unreduced `u32` the peer chose
            // freely, and one biased into the pool so duplicate and still-held
            // returns are reached often rather than by chance. Both are the
            // same call; the bias only changes how often the interesting
            // rejections come up.
            2 | 3 => {
                let index = if op % 6 == 2 {
                    any_u32(&mut unstructured)
                } else {
                    any_u32(&mut unstructured) % (POOL as u32 + 2)
                };
                let outcome = expected(index, &outstanding, free.len());
                assert_eq!(ledger.reclaim(index), outcome, "reclaim of index {index}");
                if outcome.is_ok() {
                    outstanding[index as usize] = false;
                    free.push(index);
                }
            }
            4 => {
                // The write boundary. The index is one we hold, because
                // `write`'s own contract puts ownership on the caller and its
                // out-of-range behaviour is a documented, unconditional panic
                // rather than a rejection — the enforcing component for a
                // peer-supplied index is `pd_runtime::descriptor_in_bounds`,
                // whose agreement with these accessors the `pipeline` harness
                // asserts. What is untrusted *here* is the length.
                let Some(buffer) = held.first() else {
                    continue;
                };
                let len = any_u32(&mut unstructured) as usize % (MAX_PAYLOAD + 1);
                // SAFETY: `buffer` is a token this harness holds, so it owns the
                // index exclusively for this call, and `payload` is a local
                // vector that cannot alias the pool.
                let written = unsafe { pool.write(buffer.index() as usize, &payload[..len]) };
                if len > BUFFER_SIZE {
                    assert_eq!(
                        written,
                        Err(WriteOutsideBuffer {
                            index: buffer.index() as usize,
                            offset: 0,
                            len
                        }),
                        "an oversized write must be refused, never truncated"
                    );
                } else {
                    assert_eq!(
                        written,
                        Ok(len as u32),
                        "a fitting write must report exactly the bytes written"
                    );
                }
            }
            _ => {
                // Read the ledger's own view back and check it cannot disagree
                // with itself, whatever the peer has been doing. Through a
                // local, because comparing `len()` inline would let a lint fold
                // the comparison back into `is_empty()` and make it
                // tautological — the same trap `crates/queue` documents.
                let reported = ledger.len();
                assert_eq!(reported, free.len(), "free count diverged from the model");
                assert_eq!(ledger.is_empty(), reported == 0);
            }
        }

        assert_eq!(
            ledger.len(),
            free.len(),
            "free count diverged from the model"
        );
        assert!(ledger.len() <= POOL, "the ledger grew past the pool");
        assert_eq!(
            ledger.len() + outstanding.iter().filter(|out| **out).count(),
            POOL,
            "free plus outstanding must always cover the pool exactly"
        );
    }

    // Definitive conservation, read out of the code rather than the model: hand
    // back every token, then drain the ledger. What comes out must be pairwise
    // distinct and inside the pool — an index handed out twice here is one
    // buffer with two owners, which is the failure this crate exists to make
    // unrepresentable.
    for buffer in held {
        let index = buffer.index();
        let outcome = expected(index, &outstanding, free.len());
        assert_eq!(ledger.push(buffer), outcome, "final push of index {index}");
        if outcome.is_ok() {
            outstanding[index as usize] = false;
            free.push(index);
        }
    }

    let mut drained = BTreeSet::new();
    let mut count = 0usize;
    // One more than the pool holds: the loop must end by the ledger refusing,
    // not by this bound, and that is asserted immediately after.
    for _ in 0..=POOL {
        let Some(buffer) = ledger.pop() else {
            break;
        };
        count += 1;
        let index = buffer.index();
        assert!(
            (index as usize) < POOL,
            "the drained ledger handed out index {index}, outside the pool"
        );
        assert!(drained.insert(index), "index {index} was free twice");
    }
    assert!(
        ledger.is_empty(),
        "the drain ended on its own bound, not on exhaustion"
    );
    assert_eq!(count, drained.len());
    assert_eq!(
        drained,
        free.iter().copied().collect::<BTreeSet<u32>>(),
        "the ledger's free set diverged from the model's"
    );
    assert_eq!(
        drained.len() + outstanding.iter().filter(|out| **out).count(),
        POOL,
        "the pool lost or invented a buffer over the run"
    );
}
