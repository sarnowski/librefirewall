//! The one line a configuration operation is reported with, and the vocabulary
//! it is composed from.
//!
//! # Adversary
//!
//! A **byzantine neighbour protection domain**: the deciding domain chooses
//! every byte of the answer this line renders, and the reject reason arrives as
//! a bare word out of a region that domain writes. [`reject_reason_of`] refuses
//! a word naming no reason rather than coercing it, and every write below is
//! bounded by the array it is given, so a number no vocabulary holds costs a
//! substituted token and never a byte past the line.
//!
//! # Why the line is composed here and not where it is sent
//!
//! The domain that terminates the management channel is the one that reports
//! what a configuration operation became, and it is not the domain that decides
//! about the document. Both halves of that split name the outcome, and a second
//! spelling of `unchanged` in either is how the console line, the channel's
//! result frame and the appliance's own record would come to disagree — so the
//! tokens are [`lfw_log::GenerationOutcome`]'s and the grammar has one
//! implementation, here, where neither half owns it.
//!
//! [`write_result_line`] writes no line ending. The channel's result frame is
//! exactly one line and the frame is what delimits it, so a newline in the
//! payload is a byte the far end refuses.

use lfw_log::RejectReason;

/// Bytes the line reporting a configuration operation occupies at most.
///
/// Derived from the vocabulary rather than chosen: the longest reject reason,
/// the widest generation, and the field names around them. A line that outgrew
/// this would be truncated into a different outcome, so the number moves with
/// the vocabulary.
pub const MAX_ANSWER_LEN: usize = answer_bound();

const fn answer_bound() -> usize {
    let mut longest = 0;
    let mut index = 0;
    while index < RejectReason::ALL.len() {
        let len = RejectReason::ALL[index].name().len();
        if len > longest {
            longest = len;
        }
        index += 1;
    }
    // "generation=" + 10 + " outcome=refused" + " rejected=" + reason +
    // " offset=" + 10 + "\n"
    11 + 10 + 16 + 10 + longest + 8 + 10 + 1
}

/// What a configuration operation became, in the console's own words.
///
/// The tokens are [`lfw_log::GenerationOutcome`]'s, so the console line and the
/// line the management channel carries say the same thing about the same event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Refused,
    Unchanged,
    /// The document is the candidate and nothing is committed.
    Staged,
    /// A provisional commit was made permanent.
    Confirmed,
    /// A provisional commit was undone and what it displaced is running again.
    Reverted,
}

impl Outcome {
    const fn token(self) -> &'static str {
        match self {
            Self::Applied => lfw_log::GenerationOutcome::Applied.name(),
            Self::Refused => lfw_log::GenerationOutcome::Refused.name(),
            Self::Unchanged => lfw_log::GenerationOutcome::Unchanged.name(),
            Self::Staged => lfw_log::GenerationOutcome::Staged.name(),
            Self::Confirmed => lfw_log::GenerationOutcome::Confirmed.name(),
            Self::Reverted => lfw_log::GenerationOutcome::Reverted.name(),
        }
    }
}

/// The reject reason a peer-written word names, for a caller outside this module
/// that has to render one. Re-exported rather than reimplemented: what an
/// undecodable value is substituted with is a decision, and it has one copy.
#[must_use]
pub fn reject_reason_of(bits: u32) -> RejectReason {
    reason_of(bits)
}

/// Compose the one line a configuration operation is reported with, **without a
/// line ending**, answering its length.
///
/// It cannot overrun: [`MAX_ANSWER_LEN`] is derived from this grammar, and every
/// write below is bounded by the slice it is given.
pub fn write_result_line(
    out: &mut [u8; MAX_ANSWER_LEN],
    generation: u32,
    outcome: Outcome,
    changes: u32,
    rejection: Option<(RejectReason, u32)>,
) -> usize {
    let mut at = 0usize;
    put(out, &mut at, b"generation=");
    number(out, &mut at, generation);
    put(out, &mut at, b" outcome=");
    put(out, &mut at, outcome.token().as_bytes());
    match rejection {
        Some((reason, detail)) => {
            put(out, &mut at, b" rejected=");
            put(out, &mut at, reason.name().as_bytes());
            put(out, &mut at, b" offset=");
            number(out, &mut at, detail);
        }
        None => {
            put(out, &mut at, b" changes=");
            number(out, &mut at, changes);
        }
    }
    at
}

/// The reject reason a word out of the reply region names.
///
/// The word is peer-written, so a value naming no reason is refused rather than
/// coerced — and the substitute is `malformed`, which is what an unreadable answer
/// about a document amounts to. A reason this domain could not name would
/// otherwise have to be rendered as a number, which is a token an operator cannot
/// look up.
fn reason_of(bits: u32) -> RejectReason {
    let Ok(index) = usize::try_from(bits) else {
        return RejectReason::Malformed;
    };
    RejectReason::ALL
        .get(index)
        .copied()
        .unwrap_or(RejectReason::Malformed)
}

/// Copy `bytes` in at `at`, advancing it. A `zip` rather than a slice, so nothing
/// here can index past the array; the bound is [`MAX_ANSWER_LEN`]'s derivation and
/// what would be lost is the tail of a line rather than memory safety.
fn put(out: &mut [u8; MAX_ANSWER_LEN], at: &mut usize, bytes: &[u8]) {
    for (cell, byte) in out.iter_mut().skip(*at).zip(bytes) {
        *cell = *byte;
        *at = at.saturating_add(1);
    }
}

fn number(out: &mut [u8; MAX_ANSWER_LEN], at: &mut usize, value: u32) {
    let mut digits = [b'0'; 10];
    let mut written = 0usize;
    let mut rest = value;
    loop {
        let digit = b'0'.saturating_add((rest % 10) as u8);
        // Written backwards into a ten-byte array, which holds every `u32`.
        if let Some(cell) = digits.get_mut(9usize.saturating_sub(written)) {
            *cell = digit;
        }
        written = written.saturating_add(1);
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    put(
        out,
        at,
        digits
            .get(10usize.saturating_sub(written)..)
            .unwrap_or_default(),
    );
}

#[cfg(test)]
mod tests;
