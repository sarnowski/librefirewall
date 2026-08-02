//! `lfw_http`'s request-head parser, driven the way a TCP connection drives it:
//! one arbitrary byte stream cut into arbitrary segments and fed in.
//!
//! # Adversary
//!
//! The **management-plane attacker**, with nothing in between. Every
//! byte here is that party's, and so is *where the segments fall* — which is
//! the authority a harness that fed the whole buffer at once would model
//! away. Request smuggling is exactly a disagreement about where a message
//! ends, so a parser whose verdict depended on the segmentation would be one an
//! attacker could steer.
//!
//! # What is asserted, beyond not crashing
//!
//! * **Chunking is invisible.** Feeding the same bytes in any number of pieces
//!   yields the same verdict as feeding them whole: the same error, or a
//!   completed head at the same offset. The harness re-derives the whole-buffer
//!   answer and compares.
//! * **Every bound holds.** A completed head's method, target, header count and
//!   each field's name and value are inside the constants that declare them, so
//!   a bound deleted from the parser fails here rather than becoming a longer
//!   line an operator's log carries.
//! * **`consumed` is honest.** It never exceeds what was fed, and the bytes past
//!   it are untouched — the property a caller relies on to know a second request
//!   was not read.
//! * **A head is answered.** Every completed head produces a status the server
//!   can send, and every refusal produces one too, so no input reaches a
//!   connection the server has nothing to say on.

use arbitrary::Unstructured;
use lfw_http::{
    MAX_HEADER_NAME_LEN, MAX_HEADER_VALUE_LEN, MAX_HEADERS, MAX_METHOD_LEN, MAX_TARGET_LEN, Parsed,
    Status, parse,
};

use crate::{any_index, any_u16};

/// Segments one input is cut into, at most. A bound on the harness's own work
/// rather than on the adversary's authority: the cut *points* are arbitrary and
/// every prefix is parsed regardless, so nothing about where a head can end is
/// excluded by it.
const MAX_SEGMENTS: usize = 32;

pub fn http_request_harness(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    // The first bytes decide how the rest is cut; the rest is the stream. A
    // stream shorter than the cut plan is fine — the plan simply runs out.
    let segments = any_index(&mut unstructured, MAX_SEGMENTS) + 1;
    let mut cuts: Vec<usize> = (0..segments)
        .map(|_| usize::from(any_u16(&mut unstructured)))
        .collect();
    let stream = unstructured.take_rest();

    cuts.sort_unstable();
    let mut boundaries: Vec<usize> = cuts.into_iter().map(|cut| cut.min(stream.len())).collect();
    boundaries.push(stream.len());

    // The whole-buffer verdict, which every prefix is judged against.
    let whole = verdict(stream);

    let mut accumulated = 0usize;
    let mut answered = false;
    for boundary in boundaries {
        // A caller accumulates and re-parses; so does this.
        accumulated = boundary.max(accumulated);
        let buffer = stream.get(..accumulated).unwrap_or(stream);
        match parse(buffer) {
            Ok(Parsed::NeedMore) => {
                assert!(
                    !answered,
                    "the parser answered and then asked for more bytes"
                );
            }
            Ok(Parsed::Complete { request, consumed }) => {
                answered = true;
                assert!(consumed <= buffer.len(), "consumed past the buffer");
                assert!(!request.method().is_empty());
                assert!(request.method().len() <= MAX_METHOD_LEN);
                assert!(!request.target().is_empty());
                assert!(request.target().len() <= MAX_TARGET_LEN);
                assert!(
                    request
                        .target()
                        .bytes()
                        .all(|byte| (0x21..=0x7E).contains(&byte)),
                    "a target carrying a byte no request target may"
                );
                let headers: Vec<_> = request.headers().collect();
                assert!(headers.len() <= MAX_HEADERS);
                for header in &headers {
                    assert!(!header.name.is_empty());
                    assert!(header.name.len() <= MAX_HEADER_NAME_LEN);
                    assert!(header.value.len() <= MAX_HEADER_VALUE_LEN);
                    // A field value is what would reach a log line, so no
                    // control byte may survive the parser.
                    assert!(
                        header
                            .value
                            .bytes()
                            .all(|byte| byte == b'\t' || (0x20..=0x7E).contains(&byte)),
                        "a field value carrying a control byte"
                    );
                }
                // The head that completed is a prefix of the whole buffer, so
                // the whole buffer must complete at exactly the same offset.
                assert_eq!(
                    whole,
                    Verdict::Complete(consumed),
                    "the verdict depends on where the segments fell"
                );
            }
            Err(error) => {
                // A fault inside a prefix is a fault in the whole buffer.
                assert_eq!(
                    whole,
                    Verdict::Refused(error.status()),
                    "a refusal depends on where the segments fell"
                );
                // Every refusal names something the server can answer with.
                assert!(Status::ALL.contains(&error.status()));
                return;
            }
        }
    }
}

/// The whole-buffer answer, reduced to what a caller acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    NeedMore,
    Complete(usize),
    Refused(Status),
}

fn verdict(bytes: &[u8]) -> Verdict {
    match parse(bytes) {
        Ok(Parsed::NeedMore) => Verdict::NeedMore,
        Ok(Parsed::Complete { consumed, .. }) => Verdict::Complete(consumed),
        Err(error) => Verdict::Refused(error.status()),
    }
}
