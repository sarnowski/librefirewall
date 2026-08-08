use lfw_clock::{Duration, Monotonic};
use lfw_http::{MAX_HEADER_NAME_LEN, MAX_HEADERS, MAX_TARGET_LEN, Status};
use lfw_log::{DomainDetail, OnboardRefusal, OnboardRoute};
use lfw_x509::{DEVICE_ID_LEN, FINGERPRINT_LEN, MAX_CSR_PEM_LEN};
use proptest::prelude::*;

use crate::{
    BASE_INTERVAL, BURST, Decision, Identity, Limiter, MAX_BACKOFF_SHIFT, MAX_PAGE_LEN,
    MAX_RESPONSE_LEN, Onboarding, PageDoesNotFit, REQUEST_CAPACITY, REQUEST_RECORDS, Throttle,
    write_page,
};

const DEVICE: &[u8; DEVICE_ID_LEN] = b"51c2d7744c1c58082f4d4a84b4565ef9";
const FINGERPRINT: &[u8; FINGERPRINT_LEN] =
    b"9f2b1c0d4e5a6789abcdef0123456789abcdef0123456789abcdef0123456789";

/// A request PEM that is not one, which is all this crate needs of it: what
/// makes a real one real is `lfw_x509`, and this surface serves bytes.
const CSR: &[u8] =
    b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBAA==\n-----END CERTIFICATE REQUEST-----\n";

fn identity() -> Identity {
    Identity::new(*DEVICE, *FINGERPRINT, CSR)
}

/// An appliance with an identity, at an instant a limiter can measure from.
fn surface() -> Onboarding {
    let mut onboarding = Onboarding::new(Some(identity()));
    onboarding.opened();
    onboarding
}

/// Nanoseconds since boot as an instant, built the only way the clock crate
/// offers one without a calibration.
fn at(millis: u64) -> Option<Monotonic> {
    Some(Monotonic::BOOT.saturating_add(Duration::from_millis(millis)))
}

/// Drive one whole request over a fresh connection and answer what it decided
/// and what went back.
fn request(
    onboarding: &mut Onboarding,
    now: Option<Monotonic>,
    head: &[u8],
) -> (Decision, Vec<u8>) {
    onboarding.opened();
    let decision = onboarding.take(now, head);
    let mut answer = Vec::new();
    answer.extend_from_slice(onboarding.pending());
    let len = answer.len();
    onboarding.sent(len);
    (decision, answer)
}

fn get(target: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: appliance\r\n\r\n").into_bytes()
}

/// The status line of a response, as a client reads it.
fn status_line(answer: &[u8]) -> String {
    String::from_utf8_lossy(answer)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// The body, which is whatever follows the blank line.
fn body(answer: &[u8]) -> String {
    let text = String::from_utf8_lossy(answer).into_owned();
    match text.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_owned(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// The two resources
// ---------------------------------------------------------------------------

#[test]
fn the_page_carries_the_name_and_the_fingerprint_and_links_to_the_request() {
    let mut onboarding = surface();
    let (decision, answer) = request(&mut onboarding, at(0), &get("/"));
    assert!(matches!(
        decision,
        Decision::Served {
            route: OnboardRoute::Page,
            ..
        }
    ));
    assert_eq!(status_line(&answer), "HTTP/1.1 200 OK");
    let text = String::from_utf8_lossy(&answer).into_owned();
    assert!(text.contains("Content-Type: text/html; charset=utf-8"));
    assert!(text.contains("Connection: close"));
    let page = body(&answer);
    // The two strings an administrator compares, each exactly as the profile
    // renders it — no separators, no upper case, nothing to normalise.
    assert!(page.contains(core::str::from_utf8(DEVICE).expect("ascii")));
    assert!(page.contains(core::str::from_utf8(FINGERPRINT).expect("ascii")));
    assert!(page.contains("/certificate.csr"));
    // And the sentence that stands in for the form this build does not have.
    assert!(page.contains("POST /configuration.tar"));
    assert!(!page.contains("<form"));
    assert!(!page.contains("<input"));
}

#[test]
fn the_page_declares_the_length_it_really_sent() {
    let mut onboarding = surface();
    let (decision, answer) = request(&mut onboarding, at(0), &get("/"));
    let Decision::Served { bytes, .. } = decision else {
        panic!("the page is served");
    };
    let text = String::from_utf8_lossy(&answer).into_owned();
    assert!(text.contains(&format!("Content-Length: {bytes}\r\n")));
    assert_eq!(body(&answer).len(), bytes);
    assert!(bytes <= MAX_PAGE_LEN);
}

#[test]
fn the_request_is_served_byte_for_byte_under_its_own_media_type() {
    let mut onboarding = surface();
    let (decision, answer) = request(&mut onboarding, at(0), &get("/certificate.csr"));
    assert!(matches!(
        decision,
        Decision::Served {
            route: OnboardRoute::CertificateRequest,
            ..
        }
    ));
    assert_eq!(status_line(&answer), "HTTP/1.1 200 OK");
    assert!(String::from_utf8_lossy(&answer).contains("Content-Type: application/pkcs10"));
    assert_eq!(body(&answer).as_bytes(), CSR);
}

#[test]
fn a_query_string_still_names_the_resource_it_is_appended_to() {
    let mut onboarding = surface();
    for target in ["/?t=1", "/certificate.csr?download=1"] {
        let (decision, _) = request(&mut onboarding, at(0), &get(target));
        assert!(
            matches!(decision, Decision::Served { .. }),
            "{target} names a resource"
        );
    }
}

#[test]
fn a_request_arriving_in_pieces_is_answered_when_it_ends_and_not_before() {
    let mut onboarding = surface();
    onboarding.opened();
    let head = get("/");
    for split in 1..head.len() {
        let mut fresh = Onboarding::new(Some(identity()));
        fresh.opened();
        let (front, back) = head.split_at(split);
        assert_eq!(fresh.take(at(0), front), Decision::Waiting, "at {split}");
        assert!(fresh.pending().is_empty(), "at {split}");
        assert!(!fresh.finished(), "at {split}");
        assert!(
            matches!(fresh.take(at(0), back), Decision::Served { .. }),
            "at {split}"
        );
    }
}

#[test]
fn an_answered_connection_takes_nothing_further_and_finishes_when_it_has_gone() {
    let mut onboarding = surface();
    onboarding.opened();
    assert!(matches!(
        onboarding.take(at(0), &get("/")),
        Decision::Served { .. }
    ));
    assert!(!onboarding.finished());
    // A peer that pipelines a second request onto a connection already
    // committed to an answer is read and dropped, never parsed.
    assert_eq!(
        onboarding.take(at(0), &get("/certificate.csr")),
        Decision::Waiting
    );
    let owed = onboarding.pending().len();
    onboarding.sent(owed / 2);
    assert!(!onboarding.finished());
    onboarding.sent(owed);
    assert!(onboarding.finished());
    assert!(onboarding.pending().is_empty());
}

#[test]
fn a_fresh_connection_inherits_no_byte_of_the_last_one() {
    let mut onboarding = surface();
    onboarding.opened();
    assert_eq!(onboarding.take(at(0), b"GET / HT"), Decision::Waiting);
    onboarding.opened();
    // The half-written line above would make this one malformed if it were
    // still held.
    assert!(matches!(
        onboarding.take(at(0), &get("/")),
        Decision::Served { .. }
    ));
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

/// The token a request is refused under, and the status the peer was told.
fn refusal(onboarding: &mut Onboarding, head: &[u8]) -> (OnboardRefusal, Status) {
    let (decision, answer) = request(onboarding, at(0), head);
    let Decision::Refused {
        refusal, status, ..
    } = decision
    else {
        panic!("{} is refused", String::from_utf8_lossy(head));
    };
    assert_eq!(
        status_line(&answer),
        format!("HTTP/1.1 {} {}", status.code(), status.reason())
    );
    // A refusal has no body at all.
    assert!(body(&answer).is_empty());
    (refusal, status)
}

#[test]
fn each_way_a_request_is_refused_carries_a_token_of_its_own() {
    let mut onboarding = surface();
    // Every one of these is a different thing for an administrator to go and
    // change, so a token standing for two of them would name neither.
    let cases: [(&[u8], OnboardRefusal, Status); 13] = [
        (
            b"GET /nope HTTP/1.1\r\n\r\n",
            OnboardRefusal::UnknownRoute,
            Status::NotFound,
        ),
        (
            b"POST /configuration.tar HTTP/1.1\r\n\r\n",
            OnboardRefusal::UnknownRoute,
            Status::NotFound,
        ),
        (
            b"POST / HTTP/1.1\r\n\r\n",
            OnboardRefusal::MethodNotServed,
            Status::MethodNotAllowed,
        ),
        (
            b"HEAD /certificate.csr HTTP/1.1\r\n\r\n",
            OnboardRefusal::MethodNotServed,
            Status::MethodNotAllowed,
        ),
        (
            b"GET / HTTP/1.1\nHost: x\r\n\r\n",
            OnboardRefusal::BareLineFeed,
            Status::BadRequest,
        ),
        (
            b"GET / HTTP/1.1\r\n\rX: y\r\n\r\n",
            OnboardRefusal::StrayCarriageReturn,
            Status::BadRequest,
        ),
        (
            b"GET /\r\n\r\n",
            OnboardRefusal::MalformedRequestLine,
            Status::BadRequest,
        ),
        (
            b"G(T) / HTTP/1.1\r\n\r\n",
            OnboardRefusal::MalformedMethod,
            Status::BadRequest,
        ),
        (
            b"GET \x01 HTTP/1.1\r\n\r\n",
            OnboardRefusal::MalformedTarget,
            Status::BadRequest,
        ),
        (
            b"GET / HTTP/1.0\r\n\r\n",
            OnboardRefusal::UnsupportedVersion,
            Status::VersionNotSupported,
        ),
        (
            b"GET / HTTP/x\r\n\r\n",
            OnboardRefusal::MalformedVersion,
            Status::BadRequest,
        ),
        (
            b"GET / HTTP/1.1\r\n Host: x\r\n\r\n",
            OnboardRefusal::ObsoleteLineFolding,
            Status::BadRequest,
        ),
        (
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\n",
            OnboardRefusal::BodyTooLarge,
            Status::ContentTooLarge,
        ),
    ];
    for (head, owed, status) in cases {
        assert_eq!(
            refusal(&mut onboarding, head),
            (owed, status),
            "{}",
            String::from_utf8_lossy(head)
        );
    }
}

#[test]
fn the_remaining_parser_refusals_reach_their_own_tokens_too() {
    let mut onboarding = surface();
    let long_target = format!("/{}", "a".repeat(MAX_TARGET_LEN));
    assert_eq!(
        refusal(&mut onboarding, get(&long_target).as_slice()),
        (OnboardRefusal::TargetTooLong, Status::UriTooLong)
    );

    let mut many = String::from("GET / HTTP/1.1\r\n");
    for index in 0..=MAX_HEADERS {
        many.push_str(&format!("X-{index}: y\r\n"));
    }
    many.push_str("\r\n");
    assert_eq!(
        refusal(&mut onboarding, many.as_bytes()),
        (OnboardRefusal::TooManyHeaders, Status::HeadersTooLarge)
    );

    let long_name = format!(
        "GET / HTTP/1.1\r\n{}: y\r\n\r\n",
        "n".repeat(MAX_HEADER_NAME_LEN + 1)
    );
    assert_eq!(
        refusal(&mut onboarding, long_name.as_bytes()),
        (OnboardRefusal::MalformedHeaderName, Status::HeadersTooLarge)
    );

    let long_value = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "v".repeat(512));
    assert_eq!(
        refusal(&mut onboarding, long_value.as_bytes()),
        (
            OnboardRefusal::MalformedHeaderValue,
            Status::HeadersTooLarge
        )
    );

    // A body on a `GET`, which this surface never takes: refused for its
    // framing rather than for its length, and told apart from a length too
    // large by a token of its own.
    assert_eq!(
        refusal(
            &mut onboarding,
            b"GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"
        ),
        (OnboardRefusal::BodyNotAccepted, Status::BadRequest)
    );
    assert_eq!(
        refusal(
            &mut onboarding,
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        (OnboardRefusal::BodyNotAccepted, Status::BadRequest)
    );

    let mut not_utf8 = b"GET / HTTP/1.1\r\nX: ".to_vec();
    not_utf8.extend_from_slice(&[0xff, 0xfe]);
    not_utf8.extend_from_slice(b"\r\n\r\n");
    assert_eq!(
        refusal(&mut onboarding, &not_utf8),
        (OnboardRefusal::NotUtf8, Status::BadRequest)
    );
}

#[test]
fn a_head_that_never_ends_is_refused_at_the_bound_rather_than_waited_on() {
    let mut onboarding = surface();
    onboarding.opened();
    let filler = vec![b'a'; REQUEST_CAPACITY];
    assert_eq!(onboarding.take(at(0), b"GET /"), Decision::Waiting);
    let decision = onboarding.take(at(0), &filler);
    let Decision::Refused {
        refusal,
        status,
        held,
        throttle,
    } = decision
    else {
        panic!("a head past the bound is refused");
    };
    assert_eq!(refusal, OnboardRefusal::HeadTooLong);
    assert_eq!(status, Status::HeadersTooLarge);
    assert_eq!(held, REQUEST_CAPACITY);
    assert_eq!(throttle, None);
}

#[test]
fn a_boot_with_no_identity_refuses_under_a_token_that_blames_nothing_on_the_peer() {
    let mut onboarding = Onboarding::new(None);
    let (decision, answer) = request(&mut onboarding, at(0), &get("/"));
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::IdentityAbsent,
            status: Status::ServiceUnavailable,
            ..
        }
    ));
    assert_eq!(status_line(&answer), "HTTP/1.1 503 Service Unavailable");
}

#[test]
fn a_refusal_reports_the_head_it_was_holding_when_it_decided() {
    let mut onboarding = surface();
    let head = b"GET /nope HTTP/1.1\r\n\r\n";
    let (decision, _) = request(&mut onboarding, at(0), head);
    let Decision::Refused { held, .. } = decision else {
        panic!("an unknown resource is refused");
    };
    assert_eq!(held, head.len());
}

// ---------------------------------------------------------------------------
// The limiter
// ---------------------------------------------------------------------------

#[test]
fn a_burst_is_admitted_and_the_one_past_it_is_not() {
    let mut limiter = Limiter::new();
    for spent in 0..BURST {
        assert_eq!(limiter.admit(at(0)), Ok(()), "allowance {spent}");
    }
    assert_eq!(limiter.allowance(), 0);
    let refused = limiter.admit(at(0)).expect_err("the burst is spent");
    assert_eq!(refused.strikes, 1);
    assert!(refused.wait_millis > 0);
}

#[test]
fn every_refusal_expires_and_the_wait_is_bounded() {
    let mut limiter = Limiter::new();
    for _ in 0..BURST {
        assert_eq!(limiter.admit(at(0)), Ok(()));
    }
    // Hammered: the interval doubles, and it stops doubling.
    let mut longest = 0;
    for _ in 0..64 {
        let refused = limiter.admit(at(0)).expect_err("nothing has elapsed");
        longest = longest.max(refused.wait_millis);
        assert!(refused.strikes <= MAX_BACKOFF_SHIFT);
    }
    let bound = (BASE_INTERVAL.as_nanos() / 1_000_000) << MAX_BACKOFF_SHIFT;
    assert_eq!(longest, bound);
    // And it comes back. This is the property the whole design turns on: there
    // is no sequence of requests after which an allowance never returns.
    assert_eq!(limiter.admit(at(bound)), Ok(()));
    assert_eq!(limiter.strikes(), 0);
}

#[test]
fn an_admitted_request_ends_the_run_of_refusals() {
    let mut limiter = Limiter::new();
    for _ in 0..BURST {
        assert_eq!(limiter.admit(at(0)), Ok(()));
    }
    assert!(limiter.admit(at(0)).is_err());
    assert!(limiter.admit(at(0)).is_err());
    assert_eq!(limiter.strikes(), 2);
    // Four seconds is one allowance at the two-strike interval, and taking it
    // clears the run: what the backoff is against is consecutive refusals.
    assert_eq!(limiter.admit(at(4_000)), Ok(()));
    assert_eq!(limiter.strikes(), 0);
}

#[test]
fn a_partial_interval_is_kept_rather_than_discarded() {
    let mut limiter = Limiter::new();
    for _ in 0..BURST {
        assert_eq!(limiter.admit(at(0)), Ok(()));
    }
    // The refusal that spends the burst puts the interval at two seconds. A
    // second refusal a second later must not restart the wait: an origin reset
    // on every call would mean a peer that polls never earns anything, which is
    // the lockout this design forbids.
    assert!(limiter.admit(at(0)).is_err());
    assert!(limiter.admit(at(1_000)).is_err());
    assert_eq!(limiter.admit(at(4_000)), Ok(()));
}

#[test]
fn the_allowance_never_grows_past_the_burst() {
    let mut limiter = Limiter::new();
    assert_eq!(limiter.admit(at(0)), Ok(()));
    // A year of quiet is still one burst: an allowance that accumulated would
    // hand a peer that waited an arbitrarily large one.
    assert_eq!(limiter.admit(at(31_536_000_000)), Ok(()));
    assert_eq!(limiter.allowance(), BURST - 1);
}

#[test]
fn a_node_with_no_clock_is_not_limited_at_all() {
    let mut limiter = Limiter::new();
    // Refusing here would be a lockout nothing expires, which is the one
    // outcome the design forbids outright.
    for _ in 0..1024 {
        assert_eq!(limiter.admit(None), Ok(()));
    }
    assert_eq!(limiter.allowance(), BURST);
    assert_eq!(limiter.strikes(), 0);
}

#[test]
fn the_limiter_outlives_a_connection_and_the_buffers_do_not() {
    let mut onboarding = surface();
    for _ in 0..BURST {
        let (decision, _) = request(&mut onboarding, at(0), &get("/"));
        assert!(matches!(decision, Decision::Served { .. }));
    }
    let (decision, answer) = request(&mut onboarding, at(0), &get("/"));
    let Decision::Refused {
        refusal,
        status,
        throttle,
        ..
    } = decision
    else {
        panic!("the burst is spent");
    };
    assert_eq!(refusal, OnboardRefusal::RateLimited);
    assert_eq!(status, Status::TooManyRequests);
    assert_eq!(status_line(&answer), "HTTP/1.1 429 Too Many Requests");
    let Some(Throttle {
        strikes,
        wait_millis,
    }) = throttle
    else {
        panic!("a throttled request says how long the wait is");
    };
    assert_eq!(strikes, 1);
    // The interval the *next* request will be measured against, not the one
    // that just ran out: the strike is what lengthened it, and a wait reported
    // shorter than the one really imposed would send an administrator back too
    // early to be admitted.
    assert_eq!(wait_millis, 2 * BASE_INTERVAL.as_nanos() / 1_000_000);
    assert_eq!(onboarding.limiter().strikes(), 1);
}

#[test]
fn the_limiter_runs_before_the_route_so_every_refusal_costs_the_same() {
    let mut onboarding = surface();
    for _ in 0..BURST {
        assert!(matches!(
            request(&mut onboarding, at(0), &get("/")).0,
            Decision::Served { .. }
        ));
    }
    // A request for something that does not exist is throttled rather than
    // answered "no such resource": what the limiter bounds is how much work a
    // peer can ask for, not how much of it succeeds.
    let (decision, _) = request(&mut onboarding, at(0), &get("/nope"));
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::RateLimited,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// What reaches the console
// ---------------------------------------------------------------------------

#[test]
fn a_decision_owes_the_records_its_shape_names_and_no_others() {
    assert_eq!(Decision::Waiting.records(), [None, None]);

    let served = Decision::Served {
        route: OnboardRoute::CertificateRequest,
        bytes: 431,
    };
    assert_eq!(
        served.records(),
        [
            Some(DomainDetail::OnboardingServed {
                route: OnboardRoute::CertificateRequest,
                bytes: 431,
            }),
            None,
        ]
    );

    let refused = Decision::Refused {
        refusal: OnboardRefusal::UnknownRoute,
        status: Status::NotFound,
        held: 22,
        throttle: None,
    };
    assert_eq!(
        refused.records(),
        [
            Some(DomainDetail::OnboardingRequest {
                refusal: OnboardRefusal::UnknownRoute,
                status: 404,
                held: 22,
            }),
            None,
        ]
    );

    // The one decision that owes two: the limiter's, because when the next
    // request will be admitted is a different question from why this one was
    // not.
    let throttled = Decision::Refused {
        refusal: OnboardRefusal::RateLimited,
        status: Status::TooManyRequests,
        held: 22,
        throttle: Some(Throttle {
            strikes: 3,
            wait_millis: 8_000,
        }),
    };
    assert_eq!(
        throttled.records(),
        [
            Some(DomainDetail::OnboardingRequest {
                refusal: OnboardRefusal::RateLimited,
                status: 429,
                held: 22,
            }),
            Some(DomainDetail::OnboardingThrottled {
                strikes: 3,
                wait_millis: 8_000,
            }),
        ]
    );
    assert_eq!(throttled.records().len(), REQUEST_RECORDS);
}

// ---------------------------------------------------------------------------
// The page writer and the identity's own bounds
// ---------------------------------------------------------------------------

#[test]
fn the_page_bound_is_the_page_it_bounds() {
    let mut out = [0_u8; MAX_PAGE_LEN];
    let len = write_page(DEVICE, FINGERPRINT, &mut out).expect("the derived bound holds it");
    assert_eq!(len, MAX_PAGE_LEN);
    let mut short = [0_u8; MAX_PAGE_LEN - 1];
    assert_eq!(
        write_page(DEVICE, FINGERPRINT, &mut short),
        Err(PageDoesNotFit {
            capacity: MAX_PAGE_LEN - 1
        })
    );
}

#[test]
fn a_request_longer_than_the_armouring_can_be_is_clamped_rather_than_overrunning() {
    // Unreachable from this appliance's own writer, whose bound is where
    // `MAX_CSR_PEM_LEN` comes from; held anyway, because a clamp is what keeps
    // a first-party arithmetic slip off a path a peer drives.
    let over = vec![b'x'; MAX_CSR_PEM_LEN + 64];
    let identity = Identity::new(*DEVICE, *FINGERPRINT, &over);
    assert_eq!(identity.csr().len(), MAX_CSR_PEM_LEN);
    let mut onboarding = Onboarding::new(Some(identity));
    let (decision, answer) = request(&mut onboarding, at(0), &get("/certificate.csr"));
    assert!(matches!(decision, Decision::Served { .. }));
    assert_eq!(body(&answer).len(), MAX_CSR_PEM_LEN);
}

#[test]
fn every_response_this_surface_composes_fits_the_bound_it_reserves() {
    let mut onboarding = Onboarding::new(Some(Identity::new(
        *DEVICE,
        *FINGERPRINT,
        &vec![b'x'; MAX_CSR_PEM_LEN],
    )));
    for target in ["/", "/certificate.csr"] {
        let (_, answer) = request(&mut onboarding, at(0), &get(target));
        assert!(answer.len() <= MAX_RESPONSE_LEN, "{target}");
    }
}

proptest! {
    /// Arbitrary bytes in arbitrary pieces produce a decision and never a
    /// fault, whatever the clock does.
    #[test]
    fn arbitrary_bytes_are_decided_and_never_fault(
        pieces in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..96), 0..12),
        clocked in any::<bool>(),
        millis in any::<u64>(),
    ) {
        let mut onboarding = Onboarding::new(Some(identity()));
        onboarding.opened();
        let now = if clocked { at(millis) } else { None };
        for piece in &pieces {
            let decision = onboarding.take(now, piece);
            if let Decision::Served { bytes, .. } = decision {
                prop_assert!(bytes <= crate::MAX_BODY_LEN);
            }
            // Whatever was decided, what is owed the wire is inside the buffer
            // that holds it.
            prop_assert!(onboarding.pending().len() <= MAX_RESPONSE_LEN);
        }
        let owed = onboarding.pending().len();
        onboarding.sent(owed.saturating_add(1024));
        prop_assert!(onboarding.pending().is_empty());
    }

    /// A limiter driven by arbitrary instants never reports an unbounded wait
    /// and never refuses for ever.
    #[test]
    fn a_limiter_never_reports_a_wait_it_cannot_honour(
        // Milliseconds inside a century. Past that the clock crate's own
        // millisecond-to-nanosecond conversion saturates, and two distinct
        // readings become one instant — which is a property of that conversion
        // rather than of this limiter, and asserting against it here would be
        // testing the wrong crate.
        instants in prop::collection::vec(0_u64..3_155_760_000_000, 1..64),
    ) {
        let bound = (BASE_INTERVAL.as_nanos() / 1_000_000) << MAX_BACKOFF_SHIFT;
        let mut limiter = Limiter::new();
        let mut latest = 0u64;
        for millis in instants {
            latest = latest.max(millis);
            if let Err(throttle) = limiter.admit(at(millis)) {
                prop_assert!(throttle.wait_millis <= bound);
                prop_assert!(throttle.strikes <= MAX_BACKOFF_SHIFT);
            }
        }
        // However it was driven, waiting out the longest interval admits.
        prop_assert_eq!(limiter.admit(at(latest.saturating_add(bound))), Ok(()));
    }
}
