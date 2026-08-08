use lfw_clock::{Duration, Monotonic};
use lfw_http::{MAX_HEADER_NAME_LEN, MAX_HEADERS, MAX_TARGET_LEN, Status};
use lfw_log::{DomainDetail, OnboardRefusal, OnboardRoute};
use lfw_x509::{DEVICE_ID_LEN, FINGERPRINT_LEN, MAX_CSR_PEM_LEN};
use proptest::prelude::*;

use crate::{
    BASE_INTERVAL, BURST, Decision, Identity, Limiter, MAX_BACKOFF_SHIFT, MAX_PAGE_LEN,
    MAX_RESPONSE_LEN, MAX_UPLOAD_LEN, Onboarding, PageDoesNotFit, REQUEST_CAPACITY,
    REQUEST_RECORDS, Throttle, Upload, UploadRefused, write_page,
};

/// An upload that keeps everything and installs everything, which is what makes
/// every path through the surface reachable on a host: the protection domain's
/// own writes into a shared region and its exchange with the key holder are the
/// two things a host cannot have, and this is the shape of the hole they leave.
///
/// The knobs are the three answers a real one can give — refuse to begin, keep
/// fewer bytes than were offered, refuse to install — so a test names the
/// failure it is about rather than arranging one.
#[derive(Default)]
struct Sink {
    body: Vec<u8>,
    opened: Vec<usize>,
    installs: u32,
    refuse_open: bool,
    /// Bytes to keep out of every segment offered, `None` for all of them.
    keep: Option<usize>,
    refuse_install: bool,
}

impl Sink {
    fn refusing_to_open() -> Self {
        Self {
            refuse_open: true,
            ..Self::default()
        }
    }

    fn keeping(keep: usize) -> Self {
        Self {
            keep: Some(keep),
            ..Self::default()
        }
    }

    fn refusing_to_install() -> Self {
        Self {
            refuse_install: true,
            ..Self::default()
        }
    }
}

impl Upload for Sink {
    fn open(&mut self, declared: usize) -> Result<(), UploadRefused> {
        self.opened.push(declared);
        if self.refuse_open {
            return Err(UploadRefused);
        }
        Ok(())
    }

    fn take(&mut self, segment: &[u8]) -> usize {
        let kept = self.keep.unwrap_or(segment.len()).min(segment.len());
        self.body
            .extend_from_slice(segment.get(..kept).unwrap_or_default());
        kept
    }

    fn install(&mut self) -> Result<(), UploadRefused> {
        self.installs += 1;
        if self.refuse_install {
            return Err(UploadRefused);
        }
        Ok(())
    }
}

/// An upload nothing on this path ever reaches, for the requests that are not
/// uploads. Its methods are unreachable and say so by failing the test rather
/// than by quietly answering.
struct NoUpload;

impl Upload for NoUpload {
    fn open(&mut self, _declared: usize) -> Result<(), UploadRefused> {
        panic!("a request that is not an upload reserved one");
    }

    fn take(&mut self, _segment: &[u8]) -> usize {
        panic!("a request that is not an upload offered a body");
    }

    fn install(&mut self) -> Result<(), UploadRefused> {
        panic!("a request that is not an upload was installed");
    }
}

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
    let mut onboarding = Onboarding::new(Some(identity()), false);
    onboarding.opened();
    onboarding
}

/// A `POST /configuration.tar` head declaring `len` bytes of body.
fn upload_head(len: usize) -> Vec<u8> {
    format!("POST /configuration.tar HTTP/1.1\r\nHost: appliance\r\nContent-Length: {len}\r\n\r\n")
        .into_bytes()
}

/// Drive a whole upload over a fresh connection, delivering the head and the
/// body in the pieces given.
fn upload(
    onboarding: &mut Onboarding,
    sink: &mut Sink,
    declared: usize,
    deliveries: &[&[u8]],
) -> (Decision, Vec<u8>) {
    onboarding.opened();
    let mut decision = Decision::Waiting;
    for delivery in deliveries {
        decision = onboarding.take(at(0), delivery, sink);
    }
    let _ = declared;
    let mut answer = Vec::new();
    answer.extend_from_slice(onboarding.pending());
    let len = answer.len();
    onboarding.sent(len);
    (decision, answer)
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
    let decision = onboarding.take(now, head, &mut NoUpload);
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
    // And the command that uploads a package, rather than a control that would
    // have to be unwrapped: the package is the whole body of the request, and a
    // browser form can only send one wrapped in an encoding of its own.
    assert!(page.contains("/configuration.tar"));
    assert!(page.contains("curl"));
    assert!(page.contains("--data-binary"));
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
        let mut fresh = Onboarding::new(Some(identity()), false);
        fresh.opened();
        let (front, back) = head.split_at(split);
        assert_eq!(
            fresh.take(at(0), front, &mut NoUpload),
            Decision::Waiting,
            "at {split}"
        );
        assert!(fresh.pending().is_empty(), "at {split}");
        assert!(!fresh.finished(), "at {split}");
        assert!(
            matches!(
                fresh.take(at(0), back, &mut NoUpload),
                Decision::Served { .. }
            ),
            "at {split}"
        );
    }
}

#[test]
fn an_answered_connection_takes_nothing_further_and_finishes_when_it_has_gone() {
    let mut onboarding = surface();
    onboarding.opened();
    assert!(matches!(
        onboarding.take(at(0), &get("/"), &mut NoUpload),
        Decision::Served { .. }
    ));
    assert!(!onboarding.finished());
    // A peer that pipelines a second request onto a connection already
    // committed to an answer is read and dropped, never parsed.
    assert_eq!(
        onboarding.take(at(0), &get("/certificate.csr"), &mut NoUpload),
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
    assert_eq!(
        onboarding.take(at(0), b"GET / HT", &mut NoUpload),
        Decision::Waiting
    );
    onboarding.opened();
    // The half-written line above would make this one malformed if it were
    // still held.
    assert!(matches!(
        onboarding.take(at(0), &get("/"), &mut NoUpload),
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
    let cases: [(&[u8], OnboardRefusal, Status); 14] = [
        (
            b"GET /nope HTTP/1.1\r\n\r\n",
            OnboardRefusal::UnknownRoute,
            Status::NotFound,
        ),
        // The upload route exists and takes a body, so a `POST` to it declaring
        // none is refused for being empty rather than for not being served.
        (
            b"POST /configuration.tar HTTP/1.1\r\n\r\n",
            OnboardRefusal::UploadEmpty,
            Status::BadRequest,
        ),
        // And a `GET` of it is the method refusal, not the address one: the
        // resource is there, under a method it is not served with.
        (
            b"GET /configuration.tar HTTP/1.1\r\n\r\n",
            OnboardRefusal::MethodNotServed,
            Status::MethodNotAllowed,
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
        // A body on a route that does not take one. The declared length is
        // inside the bound — the bound is the archive's, for every route — so
        // what refuses this is the method the resource is not served under.
        (
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\n",
            OnboardRefusal::MethodNotServed,
            Status::MethodNotAllowed,
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
    assert_eq!(
        onboarding.take(at(0), b"GET /", &mut NoUpload),
        Decision::Waiting
    );
    let decision = onboarding.take(at(0), &filler, &mut NoUpload);
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
    let mut onboarding = Onboarding::new(None, false);
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
    let mut onboarding = Onboarding::new(Some(identity), false);
    let (decision, answer) = request(&mut onboarding, at(0), &get("/certificate.csr"));
    assert!(matches!(decision, Decision::Served { .. }));
    assert_eq!(body(&answer).len(), MAX_CSR_PEM_LEN);
}

#[test]
fn every_response_this_surface_composes_fits_the_bound_it_reserves() {
    let mut onboarding = Onboarding::new(
        Some(Identity::new(
            *DEVICE,
            *FINGERPRINT,
            &vec![b'x'; MAX_CSR_PEM_LEN],
        )),
        false,
    );
    for target in ["/", "/certificate.csr"] {
        let (_, answer) = request(&mut onboarding, at(0), &get(target));
        assert!(answer.len() <= MAX_RESPONSE_LEN, "{target}");
    }
}

#[test]
fn a_package_is_handed_on_whole_and_installed_and_the_answer_carries_no_body() {
    let mut onboarding = surface();
    let mut sink = Sink::default();
    let archive = vec![0xa5_u8; 4096];
    let mut delivery = upload_head(archive.len());
    delivery.extend_from_slice(&archive);
    let (decision, answer) = upload(&mut onboarding, &mut sink, archive.len(), &[&delivery]);

    assert_eq!(decision, Decision::Installed { bytes: 4096 });
    assert_eq!(sink.opened, vec![4096]);
    assert_eq!(sink.body, archive);
    assert_eq!(sink.installs, 1);
    assert_eq!(status_line(&answer), "HTTP/1.1 200 OK");
    // No body at all: the status is the whole of what a client is owed, and
    // prose composed for one would be a second surface to keep true.
    assert!(body(&answer).is_empty());
    assert!(String::from_utf8_lossy(&answer).contains("Connection: close"));
    assert!(onboarding.finished());
}

/// The whole reason the head is filled before it is parsed: one TLS delivery is
/// tens of kibibytes, so an upload's first one carries a head and a great deal
/// of body — and a surface that refused on the arithmetic would answer a
/// legitimate upload "your headers are too large".
#[test]
fn a_first_delivery_far_longer_than_the_head_buffer_is_an_upload_and_not_a_long_head() {
    let mut onboarding = surface();
    let mut sink = Sink::default();
    let archive = vec![7_u8; 8 * REQUEST_CAPACITY];
    let mut delivery = upload_head(archive.len());
    delivery.extend_from_slice(&archive);
    let (decision, _) = upload(&mut onboarding, &mut sink, archive.len(), &[&delivery]);
    assert_eq!(
        decision,
        Decision::Installed {
            bytes: 8 * REQUEST_CAPACITY
        }
    );
    assert_eq!(sink.body, archive);
}

/// A package arrives in whatever pieces the network chose, including pieces
/// that cut the head, cut the boundary between head and body, and cut the body.
#[test]
fn a_package_split_anywhere_is_reassembled_in_order() {
    let archive: Vec<u8> = (0..3000_u32).map(|byte| byte as u8).collect();
    let mut whole = upload_head(archive.len());
    let head_len = whole.len();
    whole.extend_from_slice(&archive);
    for split in [1, head_len - 1, head_len, head_len + 1, whole.len() - 1] {
        let mut onboarding = surface();
        let mut sink = Sink::default();
        let (front, back) = whole.split_at(split);
        let (decision, _) = upload(&mut onboarding, &mut sink, archive.len(), &[front, back]);
        assert_eq!(
            decision,
            Decision::Installed {
                bytes: archive.len()
            },
            "at {split}"
        );
        assert_eq!(sink.body, archive, "at {split}");
    }
}

/// The body is judged when the last byte of it arrives and not before, so a peer
/// that stops short is left waiting rather than having a short archive installed.
#[test]
fn a_body_that_stops_short_installs_nothing_and_answers_nothing() {
    let mut onboarding = surface();
    let mut sink = Sink::default();
    let mut delivery = upload_head(64);
    delivery.extend_from_slice(&[1_u8; 32]);
    let (decision, answer) = upload(&mut onboarding, &mut sink, 64, &[&delivery]);
    assert_eq!(decision, Decision::Waiting);
    assert_eq!(sink.installs, 0);
    assert!(answer.is_empty());
    assert!(!onboarding.finished());
}

/// A peer contradicting its own `Content-Length`. Refused rather than truncated
/// to the declared length: two parties disagreeing about where a message ends is
/// the one thing this surface's parser has only one opinion about.
#[test]
fn a_body_longer_than_it_declared_is_refused_by_name() {
    let mut onboarding = surface();
    let mut sink = Sink::default();
    let mut delivery = upload_head(16);
    delivery.extend_from_slice(&[9_u8; 64]);
    let (decision, answer) = upload(&mut onboarding, &mut sink, 16, &[&delivery]);
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::UploadOverran,
            status: Status::BadRequest,
            ..
        }
    ));
    assert_eq!(sink.installs, 0);
    assert_eq!(status_line(&answer), "HTTP/1.1 400 Bad Request");
}

/// The same, delivered a segment at a time: the overrun is refused on the
/// segment that goes past rather than after the whole of it is taken.
#[test]
fn an_overrun_in_a_later_segment_is_refused_when_it_arrives() {
    let mut onboarding = surface();
    let mut sink = Sink::default();
    let (decision, _) = upload(
        &mut onboarding,
        &mut sink,
        4,
        &[&upload_head(4), &[1, 2], &[3, 4, 5]],
    );
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::UploadOverran,
            ..
        }
    ));
    // The two bytes that were inside the declared length were handed on; the
    // segment that went past was not handed on at all.
    assert_eq!(sink.body, vec![1, 2]);
}

/// An appliance with nowhere to put a package refuses before it takes a byte, so
/// it never begins an upload it cannot finish.
#[test]
fn an_upload_with_nowhere_to_go_is_refused_before_a_byte_is_taken() {
    let mut onboarding = surface();
    let mut sink = Sink::refusing_to_open();
    let mut delivery = upload_head(32);
    delivery.extend_from_slice(&[3_u8; 32]);
    let (decision, answer) = upload(&mut onboarding, &mut sink, 32, &[&delivery]);
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::UploadUnavailable,
            status: Status::ServiceUnavailable,
            ..
        }
    ));
    assert!(sink.body.is_empty());
    assert_eq!(sink.installs, 0);
    assert_eq!(status_line(&answer), "HTTP/1.1 503 Service Unavailable");
}

/// A caller that keeps fewer bytes than it was offered. Unreachable while a
/// declared length is held to what was reserved, and answered by name rather
/// than asserted, because nothing on a path a peer paces may fault.
#[test]
fn bytes_that_would_not_all_go_where_they_were_meant_to_are_refused_by_name() {
    let mut onboarding = surface();
    let mut sink = Sink::keeping(4);
    let mut delivery = upload_head(32);
    delivery.extend_from_slice(&[5_u8; 32]);
    let (decision, answer) = upload(&mut onboarding, &mut sink, 32, &[&delivery]);
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::UploadUnstaged,
            status: Status::ServiceUnavailable,
            ..
        }
    ));
    assert_eq!(sink.installs, 0);
    assert_eq!(status_line(&answer), "HTTP/1.1 503 Service Unavailable");
}

/// A package the domain that holds the key would not install. The surface says
/// only that it got that far and was judged; which rule refused it is that
/// domain's own record.
#[test]
fn a_package_the_key_holder_refuses_is_named_here_and_reasoned_about_there() {
    let mut onboarding = surface();
    let mut sink = Sink::refusing_to_install();
    let mut delivery = upload_head(64);
    delivery.extend_from_slice(&[2_u8; 64]);
    let (decision, answer) = upload(&mut onboarding, &mut sink, 64, &[&delivery]);
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::PackageRefused,
            status: Status::BadRequest,
            ..
        }
    ));
    assert_eq!(sink.installs, 1);
    assert_eq!(status_line(&answer), "HTTP/1.1 400 Bad Request");
    // Refused, so the surface is not shut: an administrator corrects the package
    // and uploads again.
    assert!(!onboarding.closed());
}

/// A declared length past the widest package this appliance looks at is refused
/// at the head, so no byte of the body is accumulated on the way to finding out.
#[test]
fn a_declared_length_past_the_archive_bound_is_refused_at_the_head() {
    let mut onboarding = surface();
    let mut sink = Sink::default();
    let (decision, answer) = upload(
        &mut onboarding,
        &mut sink,
        0,
        &[&upload_head(MAX_UPLOAD_LEN + 1)],
    );
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::BodyTooLarge,
            status: Status::ContentTooLarge,
            ..
        }
    ));
    assert!(sink.opened.is_empty());
    assert_eq!(status_line(&answer), "HTTP/1.1 413 Content Too Large");
}

/// An appliance that has just been given an owner serves no onboarding, and it
/// does not wait for a new connection to stop: the close is the same statement
/// whether it is made by an install or by a record read at boot.
#[test]
fn an_installed_package_shuts_the_surface_for_every_route_and_for_good() {
    let mut onboarding = surface();
    let mut sink = Sink::default();
    let mut delivery = upload_head(16);
    delivery.extend_from_slice(&[4_u8; 16]);
    let (decision, _) = upload(&mut onboarding, &mut sink, 16, &[&delivery]);
    assert_eq!(decision, Decision::Installed { bytes: 16 });
    assert!(onboarding.closed());

    for target in ["/", "/certificate.csr", "/configuration.tar"] {
        let (decision, answer) = request(&mut onboarding, at(0), &get(target));
        assert!(
            matches!(
                decision,
                Decision::Refused {
                    refusal: OnboardRefusal::AlreadyOwned,
                    status: Status::Gone,
                    ..
                }
            ),
            "{target}"
        );
        assert_eq!(status_line(&answer), "HTTP/1.1 410 Gone", "{target}");
    }
}

/// The durable half of that close: an appliance whose record already names an
/// owner is constructed shut, so a reboot does not reopen onboarding.
#[test]
fn an_appliance_that_boots_owned_serves_nothing_at_all() {
    let mut onboarding = Onboarding::new(Some(identity()), true);
    assert!(onboarding.closed());
    for target in ["/", "/certificate.csr", "/configuration.tar"] {
        let (decision, answer) = request(&mut onboarding, at(0), &get(target));
        assert!(
            matches!(
                decision,
                Decision::Refused {
                    refusal: OnboardRefusal::AlreadyOwned,
                    status: Status::Gone,
                    ..
                }
            ),
            "{target}"
        );
        assert_eq!(status_line(&answer), "HTTP/1.1 410 Gone", "{target}");
    }
}

/// The close outranks a missing identity and is decided before the route, so an
/// owned appliance answers one way whatever it is asked and whatever state its
/// cryptography reached.
#[test]
fn a_closed_surface_answers_the_same_way_for_an_address_it_never_had() {
    let mut onboarding = Onboarding::new(None, true);
    let (decision, _) = request(&mut onboarding, at(0), &get("/nope"));
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::AlreadyOwned,
            ..
        }
    ));
}

/// The limiter still runs first, so a closed appliance costs a peer the same
/// allowance every other refusal does rather than being a free surface to hammer.
#[test]
fn the_limiter_runs_before_the_close_is_looked_at() {
    let mut onboarding = Onboarding::new(Some(identity()), true);
    for _ in 0..BURST {
        let (decision, _) = request(&mut onboarding, at(0), &get("/"));
        assert!(matches!(
            decision,
            Decision::Refused {
                refusal: OnboardRefusal::AlreadyOwned,
                ..
            }
        ));
    }
    let (decision, _) = request(&mut onboarding, at(0), &get("/"));
    assert!(matches!(
        decision,
        Decision::Refused {
            refusal: OnboardRefusal::RateLimited,
            ..
        }
    ));
}

/// An installed package owes the console one record naming what it was, and no
/// resource is named: nothing was served.
#[test]
fn an_install_reports_its_length_and_names_no_resource() {
    let records = Decision::Installed { bytes: 4096 }.records();
    assert_eq!(
        records,
        [
            Some(DomainDetail::OnboardingInstalled { bytes: 4096 }),
            None
        ]
    );
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
        let mut onboarding = Onboarding::new(Some(identity()), false);
        onboarding.opened();
        let now = if clocked { at(millis) } else { None };
        for piece in &pieces {
            let decision = onboarding.take(now, piece, &mut NoUpload);
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
