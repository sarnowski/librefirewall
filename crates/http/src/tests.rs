use proptest::prelude::*;

use super::*;
use crate::response::HeadDoesNotFit;

fn complete(bytes: &[u8]) -> (Request<'_>, usize) {
    match parse(bytes).expect("a well-formed head") {
        Parsed::Complete { request, consumed } => (request, consumed),
        Parsed::NeedMore => panic!("the head is whole"),
    }
}

const SCRAPE: &[u8] = b"GET /metrics HTTP/1.1\r\nHost: 10.0.2.15\r\nUser-Agent: curl/8.14.1\r\n\
                        Accept: */*\r\n\r\n";

#[test]
fn a_scrape_parses_into_its_fields() {
    let (request, consumed) = complete(SCRAPE);
    assert_eq!(consumed, SCRAPE.len());
    assert_eq!(request.method(), "GET");
    assert!(request.is_get());
    assert_eq!(request.target(), "/metrics");
    assert_eq!(request.headers().count(), 3);
    assert_eq!(request.header("host"), Some("10.0.2.15"));
    assert_eq!(request.header("HOST"), Some("10.0.2.15"));
    assert_eq!(request.header("accept"), Some("*/*"));
    assert_eq!(request.header("cookie"), None);
}

/// The property the whole incremental design exists for: a head split anywhere
/// parses to the same thing as the same head arriving whole.
#[test]
fn a_head_split_at_every_offset_parses_identically() {
    for split in 0..=SCRAPE.len() {
        let head = &SCRAPE[..split];
        match parse(head) {
            Ok(Parsed::NeedMore) => assert!(split < SCRAPE.len()),
            Ok(Parsed::Complete { request, consumed }) => {
                assert_eq!(split, SCRAPE.len());
                assert_eq!(consumed, SCRAPE.len());
                assert_eq!(request.target(), "/metrics");
            }
            Err(error) => panic!("prefix of {split} bytes refused: {error:?}"),
        }
    }
}

/// A second request behind the first is left alone: `consumed` is the caller's
/// only way to know where one head ended, and this server closes rather than
/// reading a second — but the number must still be right.
#[test]
fn trailing_bytes_are_not_consumed() {
    let mut buffer = SCRAPE.to_vec();
    buffer.extend_from_slice(b"GET /again HTTP/1.1\r\n\r\n");
    let (request, consumed) = complete(&buffer);
    assert_eq!(consumed, SCRAPE.len());
    assert_eq!(request.target(), "/metrics");
}

#[test]
fn a_head_with_no_headers_at_all_is_well_formed() {
    let (request, consumed) = complete(b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(consumed, 18);
    assert_eq!(request.target(), "/");
    assert_eq!(request.headers().count(), 0);
}

#[test]
fn a_bare_line_feed_is_refused_at_the_first_line_ending() {
    for head in [
        &b"GET / HTTP/1.1\n\n"[..],
        &b"GET / HTTP/1.1\r\nHost: x\n\r\n"[..],
        &b"\n"[..],
    ] {
        assert_eq!(parse(head), Err(RequestError::BareLineFeed), "{head:?}");
    }
}

/// A CR at the very end is the first half of a terminator still on the wire, and
/// must not be mistaken for a stray one.
#[test]
fn a_trailing_carriage_return_is_incomplete_rather_than_malformed() {
    assert!(matches!(
        parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r"),
        Ok(Parsed::NeedMore)
    ));
    assert_eq!(
        parse(b"GET / HTTP/1.1\r\nHost:\rx\r\n\r\n"),
        Err(RequestError::StrayCarriageReturn)
    );
}

#[test]
fn every_refusal_names_the_status_the_client_is_owed() {
    let cases: &[(&[u8], RequestError, Status)] = &[
        (
            b"GET /a b HTTP/1.1\r\n\r\n",
            RequestError::MalformedRequestLine,
            Status::BadRequest,
        ),
        (
            b"GET /metrics\r\n\r\n",
            RequestError::MalformedRequestLine,
            Status::BadRequest,
        ),
        (
            b"GE(T) / HTTP/1.1\r\n\r\n",
            RequestError::MalformedMethod,
            Status::BadRequest,
        ),
        (
            b"GET  HTTP/1.1\r\n\r\n",
            RequestError::MalformedTarget,
            Status::BadRequest,
        ),
        (
            b"GET / HTTP/1.0\r\n\r\n",
            RequestError::UnsupportedVersion,
            Status::VersionNotSupported,
        ),
        (
            b"GET / HTTP/2.0\r\n\r\n",
            RequestError::UnsupportedVersion,
            Status::VersionNotSupported,
        ),
        (
            b"GET / HTTP/one.one\r\n\r\n",
            RequestError::MalformedVersion,
            Status::BadRequest,
        ),
        (
            b"GET / RTSP/1.1\r\n\r\n",
            RequestError::MalformedVersion,
            Status::BadRequest,
        ),
        (
            b"GET / HTTP/1.1\r\nHost x\r\n\r\n",
            RequestError::MalformedHeaderName,
            Status::HeadersTooLarge,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: a\r\n b\r\n\r\n",
            RequestError::ObsoleteLineFolding,
            Status::BadRequest,
        ),
        (
            b"GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
            RequestError::BodyNotAccepted,
            Status::BadRequest,
        ),
        (
            b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            RequestError::BodyNotAccepted,
            Status::BadRequest,
        ),
    ];
    for (head, expected, status) in cases {
        let error = parse(head).expect_err(&format!("{head:?} is refused"));
        assert_eq!(error, *expected, "{head:?}");
        assert_eq!(error.status(), *status, "{head:?}");
    }
}

/// `Content-Length: 0` announces no body, so it is not a smuggling risk and is
/// accepted — a scraper behind a proxy may add one.
#[test]
fn a_zero_content_length_is_accepted() {
    let (request, _) = complete(b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(request.header("content-length"), Some("0"));
}

/// Every bound is enforced at its own edge: one byte under passes, one byte over
/// is refused by the variant that names it.
#[test]
fn each_bound_is_enforced_exactly_at_its_edge() {
    let target = |len: usize| {
        let mut head = b"GET /".to_vec();
        head.extend(core::iter::repeat_n(b'a', len - 1));
        head.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        head
    };
    assert!(parse(&target(MAX_TARGET_LEN)).is_ok());
    assert_eq!(
        parse(&target(MAX_TARGET_LEN + 1)),
        Err(RequestError::TargetTooLong)
    );
    assert_eq!(
        RequestError::TargetTooLong.status(),
        Status::UriTooLong,
        "an over-long target is 414 rather than 431"
    );

    let method = |len: usize| {
        let mut head = core::iter::repeat_n(b'A', len).collect::<Vec<u8>>();
        head.extend_from_slice(b" / HTTP/1.1\r\n\r\n");
        head
    };
    assert!(parse(&method(MAX_METHOD_LEN)).is_ok());
    assert_eq!(
        parse(&method(MAX_METHOD_LEN + 1)),
        Err(RequestError::MalformedMethod)
    );

    let headers = |count: usize| {
        let mut head = b"GET / HTTP/1.1\r\n".to_vec();
        for index in 0..count {
            head.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        head
    };
    assert_eq!(
        complete(&headers(MAX_HEADERS)).0.headers().count(),
        MAX_HEADERS
    );
    assert_eq!(
        parse(&headers(MAX_HEADERS + 1)),
        Err(RequestError::TooManyHeaders)
    );

    // The field past the bound is counted before it is read, so the answer is
    // the bound's — 431 — whatever is wrong with it. A parser that read it first
    // would answer 400 and tell a client to fix a syntax error when what it must
    // do is send fewer fields.
    let mut over = headers(MAX_HEADERS);
    over.truncate(over.len() - 2);
    over.extend_from_slice(b"not a header at all\r\n\r\n");
    assert_eq!(parse(&over), Err(RequestError::TooManyHeaders));
    assert_eq!(
        RequestError::TooManyHeaders.status(),
        Status::HeadersTooLarge
    );

    let name = |len: usize| {
        let mut head = b"GET / HTTP/1.1\r\n".to_vec();
        head.extend(core::iter::repeat_n(b'x', len));
        head.extend_from_slice(b": v\r\n\r\n");
        head
    };
    assert!(parse(&name(MAX_HEADER_NAME_LEN)).is_ok());
    assert_eq!(
        parse(&name(MAX_HEADER_NAME_LEN + 1)),
        Err(RequestError::MalformedHeaderName)
    );

    let value = |len: usize| {
        let mut head = b"GET / HTTP/1.1\r\nX: ".to_vec();
        head.extend(core::iter::repeat_n(b'v', len));
        head.extend_from_slice(b"\r\n\r\n");
        head
    };
    assert!(parse(&value(MAX_HEADER_VALUE_LEN)).is_ok());
    assert_eq!(
        parse(&value(MAX_HEADER_VALUE_LEN + 1)),
        Err(RequestError::MalformedHeaderValue)
    );
}

/// A method other than GET parses: this crate reads a request and the server
/// above decides that 405 is the answer. A parser that refused here could never
/// serve the proxy the crate header is designed for.
#[test]
fn a_method_this_server_does_not_answer_still_parses() {
    for method in ["POST", "DELETE", "PUT", "OPTIONS", "get"] {
        let head = format!("{method} /metrics HTTP/1.1\r\n\r\n");
        let (request, _) = complete(head.as_bytes());
        assert_eq!(request.method(), method);
        assert_eq!(request.is_get(), method == "GET");
    }
}

#[test]
fn a_head_is_read_as_ascii_and_arbitrary_bytes_are_refused() {
    let head = b"GET /\xff\xfe HTTP/1.1\r\n\r\n";
    // The target check catches it before UTF-8 does, and either way it is a 400.
    assert_eq!(
        parse(head).expect_err("not ASCII").status(),
        Status::BadRequest
    );
}

// ── Responses ───────────────────────────────────────────────────────────────

fn head_to_string(status: Status, content_type: Option<ContentType>, length: u64) -> String {
    let mut out = [0u8; MAX_HEAD_LEN];
    let len = write_head(status, content_type, length, &mut out).expect("the declared bound fits");
    String::from_utf8(out[..len].to_vec()).expect("ASCII")
}

#[test]
fn a_metrics_head_carries_the_type_the_length_and_the_close() {
    let head = head_to_string(Status::Ok, Some(ContentType::Metrics), 20_480);
    assert_eq!(
        head,
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: 20480\r\n\
         Connection: close\r\n\r\n"
    );
}

#[test]
fn a_head_with_no_body_type_still_carries_a_length() {
    let head = head_to_string(Status::NotFound, None, 0);
    assert_eq!(
        head,
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

/// The bound is what lets a caller reserve room in front of a body and never be
/// refused: every status, with every content type the type admits and the
/// longest length, must fit it.
#[test]
fn the_declared_head_bound_holds_every_status() {
    for status in Status::ALL {
        for content_type in ContentType::ALL {
            let mut out = [0u8; MAX_HEAD_LEN];
            let len = write_head(status, Some(content_type), u64::MAX, &mut out)
                .expect("the bound holds every status");
            assert!(len <= MAX_HEAD_LEN);
            let text = core::str::from_utf8(&out[..len]).expect("ASCII");
            assert!(text.starts_with(&format!("HTTP/1.1 {} {}", status.code(), status.reason())));
            assert!(text.ends_with("\r\n\r\n"));
            assert!(text.contains(&format!("Content-Length: {}\r\n", u64::MAX)));
            assert!(text.contains(&format!("Content-Type: {}\r\n", content_type.as_str())));
        }
    }
}

/// The bound is derived from `Status::ALL` and the content types `ContentType`
/// admits, so it is held to the longest head those actually produce rather than
/// only to fitting one: a bound computed from a *different* string would agree
/// by luck.
#[test]
fn the_head_bound_is_the_longest_head_it_bounds() {
    let longest = Status::ALL
        .iter()
        .flat_map(|status| {
            ContentType::ALL
                .map(|content_type| head_to_string(*status, Some(content_type), u64::MAX).len())
        })
        .max()
        .expect("the table is not empty");
    assert_eq!(crate::response::head_bound(), MAX_HEAD_LEN);
    assert_eq!(MAX_HEAD_LEN, longest);
}

/// A header name that is not a token, and a value carrying a control byte:
/// two refusals a well-formed-looking line reaches, and the only two paths in
/// `parse_header` a length bound does not.
#[test]
fn a_header_name_or_value_that_is_not_one_is_refused() {
    assert_eq!(
        parse(b"GET / HTTP/1.1\r\n: v\r\n\r\n"),
        Err(RequestError::MalformedHeaderName)
    );
    assert_eq!(
        parse(b"GET / HTTP/1.1\r\nX(Y): v\r\n\r\n"),
        Err(RequestError::MalformedHeaderName)
    );
    assert_eq!(
        parse(b"GET / HTTP/1.1\r\nX: \x07\r\n\r\n"),
        Err(RequestError::MalformedHeaderValue)
    );
}

/// A version with no dot at all, which is neither a version this server speaks
/// nor one it can recognise.
#[test]
fn a_version_with_no_minor_number_is_malformed_rather_than_unsupported() {
    assert_eq!(
        parse(b"GET / HTTP/2\r\n\r\n"),
        Err(RequestError::MalformedVersion)
    );
}

#[test]
fn a_head_that_does_not_fit_is_refused_rather_than_truncated() {
    let mut out = [0u8; 8];
    assert_eq!(
        write_head(Status::Ok, None, 0, &mut out),
        Err(HeadDoesNotFit { capacity: 8 })
    );
}

#[test]
fn the_status_table_is_ordered_and_its_tokens_are_its_codes() {
    let mut codes: Vec<u16> = Status::ALL.iter().map(|status| status.code()).collect();
    let ordered = codes.clone();
    codes.sort_unstable();
    assert_eq!(codes, ordered, "ALL is ascending, so a slot is stable");
    for (slot, status) in Status::ALL.iter().enumerate() {
        assert_eq!(status.slot(), slot);
        assert_eq!(status.token(), status.code().to_string());
        assert!(!status.reason().is_empty());
    }
}

proptest! {
    /// Arbitrary bytes: `parse` answers, never panics, and never claims to have
    /// consumed more than it was given.
    #[test]
    fn parsing_is_total_over_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        match parse(&bytes) {
            Ok(Parsed::NeedMore) => {
                prop_assert!(find_terminator(&bytes).is_none() || has_bad_line_ending(&bytes));
            }
            Ok(Parsed::Complete { request, consumed }) => {
                prop_assert!(consumed <= bytes.len());
                prop_assert!(!request.method().is_empty());
                prop_assert!(request.method().len() <= MAX_METHOD_LEN);
                prop_assert!(!request.target().is_empty());
                prop_assert!(request.target().len() <= MAX_TARGET_LEN);
                prop_assert!(request.headers().count() <= MAX_HEADERS);
                for header in request.headers() {
                    prop_assert!(!header.name.is_empty());
                    prop_assert!(header.name.len() <= MAX_HEADER_NAME_LEN);
                    prop_assert!(header.value.len() <= MAX_HEADER_VALUE_LEN);
                }
            }
            Err(_) => {}
        }
    }

    /// Chunking is invisible: feeding a prefix can only answer `NeedMore` or the
    /// same verdict the whole buffer gives. A parser whose answer depended on
    /// where TCP happened to split would be one an attacker could steer.
    #[test]
    fn a_prefix_answers_need_more_or_the_same_verdict(
        bytes in prop::collection::vec(any::<u8>(), 0..300),
        split in 0usize..300,
    ) {
        let split = split.min(bytes.len());
        let whole = parse(&bytes).map(|parsed| match parsed {
            Parsed::NeedMore => None,
            Parsed::Complete { consumed, .. } => Some(consumed),
        });
        let prefix = parse(&bytes[..split]).map(|parsed| match parsed {
            Parsed::NeedMore => None,
            Parsed::Complete { consumed, .. } => Some(consumed),
        });
        match prefix {
            // A prefix that completed did so at or before the split, so the
            // whole buffer must complete at exactly the same place.
            Ok(Some(consumed)) => {
                prop_assert!(consumed <= split);
                prop_assert_eq!(whole, Ok(Some(consumed)));
            }
            // A prefix that refused found its fault inside the prefix, so the
            // whole buffer meets the same fault.
            Err(error) => prop_assert_eq!(whole, Err(error)),
            Ok(None) => {}
        }
    }

    /// Every head fits the bound and round-trips its own length, whatever the
    /// body length is.
    #[test]
    fn a_head_states_the_length_it_was_given(length in any::<u64>()) {
        for status in Status::ALL {
            let head = head_to_string(status, Some(ContentType::Metrics), length);
            let stated = format!("Content-Length: {length}\r\n");
            prop_assert!(head.contains(&stated));
            prop_assert!(head.contains("Connection: close\r\n"));
        }
    }
}

fn find_terminator(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn has_bad_line_ending(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
}

/// A complete head is read the same whatever follows it.
///
/// Found by `fuzz/src/http_request.rs`, which feeds one stream cut at arbitrary
/// points and holds the verdicts to agreeing: a prefix ending at the blank line
/// completed, and the same bytes with a malformed byte appended were refused
/// `BadRequest`. The line-ending scan ran over the whole buffer rather than
/// over the head, so what came *after* the terminator decided the verdict on
/// what came before it — a disagreement about where a message ends, which is
/// precisely the shape of request smuggling, and one an attacker steers by
/// appending.
#[test]
fn a_completed_head_is_read_the_same_whatever_follows_it() {
    let head = b"POST /metrics HTTP/1.1\r\n\r\n";
    let Ok(Parsed::Complete { consumed, .. }) = parse(head) else {
        panic!("a well-formed head completes");
    };
    assert_eq!(consumed, head.len());

    for trailing in [
        &b"\n"[..],
        b"\r",
        b" /mets\n\n",
        b"GET / HTTP/1.1\r\n\r\n",
        b"\x00\xff",
    ] {
        let mut stream = head.to_vec();
        stream.extend_from_slice(trailing);
        match parse(&stream) {
            Ok(Parsed::Complete {
                consumed: again, ..
            }) => assert_eq!(
                again, consumed,
                "the head ends where it ends, whatever follows: {trailing:?}"
            ),
            other => panic!("bytes past the head changed the verdict on it: {other:?}"),
        }
    }
}

/// And a malformed line ending *inside* an incomplete head is still refused,
/// which is the half of the scan the fix above must not have removed.
#[test]
fn a_bare_line_feed_inside_the_head_is_still_refused() {
    assert_eq!(parse(b"GET / HTTP/1.1\n"), Err(RequestError::BareLineFeed));
    assert_eq!(
        parse(b"GET / HTTP/1.1\r\nHost: a\nb: c\r\n\r\n"),
        Err(RequestError::BareLineFeed)
    );
}
