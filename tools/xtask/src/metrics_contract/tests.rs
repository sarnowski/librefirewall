use super::*;

/// An exposition of the shape the appliance renders, built here so a test can
/// bend one field at a time. Every domain and every required family appears, so
/// the base case passes and each mutation below fails for exactly one reason.
fn body(forwarded: (u64, u64), transmitted: (u64, u64)) -> String {
    let mut text = String::new();
    fn family(text: &mut String, name: &str, kind: &str, help: &str) {
        text.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
    }
    family(
        &mut text,
        "librefirewall_forwarded_frames_total",
        "counter",
        "Frames forwarded.",
    );
    text.push_str(&format!(
        "librefirewall_forwarded_frames_total{{domain=\"forwarder\",pipeline=\"0\"}} {}\n",
        forwarded.0
    ));
    text.push_str(&format!(
        "librefirewall_forwarded_frames_total{{domain=\"forwarder\",pipeline=\"1\"}} {}\n",
        forwarded.1
    ));
    family(
        &mut text,
        "librefirewall_route_drops_total",
        "counter",
        "Drops.",
    );
    text.push_str(
        "librefirewall_route_drops_total{domain=\"forwarder\",pipeline=\"0\",reason=\"no_route\"} 0\n",
    );
    family(
        &mut text,
        "librefirewall_transmit_frames_total",
        "counter",
        "Sent.",
    );
    text.push_str(&format!(
        "librefirewall_transmit_frames_total{{domain=\"nic_driver0\"}} {}\n",
        transmitted.0
    ));
    text.push_str(&format!(
        "librefirewall_transmit_frames_total{{domain=\"nic_driver1\"}} {}\n",
        transmitted.1
    ));
    text.push_str("librefirewall_transmit_frames_total{domain=\"nic_driver2\"} 3\n");
    for (name, help) in [
        ("librefirewall_receive_frames_total", "Received."),
        ("librefirewall_input_drops_total", "Input drops."),
        ("librefirewall_invariant_faults_total", "Ours."),
        ("librefirewall_device_faults_total", "Theirs."),
        ("librefirewall_pool_returns_refused_total", "Returns."),
    ] {
        family(&mut text, name, "counter", help);
        for domain in ["nic_driver0", "nic_driver1", "nic_driver2"] {
            text.push_str(&format!("{name}{{domain=\"{domain}\"}} 0\n"));
        }
    }
    for (name, help) in [
        ("librefirewall_endpoint_frames_total", "Frames."),
        ("librefirewall_endpoint_replies_total", "Replies."),
        ("librefirewall_tcp_refused_total", "Refused."),
    ] {
        family(&mut text, name, "counter", help);
        text.push_str(&format!("{name}{{domain=\"management\"}} 1\n"));
    }
    family(
        &mut text,
        "librefirewall_tcp_segments_total",
        "counter",
        "Segments.",
    );
    for direction in ["received", "sent"] {
        text.push_str(&format!(
            "librefirewall_tcp_segments_total{{domain=\"management\",direction=\"{direction}\"}} 1\n"
        ));
    }
    family(
        &mut text,
        "librefirewall_http_requests_total",
        "counter",
        "Requests.",
    );
    text.push_str("librefirewall_http_requests_total{domain=\"management\"} 1\n");
    family(
        &mut text,
        "librefirewall_http_responses_total",
        "counter",
        "Responses.",
    );
    text.push_str("librefirewall_http_responses_total{domain=\"management\",status=\"200\"} 1\n");
    text.push_str("librefirewall_http_responses_total{domain=\"management\",status=\"404\"} 0\n");
    text.push_str("librefirewall_http_responses_total{domain=\"management\",status=\"503\"} 0\n");
    family(
        &mut text,
        "librefirewall_http_response_bytes_total",
        "counter",
        "Bytes.",
    );
    text.push_str("librefirewall_http_response_bytes_total{domain=\"management\"} 25000\n");
    family(
        &mut text,
        "librefirewall_console_records_total",
        "counter",
        "Records.",
    );
    text.push_str(
        "librefirewall_console_records_total{domain=\"console\",outcome=\"printed\"} 9\n",
    );
    family(
        &mut text,
        "librefirewall_uart_bytes_written_total",
        "counter",
        "Bytes.",
    );
    text.push_str("librefirewall_uart_bytes_written_total{domain=\"console\"} 900\n");
    family(
        &mut text,
        "librefirewall_configuration_generation",
        "gauge",
        "Generation.",
    );
    text.push_str("librefirewall_configuration_generation{domain=\"config\"} 1\n");
    family(
        &mut text,
        "librefirewall_clock_frequency_hertz",
        "gauge",
        "Hertz.",
    );
    text.push_str("librefirewall_clock_frequency_hertz{domain=\"clock\"} 1000000000\n");
    family(
        &mut text,
        "librefirewall_log_records_dropped_total",
        "counter",
        "Lost.",
    );
    for domain in [
        "forwarder",
        "nic_driver0",
        "nic_driver1",
        "nic_driver2",
        "management",
        "console",
        "config",
        "clock",
    ] {
        text.push_str(&format!(
            "librefirewall_log_records_dropped_total{{domain=\"{domain}\"}} 0\n"
        ));
    }
    text
}

fn scrape_of(body: String) -> Scrape {
    Scrape {
        command: "curl --silent http://127.0.0.1:1/metrics".to_owned(),
        status_line: "HTTP/1.1 200 OK".to_owned(),
        headers: vec![
            format!("Content-Type: {METRICS_CONTENT_TYPE}"),
            format!("Content-Length: {}", body.len()),
            "Connection: close".to_owned(),
        ],
        body,
    }
}

fn healthy() -> Scrape {
    scrape_of(body((5, 4), (4, 5)))
}

/// The pair the contract is stated over. The scenario takes two scrapes because
/// one cannot contain the response it is; `second` therefore carries the
/// first's request and its 200.
fn pair() -> Vec<Scrape> {
    vec![healthy(), scrape_of(second(body((5, 4), (4, 5))))]
}

/// A first scrape's body, bent into what the endpoint reports on the second:
/// two requests seen, one 200 already sent.
fn second(text: String) -> String {
    text.replace(
        "librefirewall_http_requests_total{domain=\"management\"} 1",
        "librefirewall_http_requests_total{domain=\"management\"} 2",
    )
}

/// One scrape where the base case needs only one to be judged, paired with a
/// well-formed second so the pair itself is not what fails.
fn only(text: String) -> Vec<Scrape> {
    vec![scrape_of(text), scrape_of(second(body((5, 4), (4, 5))))]
}

#[test]
fn a_well_formed_scrape_that_agrees_with_the_wire_is_accepted() {
    let judged = judge(&pair(), 9).expect("the contract is met");
    assert!(
        judged.contains("9 forwarded frames reported and 9 observed"),
        "{judged}"
    );
    // The evidence carries the command and the asserted lines verbatim.
    let evidence = evidence(&pair(), &judged);
    assert!(evidence.contains("$ curl --silent"), "{evidence}");
    assert!(evidence.contains("HTTP/1.1 200 OK"), "{evidence}");
    assert!(evidence.contains(METRICS_CONTENT_TYPE), "{evidence}");
    assert!(
        evidence.contains(
            "librefirewall_forwarded_frames_total{domain=\"forwarder\",pipeline=\"0\"} 5"
        ),
        "{evidence}"
    );
}

/// The whole point of the scenario: a number that disagrees with the wire is a
/// failure however well formed the document is.
#[test]
fn a_forwarded_count_that_disagrees_with_the_wire_is_refused() {
    let verdict = judge(&pair(), 8).expect_err("nine reported against eight observed");
    assert!(verdict.contains("reports 9 forwarded frames"), "{verdict}");
    assert!(verdict.contains("observed 8"), "{verdict}");
    assert!(verdict.contains("pipeline=\"0\""), "{verdict}");
}

/// Two zeroes agree, and prove nothing.
#[test]
fn a_boot_that_forwarded_nothing_is_refused_rather_than_trivially_satisfied() {
    let verdict = judge(&only(body((0, 0), (0, 0))), 0).expect_err("nothing moved");
    assert!(verdict.contains("compared two zeroes"), "{verdict}");
}

/// A node that summed its own pipelines would publish one series, which is the
/// shape MONITORING.md's no-total rule refuses.
#[test]
fn a_pre_summed_forwarded_total_is_refused() {
    let mut text = body((9, 0), (4, 5));
    text = text.replace(
        "librefirewall_forwarded_frames_total{domain=\"forwarder\",pipeline=\"1\"} 0\n",
        "",
    );
    let verdict = judge(&only(text), 9).expect_err("one series where there are two pipelines");
    assert!(verdict.contains("no-total rule"), "{verdict}");
}

/// The drivers count the same frames one hop later, so a disagreement between
/// the forwarder and its two drivers is its own finding.
#[test]
fn drivers_that_disagree_with_the_forwarder_are_refused() {
    let verdict = judge(&only(body((5, 4), (4, 4))), 9).expect_err("a driver short");
    assert!(verdict.contains("8 transmitted frames"), "{verdict}");
}

#[test]
fn every_header_field_of_the_contract_is_compared() {
    let mut wrong_type = healthy();
    wrong_type.headers[0] = "Content-Type: text/html".to_owned();
    assert!(
        judge(&[wrong_type, scrape_of(second(body((5, 4), (4, 5))))], 9)
            .expect_err("a wrong type")
            .contains("text/html")
    );

    let mut wrong_length = healthy();
    wrong_length.headers[1] = "Content-Length: 3".to_owned();
    assert!(
        judge(&[wrong_length, scrape_of(second(body((5, 4), (4, 5))))], 9)
            .expect_err("a wrong length")
            .contains("Content-Length of 3")
    );

    let mut keep_alive = healthy();
    keep_alive.headers[2] = "Connection: keep-alive".to_owned();
    assert!(
        judge(&[keep_alive, scrape_of(second(body((5, 4), (4, 5))))], 9)
            .expect_err("keep-alive")
            .contains("keep-alive")
    );

    let mut refused = healthy();
    refused.status_line = "HTTP/1.1 503 Service Unavailable".to_owned();
    assert!(
        judge(&[refused, scrape_of(second(body((5, 4), (4, 5))))], 9)
            .expect_err("a refusal")
            .contains("503")
    );
}

#[test]
fn a_missing_family_names_the_subsystem_that_is_not_reaching_the_endpoint() {
    let text = body((5, 4), (4, 5)).replace(
        "# HELP librefirewall_uart_bytes_written_total Bytes.\n# TYPE librefirewall_uart_bytes_written_total counter\n",
        "",
    );
    let verdict = judge(&only(text), 9).expect_err("no UART family");
    assert!(
        verdict.contains("librefirewall_uart_bytes_written_total"),
        "{verdict}"
    );
}

#[test]
fn a_shard_that_is_not_published_is_named_by_its_domain() {
    let text = body((5, 4), (4, 5)).replace("domain=\"clock\"", "domain=\"forwarder\"");
    let verdict = judge(&only(text), 9).expect_err("no clock shard");
    assert!(verdict.contains("domain=\"clock\""), "{verdict}");
}

/// The parser is the assertion: a body that is not exposition fails as
/// malformed rather than as a missing name.
#[test]
fn a_body_that_is_not_exposition_is_refused_by_the_parser() {
    let cases: &[(&str, &str)] = &[
        ("not a metric at all\n", "no counter value"),
        ("# TYPE x counter\n", "no HELP line"),
        ("# HELP x h\n# TYPE x histogram\n", "type \"histogram\""),
        ("# HELP x h\n# TYPE x counter\nx{a=1} 2\n", "unquoted value"),
        (
            "# HELP x h\n# TYPE x counter\nx{a=\"1\" 2\n",
            "unterminated",
        ),
        (
            "# HELP x h\n# TYPE x counter\nx{a=\"1\",a=\"2\"} 3\n",
            "appears twice",
        ),
        ("# HELP x h\n# HELP x h\n", "declared twice"),
        ("#nonsense\n", "unexpected comment"),
        ("", "no sample at all"),
    ];
    for (text, expected) in cases {
        let verdict = judge(&only((*text).to_owned()), 1)
            .expect_err(&format!("{text:?} is not an exposition"));
        assert!(verdict.contains(expected), "{text:?}: {verdict}");
    }
}

/// A label set is read as a set: the renderer's order is not part of the
/// contract, and a test that depended on it would break on a reordering that
/// changed nothing an operator sees.
#[test]
fn label_order_is_not_part_of_the_contract() {
    let text = body((5, 4), (4, 5)).replace(
        "librefirewall_forwarded_frames_total{domain=\"forwarder\",pipeline=\"0\"} 5",
        "librefirewall_forwarded_frames_total{pipeline=\"0\",domain=\"forwarder\"} 5",
    );
    judge(&only(text), 9).expect("the same series, written the other way round");
}

/// The endpoint's own account of the request that just crossed it. A request is
/// counted as its head completes, before the shard the body is rendered from is
/// published, so every scrape carries at least its own.
#[test]
fn an_endpoint_that_reports_no_request_it_just_answered_is_refused() {
    let text = body((5, 4), (4, 5)).replace(
        "librefirewall_http_requests_total{domain=\"management\"} 1",
        "librefirewall_http_requests_total{domain=\"management\"} 0",
    );
    let verdict = judge(&only(text), 9).expect_err("no request counted");
    assert!(verdict.contains("no HTTP request"), "{verdict}");
}

/// What the second scrape is *for*: the counters advanced between the two,
/// rather than merely being present in both.
#[test]
fn a_second_scrape_that_does_not_report_the_first_is_refused() {
    // The request the first scrape made is not in the second's account.
    let stuck = vec![healthy(), healthy()];
    let verdict = judge(&stuck, 9).expect_err("one request reported after two were made");
    assert!(verdict.contains("reports 1 HTTP requests"), "{verdict}");

    // The 200 the first scrape was answered with is not in the second's.
    let text = second(body((5, 4), (4, 5))).replace(
        "librefirewall_http_responses_total{domain=\"management\",status=\"200\"} 1",
        "librefirewall_http_responses_total{domain=\"management\",status=\"200\"} 0",
    );
    let verdict =
        judge(&[healthy(), scrape_of(text)], 9).expect_err("no 200 counted after one was sent");
    assert!(verdict.contains("no 200 response"), "{verdict}");

    // Nor are the bytes it carried.
    let text = second(body((5, 4), (4, 5))).replace(
        "librefirewall_http_response_bytes_total{domain=\"management\"} 25000",
        "librefirewall_http_response_bytes_total{domain=\"management\"} 1",
    );
    let verdict = judge(&[healthy(), scrape_of(text)], 9).expect_err("a response of one byte");
    assert!(verdict.contains("response bytes"), "{verdict}");
}

/// The one staging buffer is released when the response can no longer be asked
/// for again. A node that instead held it through the first connection's
/// `TIME_WAIT` would refuse the second scrape, and a `503` in the account is how
/// that shows up even when both scrapes happened to be answered.
#[test]
fn a_node_that_refused_a_scrape_for_want_of_its_staging_buffer_is_refused() {
    let text = second(body((5, 4), (4, 5))).replace(
        "librefirewall_http_responses_total{domain=\"management\",status=\"503\"} 0",
        "librefirewall_http_responses_total{domain=\"management\",status=\"503\"} 1",
    );
    let verdict = judge(&[healthy(), scrape_of(text)], 9).expect_err("a refused scrape");
    assert!(verdict.contains("staging buffer"), "{verdict}");
}

/// The contract is stated over two scrapes, so a scenario that took some other
/// number says so rather than judging whichever one it has.
#[test]
fn a_run_that_did_not_take_two_scrapes_is_refused() {
    let verdict = judge(&[healthy()], 9).expect_err("one scrape");
    assert!(verdict.contains("took 1 scrapes"), "{verdict}");
    let verdict = judge(&[], 9).expect_err("no scrape");
    assert!(verdict.contains("took 0 scrapes"), "{verdict}");
}

/// The transport under the endpoint is counting too, and a scrape that crossed
/// it reporting no received segment means the shard is stale rather than the
/// wire quiet.
#[test]
fn a_transport_that_reports_no_segment_it_just_carried_is_refused() {
    let text = body((5, 4), (4, 5)).replace(
        "librefirewall_tcp_segments_total{domain=\"management\",direction=\"received\"} 1",
        "librefirewall_tcp_segments_total{domain=\"management\",direction=\"received\"} 0",
    );
    let verdict = judge(&only(text), 9).expect_err("no segment counted");
    assert!(verdict.contains("no segment received"), "{verdict}");
}
