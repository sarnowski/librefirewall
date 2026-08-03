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
    // The two refusals the filter reaches, split per pipeline as the appliance
    // publishes them: the harness sums them itself, because the node computes no
    // total. Pipeline 1 carries none of either, so a reader that read one
    // pipeline instead of summing both would still agree here — which is why the
    // test that moves a count to the other pipeline exists.
    for (reason, counts) in [
        ("policy_denied", (DENIED_PROBES, 0)),
        ("no_policy_match", (UNMATCHED_PROBES, 0)),
    ] {
        text.push_str(&format!(
            "librefirewall_route_drops_total{{domain=\"forwarder\",pipeline=\"0\",\
             reason=\"{reason}\"}} {}\n",
            counts.0
        ));
        text.push_str(&format!(
            "librefirewall_route_drops_total{{domain=\"forwarder\",pipeline=\"1\",\
             reason=\"{reason}\"}} {}\n",
            counts.1
        ));
    }
    family(&mut text, RULE_HITS, "counter", "Hits.");
    // The shipped document's own rule ids, as the info block below carries its
    // own addressing: the base case must agree with the topology every test here
    // judges against. The accepting rule's counter is the forwarded total,
    // because every frame that left passed it.
    text.push_str(&format!(
        "{RULE_HITS}{{domain=\"forwarder\",rule=\"probe-blocked\"}} {DENIED_PROBES}\n"
    ));
    text.push_str(&format!(
        "{RULE_HITS}{{domain=\"forwarder\",rule=\"probe-forward\"}} {}\n",
        forwarded.0 + forwarded.1
    ));
    family(&mut text, POLICY_PACKETS, "counter", "Decided.");
    text.push_str(&format!(
        "{POLICY_PACKETS}{{domain=\"forwarder\",verdict=\"accepted\"}} {}\n",
        forwarded.0 + forwarded.1
    ));
    text.push_str(&format!(
        "{POLICY_PACKETS}{{domain=\"forwarder\",verdict=\"denied\"}} {}\n",
        DENIED_PROBES + UNMATCHED_PROBES
    ));
    family(
        &mut text,
        "librefirewall_policy_bytes_total",
        "counter",
        "Bytes decided.",
    );
    text.push_str(
        "librefirewall_policy_bytes_total{domain=\"forwarder\",verdict=\"accepted\"} 460\n",
    );
    text.push_str(
        "librefirewall_policy_bytes_total{domain=\"forwarder\",verdict=\"denied\"} 156\n",
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
        "librefirewall_block_capacity_sectors",
        "gauge",
        "Sectors.",
    );
    text.push_str("librefirewall_block_capacity_sectors{domain=\"recorder\"} 131072\n");
    family(&mut text, INTERFACE_INFO, "gauge", "Identity.");
    // The shipped document's own values, so the base case agrees with the
    // topology every test below judges against.
    for (domain, id, role, address, prefix, mac) in [
        (
            "nic_driver0",
            "dataplane-0",
            "dataplane",
            "10.0.0.1",
            24,
            "52:54:00:12:34:50",
        ),
        (
            "nic_driver1",
            "dataplane-1",
            "dataplane",
            "10.0.1.1",
            24,
            "52:54:00:12:34:51",
        ),
        (
            "nic_driver2",
            "management",
            "management",
            "10.0.2.15",
            24,
            "52:54:00:12:34:52",
        ),
    ] {
        text.push_str(&format!(
            "{INTERFACE_INFO}{{domain=\"{domain}\",interface=\"{id}\",role=\"{role}\",\
             address=\"{address}\",prefix_length=\"{prefix}\",mac=\"{mac}\"}} 1\n"
        ));
    }
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

/// Policy denials and default denies the fixture body reports, per pipeline. Two
/// and one rather than one and one, so a verdict that credited one refusal to the
/// other reads as a mismatch rather than as agreement.
const DENIED_PROBES: u64 = 2;
const UNMATCHED_PROBES: u64 = 1;

/// What the harness measured about the filter, with the rules read out of the
/// shipped document exactly as a scenario reads them. The filter probe set's
/// witness, so both of its refusal counters are obliged to have risen.
fn witness() -> PolicyWitness {
    PolicyWitness {
        policy: topology()
            .port_policy()
            .expect("the shipped document declares an accepting and a dropping port rule"),
        probed_the_denying_rule: true,
        probed_the_fallthrough: true,
    }
}

/// The routed probe set's witness, which obliges both refusal counters to still
/// read zero.
fn routed_witness() -> PolicyWitness {
    PolicyWitness {
        probed_the_denying_rule: false,
        probed_the_fallthrough: false,
        ..witness()
    }
}

/// The bench the shipped document describes, which is what the info series are
/// judged against. Read from the file rather than restated, exactly as the
/// scenario does.
fn topology() -> Topology {
    Topology::read(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../systems/qemu-x86_64/configuration.xml"
    )))
    .expect("the shipped document describes a bench")
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

/// Both scrapes of one body, for a case whose expectation is stated over the
/// whole pair rather than over one bent scrape: [`only`]'s second scrape is the
/// *unmutated* body, so a case that must hold for both cannot use it.
fn both(text: String) -> Vec<Scrape> {
    vec![scrape_of(text.clone()), scrape_of(second(text))]
}

#[test]
fn a_well_formed_scrape_that_agrees_with_the_wire_is_accepted() {
    let judged = judge(&pair(), 9, witness(), &topology()).expect("the contract is met");
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
    let verdict = judge(&pair(), 8, witness(), &topology())
        .expect_err("nine reported against eight observed");
    assert!(verdict.contains("reports 9 forwarded frames"), "{verdict}");
    assert!(verdict.contains("observed 8"), "{verdict}");
    assert!(verdict.contains("pipeline=\"0\""), "{verdict}");
}

/// Two zeroes agree, and prove nothing.
#[test]
fn a_boot_that_forwarded_nothing_is_refused_rather_than_trivially_satisfied() {
    let verdict =
        judge(&only(body((0, 0), (0, 0))), 0, witness(), &topology()).expect_err("nothing moved");
    assert!(verdict.contains("compared two zeroes"), "{verdict}");
}

/// A node that summed its own pipelines would publish one series, which is the
/// shape the no-total rule refuses: a domain restart would corrupt the sum.
#[test]
fn a_pre_summed_forwarded_total_is_refused() {
    let mut text = body((9, 0), (4, 5));
    text = text.replace(
        "librefirewall_forwarded_frames_total{domain=\"forwarder\",pipeline=\"1\"} 0\n",
        "",
    );
    let verdict = judge(&only(text), 9, witness(), &topology())
        .expect_err("one series where there are two pipelines");
    assert!(verdict.contains("no-total rule"), "{verdict}");
}

/// The drivers count the same frames one hop later, so a disagreement between
/// the forwarder and its two drivers is its own finding.
#[test]
fn drivers_that_disagree_with_the_forwarder_are_refused() {
    let verdict =
        judge(&only(body((5, 4), (4, 4))), 9, witness(), &topology()).expect_err("a driver short");
    assert!(verdict.contains("8 transmitted frames"), "{verdict}");
}

#[test]
fn every_header_field_of_the_contract_is_compared() {
    let mut wrong_type = healthy();
    wrong_type.headers[0] = "Content-Type: text/html".to_owned();
    assert!(
        judge(
            &[wrong_type, scrape_of(second(body((5, 4), (4, 5))))],
            9,
            witness(),
            &topology()
        )
        .expect_err("a wrong type")
        .contains("text/html")
    );

    let mut wrong_length = healthy();
    wrong_length.headers[1] = "Content-Length: 3".to_owned();
    assert!(
        judge(
            &[wrong_length, scrape_of(second(body((5, 4), (4, 5))))],
            9,
            witness(),
            &topology()
        )
        .expect_err("a wrong length")
        .contains("Content-Length of 3")
    );

    let mut keep_alive = healthy();
    keep_alive.headers[2] = "Connection: keep-alive".to_owned();
    assert!(
        judge(
            &[keep_alive, scrape_of(second(body((5, 4), (4, 5))))],
            9,
            witness(),
            &topology()
        )
        .expect_err("keep-alive")
        .contains("keep-alive")
    );

    let mut refused = healthy();
    refused.status_line = "HTTP/1.1 503 Service Unavailable".to_owned();
    assert!(
        judge(
            &[refused, scrape_of(second(body((5, 4), (4, 5))))],
            9,
            witness(),
            &topology()
        )
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
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("no UART family");
    assert!(
        verdict.contains("librefirewall_uart_bytes_written_total"),
        "{verdict}"
    );
}

#[test]
fn a_shard_that_is_not_published_is_named_by_its_domain() {
    let text = body((5, 4), (4, 5)).replace("domain=\"clock\"", "domain=\"forwarder\"");
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("no clock shard");
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
        let verdict = judge(&only((*text).to_owned()), 1, witness(), &topology())
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
    judge(&only(text), 9, witness(), &topology())
        .expect("the same series, written the other way round");
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
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("no request counted");
    assert!(verdict.contains("no HTTP request"), "{verdict}");
}

/// What the second scrape is *for*: the counters advanced between the two,
/// rather than merely being present in both.
#[test]
fn a_second_scrape_that_does_not_report_the_first_is_refused() {
    // The request the first scrape made is not in the second's account.
    let stuck = vec![healthy(), healthy()];
    let verdict = judge(&stuck, 9, witness(), &topology())
        .expect_err("one request reported after two were made");
    assert!(verdict.contains("reports 1 HTTP requests"), "{verdict}");

    // The 200 the first scrape was answered with is not in the second's.
    let text = second(body((5, 4), (4, 5))).replace(
        "librefirewall_http_responses_total{domain=\"management\",status=\"200\"} 1",
        "librefirewall_http_responses_total{domain=\"management\",status=\"200\"} 0",
    );
    let verdict = judge(&[healthy(), scrape_of(text)], 9, witness(), &topology())
        .expect_err("no 200 counted after one was sent");
    assert!(verdict.contains("no 200 response"), "{verdict}");

    // Nor are the bytes it carried.
    let text = second(body((5, 4), (4, 5))).replace(
        "librefirewall_http_response_bytes_total{domain=\"management\"} 25000",
        "librefirewall_http_response_bytes_total{domain=\"management\"} 1",
    );
    let verdict = judge(&[healthy(), scrape_of(text)], 9, witness(), &topology())
        .expect_err("a response of one byte");
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
    let verdict = judge(&[healthy(), scrape_of(text)], 9, witness(), &topology())
        .expect_err("a refused scrape");
    assert!(verdict.contains("staging buffer"), "{verdict}");
}

/// The contract is stated over two scrapes, so a scenario that took some other
/// number says so rather than judging whichever one it has.
#[test]
fn a_run_that_did_not_take_two_scrapes_is_refused() {
    let verdict = judge(&[healthy()], 9, witness(), &topology()).expect_err("one scrape");
    assert!(verdict.contains("took 1 scrapes"), "{verdict}");
    let verdict = judge(&[], 9, witness(), &topology()).expect_err("no scrape");
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
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("no segment counted");
    assert!(verdict.contains("no segment received"), "{verdict}");
}

/// The valuable half of the info family: every label value is compared against
/// the document, so a node reporting an address it is not running fails.
///
/// One test per label, because they fail for different reasons and a single
/// mutation would prove only that *something* is compared.
#[test]
fn an_info_label_that_disagrees_with_the_document_is_refused() {
    for (from, to, expected) in [
        (
            "interface=\"dataplane-0\"",
            "interface=\"wan\"",
            "interface",
        ),
        ("role=\"dataplane\"", "role=\"management\"", "role"),
        ("address=\"10.0.0.1\"", "address=\"10.9.9.9\"", "address"),
        (
            "prefix_length=\"24\"",
            "prefix_length=\"25\"",
            "prefix_length",
        ),
        (
            "mac=\"52:54:00:12:34:50\"",
            "mac=\"52:54:00:aa:bb:cc\"",
            "mac",
        ),
    ] {
        let text = body((5, 4), (4, 5)).replacen(from, to, 1);
        let verdict = judge(&only(text), 9, witness(), &topology())
            .expect_err("a label the document does not contain");
        assert!(
            verdict.contains(expected),
            "the verdict names the label that moved: {verdict}"
        );
        assert!(
            verdict.contains("configuration document"),
            "and says what it was compared against: {verdict}"
        );
    }
}

/// The join key. A series carrying the wrong `domain` is not a cosmetic error:
/// it points an interface's identity at another port's counters, so the query
/// answers with the wrong port rather than with nothing.
#[test]
fn an_info_series_under_the_wrong_domain_is_refused() {
    let text = body((5, 4), (4, 5)).replacen(
        &format!("{INTERFACE_INFO}{{domain=\"nic_driver1\""),
        &format!("{INTERFACE_INFO}{{domain=\"nic_driver0\""),
        1,
    );
    let verdict = judge(&only(text), 9, witness(), &topology())
        .expect_err("two series under one domain, one missing");
    assert!(verdict.contains(INTERFACE_INFO), "{verdict}");
}

/// One series per configured interface is the whole cardinality of the family,
/// so a missing one and a duplicated one are both findings.
#[test]
fn a_missing_or_duplicated_info_series_is_refused() {
    let full = body((5, 4), (4, 5));
    let management_line = full
        .lines()
        .find(|line| line.contains("interface=\"management\""))
        .expect("the base case carries it")
        .to_owned();

    let without = full.replacen(&format!("{management_line}\n"), "", 1);
    let verdict = judge(&only(without), 9, witness(), &topology()).expect_err("a port unreported");
    assert!(verdict.contains("cardinality of this family"), "{verdict}");

    let twice = full.replacen(
        &format!("{management_line}\n"),
        &format!("{management_line}\n{management_line}\n"),
        1,
    );
    let verdict =
        judge(&only(twice), 9, witness(), &topology()).expect_err("a port reported twice");
    assert!(verdict.contains("reported twice"), "{verdict}");
}

/// An extra label is an extra dimension nothing in the metric inventory
/// names, and metric cardinality must stay bounded.
#[test]
fn an_info_series_carrying_a_label_the_contract_does_not_name_is_refused() {
    let text = body((5, 4), (4, 5)).replacen(
        "interface=\"dataplane-0\"",
        "interface=\"dataplane-0\",enabled=\"true\"",
        1,
    );
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("an undeclared label");
    assert!(verdict.contains("the contract is"), "{verdict}");
}

/// An info metric's value is a constant, so a value other than 1 is a family
/// pretending to measure something.
#[test]
fn an_info_series_whose_value_is_not_one_is_refused() {
    let text = body((5, 4), (4, 5)).replacen(
        "mac=\"52:54:00:12:34:50\"} 1",
        "mac=\"52:54:00:12:34:50\"} 0",
        1,
    );
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("a value that is not 1");
    assert!(verdict.contains("always 1"), "{verdict}");
}

/// The document is what the labels are judged against, so a scrape that matches
/// the *shipped* document must fail against the alternate one. This is the host
/// half of what the two scrape scenarios prove on real hardware paths: labels
/// compiled in would satisfy both documents and this asserts they cannot.
#[test]
fn a_scrape_matching_one_document_is_refused_against_another() {
    let alternate = Topology::read(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scenarios/alternate-addressing.xml"
    )))
    .expect("the alternate document describes a bench");
    let verdict = judge(&pair(), 9, witness(), &alternate)
        .expect_err("the shipped document's labels against the alternate document");
    assert!(verdict.contains("configuration document"), "{verdict}");
}

/// The per-rule cross-check, in the direction that matters: a hit counter that
/// disagrees with the wire is a failure however well formed the exposition is.
#[test]
fn a_rule_hit_count_that_disagrees_with_the_wire_is_refused() {
    // The accepting rule against the frames the harness saw come back.
    let text = body((5, 4), (4, 5)).replacen(
        &format!("{RULE_HITS}{{domain=\"forwarder\",rule=\"probe-forward\"}} 9"),
        &format!("{RULE_HITS}{{domain=\"forwarder\",rule=\"probe-forward\"}} 8"),
        1,
    );
    let verdict = judge(&only(text), 9, witness(), &topology())
        .expect_err("eight hits against nine forwarded frames");
    assert!(verdict.contains("probe-forward"), "{verdict}");
    assert!(verdict.contains("observed coming back"), "{verdict}");

    // And the dropping rule against the probes the harness injected to its port
    // and never saw come back.
    let text = body((5, 4), (4, 5)).replacen(
        &format!("{RULE_HITS}{{domain=\"forwarder\",rule=\"probe-blocked\"}} {DENIED_PROBES}"),
        &format!("{RULE_HITS}{{domain=\"forwarder\",rule=\"probe-blocked\"}} 0"),
        1,
    );
    let verdict = judge(&only(text), 9, witness(), &topology())
        .expect_err("a rule crediting itself with none of the denials the pipeline counted");
    assert!(verdict.contains("probe-blocked"), "{verdict}");
    assert!(verdict.contains("count them in two places"), "{verdict}");
}

/// The two rules' counters must not be readable as each other's: a scrape that
/// credited the accepting rule's traffic to the dropping one is exactly the defect
/// a per-rule counter exists to make visible.
#[test]
fn two_rules_counters_are_not_interchangeable() {
    let text = body((5, 4), (4, 5))
        .replace("rule=\"probe-forward\"", "rule=\"swapped\"")
        .replace("rule=\"probe-blocked\"", "rule=\"probe-forward\"")
        .replace("rule=\"swapped\"", "rule=\"probe-blocked\"");
    let verdict =
        judge(&only(text), 9, witness(), &topology()).expect_err("the two counters transposed");
    assert!(verdict.contains("wrong rule's traffic"), "{verdict}");
}

/// One series per declared rule and not one more: a position no rule occupies is
/// a counter under no operator's name.
#[test]
fn a_rule_series_the_document_declares_no_rule_for_is_refused() {
    let mut text = body((5, 4), (4, 5));
    text.push_str(&format!(
        "{RULE_HITS}{{domain=\"forwarder\",rule=\"invented\"}} 0\n"
    ));
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("a third rule series");
    assert!(verdict.contains("whole cardinality"), "{verdict}");

    // And the other direction: a rule the document declares that reaches no
    // series at all.
    let text = body((5, 4), (4, 5)).replacen(
        &format!("{RULE_HITS}{{domain=\"forwarder\",rule=\"probe-blocked\"}} {DENIED_PROBES}\n"),
        "",
        1,
    );
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("a rule with no series");
    assert!(verdict.contains("whole cardinality"), "{verdict}");
}

/// An extra label on a rule series is an unbounded dimension the inventory does
/// not name, and this family's cardinality is an operator's to set.
#[test]
fn a_rule_series_carrying_an_extra_label_is_refused() {
    let text = body((5, 4), (4, 5)).replacen(
        "rule=\"probe-forward\"}",
        "rule=\"probe-forward\",pipeline=\"0\"}",
        1,
    );
    let verdict = judge(&only(text), 9, witness(), &topology()).expect_err("an extra dimension");
    assert!(verdict.contains("the contract is"), "{verdict}");
}

/// The filter's own totals are held to the same three counts, so a node whose
/// per-rule counters agree and whose totals do not is still a failure.
#[test]
fn a_policy_total_that_disagrees_with_the_wire_is_refused() {
    for (from, to, expected) in [
        (
            format!("{POLICY_PACKETS}{{domain=\"forwarder\",verdict=\"accepted\"}} 9"),
            format!("{POLICY_PACKETS}{{domain=\"forwarder\",verdict=\"accepted\"}} 8"),
            "observed forwarded",
        ),
        (
            format!(
                "{POLICY_PACKETS}{{domain=\"forwarder\",verdict=\"denied\"}} {}",
                DENIED_PROBES + UNMATCHED_PROBES
            ),
            format!("{POLICY_PACKETS}{{domain=\"forwarder\",verdict=\"denied\"}} 0"),
            "under the filter's two reasons",
        ),
    ] {
        let text = body((5, 4), (4, 5)).replacen(&from, &to, 1);
        let verdict =
            judge(&only(text), 9, witness(), &topology()).expect_err("a total that disagrees");
        assert!(verdict.contains(expected), "{verdict}");
    }
}

/// The two refusals must stay distinguishable, and a node that merged them is
/// internally consistent — so what catches it is the probe set, not the
/// arithmetic.
///
/// The body below credits the fallthrough's refusal to the dropping rule and to
/// the `policy_denied` reason, and raises that rule's hit counter to match: every
/// equality the appliance owes itself still holds, and the total is unchanged. It
/// is refused because the boot injected a probe *no rule is about*, and that
/// refusal has to appear as the fallthrough's.
#[test]
fn the_two_refusal_reasons_are_held_apart() {
    let text = body((5, 4), (4, 5))
        .replacen(
            "reason=\"no_policy_match\"} 1",
            "reason=\"no_policy_match\"} 0",
            1,
        )
        .replacen(
            "reason=\"policy_denied\"} 2",
            "reason=\"policy_denied\"} 3",
            1,
        )
        .replacen(
            &format!("rule=\"probe-blocked\"}} {DENIED_PROBES}"),
            "rule=\"probe-blocked\"} 3",
            1,
        );
    let verdict = judge(&only(text), 9, witness(), &topology())
        .expect_err("the fallthrough's refusal credited to a rule");
    assert!(verdict.contains("no_policy_match"), "{verdict}");
    assert!(
        verdict.contains("the default deny did not happen"),
        "{verdict}"
    );
}

/// The other direction, and the stronger half: the routed probe set provokes
/// neither refusal, so both counters must still read exactly zero. A node that
/// refused one of those six probes by policy would be refusing a frame the filter
/// is not consulted for.
#[test]
fn a_filter_refusal_no_probe_could_have_caused_is_refused() {
    let verdict = judge(&pair(), 9, routed_witness(), &topology())
        .expect_err("a policy denial on a boot that injected nothing the filter refuses");
    assert!(verdict.contains("nobody put on the wire"), "{verdict}");

    // And the routed set's own body, which reports neither, is accepted under
    // that witness — so the refusal above is the counter's and not the witness's.
    let quiet = body((5, 4), (4, 5))
        .replacen(
            "reason=\"policy_denied\"} 2",
            "reason=\"policy_denied\"} 0",
            1,
        )
        .replacen(
            "reason=\"no_policy_match\"} 1",
            "reason=\"no_policy_match\"} 0",
            1,
        )
        .replacen(
            &format!("rule=\"probe-blocked\"}} {DENIED_PROBES}"),
            "rule=\"probe-blocked\"} 0",
            1,
        )
        .replacen(
            &format!(
                "{POLICY_PACKETS}{{domain=\"forwarder\",verdict=\"denied\"}} {}",
                DENIED_PROBES + UNMATCHED_PROBES
            ),
            &format!("{POLICY_PACKETS}{{domain=\"forwarder\",verdict=\"denied\"}} 0"),
            1,
        );
    judge(&both(quiet), 9, routed_witness(), &topology())
        .expect("a boot whose six probes the filter was consulted for exactly twice");
}

/// Summed over both pipelines, as a reader must: the node publishes no total, so a
/// check that read one pipeline would pass a node that had counted the refusal on
/// the other.
#[test]
fn a_refusal_counted_on_the_other_pipeline_still_sums() {
    let text = body((5, 4), (4, 5))
        .replacen(
            "pipeline=\"0\",reason=\"policy_denied\"} 2",
            "pipeline=\"0\",reason=\"policy_denied\"} 0",
            1,
        )
        .replacen(
            "pipeline=\"1\",reason=\"policy_denied\"} 0",
            "pipeline=\"1\",reason=\"policy_denied\"} 2",
            1,
        );
    judge(&only(text), 9, witness(), &topology())
        .expect("the same two refusals, counted on the other direction of the same dataplane");
}
