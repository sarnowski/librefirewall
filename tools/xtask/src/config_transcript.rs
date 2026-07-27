//! The configuration transcript one boot must produce on the `LFW-CFG` console
//! channel.
//!
//! This is the [`crate::ab_test`] pattern applied to a second structured
//! channel. The boot manager emits `LFW-BOOT ` records and a scenario declares
//! the exact ordered sequence it must produce; the configuration and forwarding
//! domains emit `LFW-CFG ` records and a scenario declares the same. Nothing
//! here reads prose, and nothing here waits on a clock: the records carry the
//! generation and a per-boot sequence number precisely because the system has
//! no clock to order them by (MONITORING.md).
//!
//! # Where the expectation comes from
//!
//! Not from a list written out beside the test. [`ConfigContract::from_document`]
//! runs the document through `config::load` and then through `config::diff`
//! against the empty model — the same two calls `pds/config` makes at boot —
//! and renders each record with `lfw_log::render`, the same renderer the
//! domain's console `Sink` uses. The expected transcript is therefore a
//! function of the document and of the crates under test, and a hand-written
//! list that had drifted from either is not something this file can hold.
//!
//! # The ordering it asserts, and the ordering it does not
//!
//! Three records are the protocol's, not one domain's, and only the ordering
//! the protocol guarantees is asserted:
//!
//! * The change records and the publishing domain's `outcome=applied` summary
//!   come from one domain in one call, in `seq` order.
//! * The forwarding domain's own `outcome=applied` for that generation can only
//!   follow it: the domain switches when the publisher has committed, and the
//!   publisher commits only after the commit that produced the summary.
//! * The fail-closed `generation=0` record comes from the forwarding domain's
//!   `init`, so it precedes that domain's switch — and nothing orders it
//!   against the publishing domain's records at all. Its position among them is
//!   therefore *not* asserted; only that there is exactly one of it and that it
//!   is not seen after the switch.

use std::path::Path;

use config::{Change, Model};
use lfw_log::{Event, Field, GenerationOutcome, MAX_LINE_LEN, render};

/// The prefix marking a run of serial bytes as a configuration record rather
/// than console prose. The grammar is fixed in `crates/log/src/render.rs`.
const CONFIG_RECORD_PREFIX: &str = "LFW-CFG ";

/// What opens a record on any channel, and therefore what closes the one
/// before it. MONITORING.md makes this the reader's only handle: a record is
/// recognised by this prefix appearing anywhere in the stream, never by a line
/// boundary.
const RECORD_MARKER: &str = "LFW-";

/// The first generation a commit can assign: the datastore starts running
/// generation 0 — the fail-closed empty configuration — and the document a
/// domain is built with is the next one.
const FIRST_COMMIT: u32 = 1;

/// Room for every record one commit from the empty model can produce: every
/// object the handover image holds, in every field a record can name. The same
/// two constants `pds/config` sizes its own buffer from.
const MAX_CHANGES: usize = (wire::MAX_INTERFACES + wire::MAX_NEIGHBOURS) * Field::ALL.len();

/// Why a document does not describe a transcript worth asserting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ContractError {
    /// `config::load` refused it — the same refusal the appliance would make.
    Refused(String),
    /// The diff from the empty model moved nothing, so the document is the
    /// empty configuration: the domain would report `outcome=unchanged` and
    /// never publish, and there is no generation swap to prove.
    MovesNothing,
    /// More records than the buffer this file sizes from the ABI, which cannot
    /// happen for a document the ABI can hold and is refused rather than
    /// asserted against a truncated expectation.
    TooManyChanges { total: usize },
    /// A record would not render, which can only mean the console grammar has
    /// outgrown its own advertised maximum. Names the event rather than the
    /// bytes: every field of one is a parsed domain type, so the rendering is
    /// the same closed vocabulary a console line is.
    Unrenderable { event: String },
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => {
                write!(
                    f,
                    "the configuration domain would refuse this document: {reason}"
                )
            }
            Self::MovesNothing => f.write_str(
                "the document is the empty configuration, so no generation would be published",
            ),
            Self::TooManyChanges { total } => write!(
                f,
                "the diff has {total} records, past the {MAX_CHANGES} the handover ABI can hold"
            ),
            Self::Unrenderable { event } => write!(
                f,
                "{event} does not fit the {MAX_LINE_LEN}-byte console line"
            ),
        }
    }
}

/// The `LFW-CFG` transcript a boot from one document must produce.
pub(crate) struct ConfigContract {
    /// Every change record generation 1 carries, in `seq` order.
    changes: Vec<String>,
}

impl ConfigContract {
    /// Derive the transcript `document` must produce.
    ///
    /// # Errors
    /// [`ContractError`], where the document is not one a commit would publish.
    pub(crate) fn from_document(document: &[u8]) -> Result<Self, ContractError> {
        let model = config::load(document)
            .map_err(|error| ContractError::Refused(error.reason().name().to_owned()))?;
        let mut records = [None::<Change>; MAX_CHANGES];
        let summary = config::diff(&Model::EMPTY, &model, &mut records);
        if summary.overflowed() {
            return Err(ContractError::TooManyChanges {
                total: summary.total(),
            });
        }
        if summary.is_empty() {
            return Err(ContractError::MovesNothing);
        }

        let mut changes = Vec::with_capacity(summary.written());
        for (sequence, change) in records.iter().flatten().enumerate() {
            let sequence = sequence as u32;
            changes.push(line(&Event::ConfigChange {
                generation: FIRST_COMMIT,
                sequence,
                change: change.kind,
                object: change.object,
                key: change.key,
                field: change.field,
                from: change.from,
                to: change.to,
            })?);
        }
        Ok(Self { changes })
    }

    /// One clause naming what this transcript rests on, for a passing run.
    pub(crate) fn summary(&self) -> String {
        format!(
            "generation {FIRST_COMMIT} moved {} values, every one of them recorded",
            self.changes.len()
        )
    }

    /// The fail-closed record the forwarding domain emits in `init`: it is
    /// running the empty table, and says so rather than being silent about it.
    fn fail_closed() -> Result<String, ContractError> {
        line(&Event::ConfigGeneration {
            generation: 0,
            outcome: GenerationOutcome::Applied,
            changes: 0,
        })
    }

    /// The publishing domain's summary: the commit happened and moved this many
    /// values.
    fn committed(&self) -> Result<String, ContractError> {
        line(&Event::ConfigGeneration {
            generation: FIRST_COMMIT,
            outcome: GenerationOutcome::Applied,
            // Saturating rather than truncating, though the overflow check in
            // `from_document` has already bounded this by `MAX_CHANGES`.
            changes: u32::try_from(self.changes.len()).unwrap_or(u32::MAX),
        })
    }

    /// The forwarding domain's own summary once it has switched. It reports no
    /// change count: the diff is the publishing domain's record, and this one
    /// says only which generation is now carrying traffic.
    fn switched() -> Result<String, ContractError> {
        line(&Event::ConfigGeneration {
            generation: FIRST_COMMIT,
            outcome: GenerationOutcome::Applied,
            changes: 0,
        })
    }

    /// Judge one boot's serial capture against this transcript.
    ///
    /// # Errors
    /// The verdict, naming what the channel carried against what the document
    /// says it must, and where the whole run log is.
    pub(crate) fn judge(&self, serial: &[u8], log: &Path) -> Result<(), String> {
        let text = String::from_utf8_lossy(serial);
        let observed = config_records(&text);
        let fail_closed = Self::fail_closed()?;
        let committed = self.committed()?;
        let switched = Self::switched()?;

        let refusals: Vec<&str> = observed
            .iter()
            .copied()
            .filter(|line| line.contains(" rejected="))
            .collect();
        if !refusals.is_empty() {
            return Err(format!(
                "the appliance refused its own configuration: {refusals:#?}\n  full run log: {}",
                log.display()
            ));
        }

        let at: Vec<usize> = observed
            .iter()
            .enumerate()
            .filter(|(_, line)| **line == fail_closed)
            .map(|(index, _)| index)
            .collect();
        let [fail_closed_at] = at.as_slice() else {
            return Err(format!(
                "the fail-closed record {fail_closed:?} appears {} times; the forwarding domain \
                 emits it exactly once, in `init`, and a node that never emitted it was never \
                 running the empty table\n  observed: {observed:#?}\n  full run log: {}",
                at.len(),
                log.display()
            ));
        };

        // Every other record, in the order it was emitted. The fail-closed one
        // is lifted out because nothing orders it against the publishing
        // domain's records; everything left is one ordered chain.
        let rest: Vec<&str> = observed
            .iter()
            .enumerate()
            .filter(|(index, _)| index != fail_closed_at)
            .map(|(_, line)| *line)
            .collect();
        let mut expected: Vec<&str> = self.changes.iter().map(String::as_str).collect();
        expected.push(&committed);
        expected.push(&switched);
        if rest != expected {
            return Err(format!(
                "the configuration channel did not carry the transcript this document \
                 describes\n{}\n  full run log: {}",
                describe(&expected, &rest),
                log.display()
            ));
        }

        // The forwarding domain emits the fail-closed record in `init` and the
        // switch in a later wakeup, both from one single-threaded domain, so
        // the first may never be seen after the second.
        match observed.iter().rposition(|line| *line == switched) {
            Some(switch_at) if *fail_closed_at < switch_at => Ok(()),
            _ => Err(format!(
                "the fail-closed record appears after the switch to generation {FIRST_COMMIT}, \
                 which one domain emitting both in order cannot produce\n  observed: \
                 {observed:#?}\n  full run log: {}",
                log.display()
            )),
        }
    }
}

/// Render one event as the console line the domain's own `Sink` would write.
fn line(event: &Event) -> Result<String, ContractError> {
    let unrenderable = || ContractError::Unrenderable {
        event: format!("{event:?}"),
    };
    let mut buffer = [0u8; MAX_LINE_LEN];
    let written = render(event, &mut buffer).map_err(|_| unrenderable())?;
    let bytes = buffer.get(..written).ok_or_else(unrenderable)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| unrenderable())
}

impl From<ContractError> for String {
    fn from(error: ContractError) -> Self {
        error.to_string()
    }
}

/// Extract the configuration records from a serial capture, in emission order.
///
/// # Why a line is not a record
///
/// The console is one unsynchronised device shared by every protection domain
/// and a record is written with no lock, so a record does not reliably *begin*
/// a line. Every boot capture under `build/image/qemu-*.log` carries the shape
/// `LFW-PD domain=nic-driverLFW-PD domain=nic-driver state=starting`: one
/// domain's whole record written inside another's, mid-record. MONITORING.md
/// therefore states the reader's obligation as part of the contract — recover
/// records by scanning for the `LFW-` prefix anywhere in the stream — and
/// [`records_in_line`] is that scan.
///
/// Splitting on newlines and matching a prefix, which this did before, was not
/// merely fragile but *asymmetrically* so. Only `LFW-PD` records are seen to
/// tear today, so the transcript comparison went on passing; but a
/// `LFW-CFG … rejected=` record written after another domain's on one line
/// fails a `starts_with` filter, and [`ConfigContract::judge`]'s refusal guard
/// would then read a node that had refused its own configuration as a clean
/// boot. A guard that fails open on the case it exists for is worse than none.
///
/// # What this deliberately does not do, and what it costs
///
/// It does not reassemble. A record torn through its own middle leaves a head
/// fragment here and a tail carrying no marker, which is discarded — so the
/// transcript comparison reports a mismatch rather than silently accepting one.
/// That is the honest limit of the contract rather than an omission: two
/// concurrent writers leave a reader nothing to decide which fragment continues
/// which by, and a harness that guessed would be inventing records.
///
/// It also gives up one property the line-splitting reader had: prose that
/// *quotes* a record now reads as one, the marker being the only handle the
/// contract offers. That is the right way to be wrong, and is asserted as such
/// — a quoted record carries its prose with it, so it lands as a mismatch or a
/// refusal verdict and stops the gate, where a torn record went unseen.
fn config_records(text: &str) -> Vec<&str> {
    text.lines().flat_map(records_in_line).collect()
}

/// The records one captured line carries, in the order they were written: each
/// [`RECORD_MARKER`] opens a candidate that runs to the next marker or to the
/// end of the line, and only the candidates on the `LFW-CFG` channel are kept.
/// GRUB's prose, seL4's boot chatter and the `LFW-PD` lifecycle channel
/// therefore cannot be mistaken for a configuration decision wherever in a line
/// they sit.
fn records_in_line(line: &str) -> Vec<&str> {
    let markers: Vec<usize> = line
        .match_indices(RECORD_MARKER)
        .map(|(at, _)| at)
        .collect();
    markers
        .iter()
        .enumerate()
        .filter_map(|(position, start)| {
            let end = markers.get(position + 1).copied().unwrap_or(line.len());
            line.get(*start..end).map(str::trim)
        })
        .filter(|record| record.starts_with(CONFIG_RECORD_PREFIX))
        .collect()
}

/// Name the first place two transcripts part company, then print both. The
/// index alone is what makes a sixteen-record diff readable; the two lists
/// behind it are what makes it actionable.
fn describe(expected: &[&str], observed: &[&str]) -> String {
    let first = expected
        .iter()
        .zip(observed)
        .position(|(left, right)| left != right);
    let head = match first {
        Some(index) => format!(
            "  first difference at record {index}:\n    expected: {:?}\n    observed: {:?}",
            expected.get(index),
            observed.get(index),
        ),
        None => format!(
            "  the shorter transcript is a prefix of the longer: {} records expected, {} observed",
            expected.len(),
            observed.len(),
        ),
    };
    format!("{head}\n  expected: {expected:#?}\n  observed: {observed:#?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED: &[u8] = include_bytes!("../../../systems/qemu-x86_64/configuration.xml");
    const ALTERNATE: &[u8] = include_bytes!("../scenarios/alternate-addressing.xml");

    /// The two halves a `nic-driver` record is torn into when another domain
    /// writes between them, verbatim from `build/image/qemu-generation-swap.log`
    /// — the head that ends a line another domain's record is spliced onto, and
    /// the tail that resumes on the line after.
    const TORN_HEAD: &str = "LFW-PD domain=nic-driver sta";
    const TORN_TAIL: &str = "te=ready rx-posted=16";

    fn log() -> &'static Path {
        Path::new("/nonexistent/qemu.log")
    }

    /// Rewrite a capture the way the console really tears one: every `LFW-CFG`
    /// record is written *inside* a `nic-driver` record, which resumes on the
    /// line after. Nothing about the configuration channel changes — the same
    /// records in the same order — only where the line breaks fall.
    fn tear_every_config_record(text: &str) -> String {
        text.lines()
            .map(str::trim_end)
            .map(|line| {
                if line.starts_with(CONFIG_RECORD_PREFIX) {
                    format!("{TORN_HEAD}{line}\r\n{TORN_TAIL}\r\n")
                } else {
                    format!("{line}\r\n")
                }
            })
            .collect()
    }

    /// The serial capture a boot from `document` must produce, in the order the
    /// appliance was observed to produce it: the publishing domain runs at the
    /// highest priority in the system, so it commits before the forwarding
    /// domain's `init` runs at all.
    fn capture(contract: &ConfigContract) -> String {
        let mut text =
            String::from("Bootstrapping kernel\r\nLFW-PD domain=config state=starting\r\n");
        for record in &contract.changes {
            text.push_str(record);
            text.push_str("\r\n");
        }
        text.push_str(&contract.committed().unwrap());
        text.push_str("\r\nLFW-PD domain=config state=ready\r\n");
        text.push_str("LFW-PD domain=forwarder state=starting\r\n");
        text.push_str(&ConfigContract::fail_closed().unwrap());
        text.push_str("\r\n");
        text.push_str(&ConfigContract::switched().unwrap());
        text.push_str("\r\nLFW-PD domain=nic-driver state=ready rx-posted=16\r\n");
        text
    }

    #[test]
    fn the_shipped_document_produces_a_record_for_every_value_it_names() {
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        // Two interfaces of five fields and two neighbours of three: the
        // document's own content, counted rather than restated.
        assert_eq!(contract.changes.len(), 2 * 5 + 2 * 3);
        assert!(contract.summary().contains("16"));
        for record in &contract.changes {
            assert!(record.starts_with("LFW-CFG generation=1 seq="), "{record}");
            assert!(record.contains("change=added"), "{record}");
            assert!(
                !record.contains(" from="),
                "an addition came from nothing: {record}"
            );
        }
    }

    #[test]
    fn the_expected_records_are_the_documents_own_values() {
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let joined = contract.changes.join("\n");
        for value in [
            "key=dataplane-0 field=mac to=52:54:00:12:34:50",
            "key=dataplane-1 field=address to=10.0.1.1",
            "key=endpoint-a field=address to=10.0.0.2",
            "key=endpoint-b field=mac to=52:54:00:00:00:0b",
        ] {
            assert!(joined.contains(value), "{value} missing from:\n{joined}");
        }
    }

    #[test]
    fn the_alternate_document_produces_a_transcript_that_shares_no_value_with_the_shipped_one() {
        let shipped = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let alternate = ConfigContract::from_document(ALTERNATE).expect("the alternate document");
        assert_eq!(shipped.changes.len(), alternate.changes.len());
        for record in &alternate.changes {
            assert!(
                !shipped.changes.contains(record),
                "a transcript both documents produce proves nothing: {record}"
            );
        }
    }

    #[test]
    fn a_boot_that_carried_the_transcript_is_accepted() {
        for document in [SHIPPED, ALTERNATE] {
            let contract = ConfigContract::from_document(document).expect("a shipped document");
            contract
                .judge(capture(&contract).as_bytes(), log())
                .expect("the transcript the document describes");
        }
    }

    #[test]
    fn a_boot_carrying_another_documents_transcript_is_refused() {
        let shipped = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let alternate = ConfigContract::from_document(ALTERNATE).expect("the alternate document");
        // The scenario-3 failure this exists to catch: an image that still
        // carries the first document's table would produce the first
        // document's records, and a weaker check would read that as a pass.
        let verdict = alternate
            .judge(capture(&shipped).as_bytes(), log())
            .expect_err("the wrong document's transcript");
        assert!(
            verdict.contains("first difference at record 0"),
            "{verdict}"
        );
        assert!(verdict.contains("dataplane-0"), "{verdict}");
        assert!(verdict.contains("uplink"), "{verdict}");
    }

    #[test]
    fn an_unchanged_value_that_produced_a_record_is_refused() {
        // The exactness the contract rests on: one extra record — a value
        // nobody edited reported as changed — must fail, so the count is
        // asserted rather than a floor.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let mut text = capture(&contract);
        text.push_str(
            "LFW-CFG generation=1 seq=16 change=modified object=interface key=dataplane-0 \
             field=port from=0 to=0\r\n",
        );
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("a record for a value that did not move");
        assert!(verdict.contains("seq=16"), "{verdict}");
    }

    #[test]
    fn a_missing_record_is_refused_by_the_record_that_is_missing() {
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let dropped = contract.changes[7].clone();
        let text = capture(&contract).replace(&format!("{dropped}\r\n"), "");
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("a value that moved with no record of it");
        assert!(
            verdict.contains("first difference at record 7"),
            "{verdict}"
        );
    }

    #[test]
    fn a_node_that_never_reached_the_fail_closed_generation_is_refused() {
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let without = capture(&contract).replace(
            &format!("{}\r\n", ConfigContract::fail_closed().unwrap()),
            "",
        );
        let verdict = contract
            .judge(without.as_bytes(), log())
            .expect_err("no fail-closed record");
        assert!(verdict.contains("appears 0 times"), "{verdict}");
    }

    #[test]
    fn a_fail_closed_record_after_the_switch_is_refused() {
        // The one ordering the forwarding domain guarantees of itself: it says
        // it is running the empty table before it says it has left it. A
        // capture in the other order describes a domain that restarted, which
        // is not a passing boot.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let fail_closed = ConfigContract::fail_closed().unwrap();
        let switched = ConfigContract::switched().unwrap();
        let text = capture(&contract)
            .replace(&format!("{fail_closed}\r\n{switched}\r\n"), "@\r\n")
            .replace("@\r\n", &format!("{switched}\r\n{fail_closed}\r\n"));
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("the fail-closed record after the switch");
        assert!(verdict.contains("after the switch"), "{verdict}");
    }

    #[test]
    fn a_node_that_staged_but_never_switched_is_refused() {
        // Exactly the deadlock this scenario exists to detect: the publishing
        // domain committed and said so, and the forwarding domain never
        // reported the generation as carrying traffic.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let switched = ConfigContract::switched().unwrap();
        let text = capture(&contract).replacen(&format!("{switched}\r\n"), "", 1);
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("no switch record");
        assert!(verdict.contains("full run log"), "{verdict}");
    }

    #[test]
    fn a_refused_configuration_is_reported_as_a_refusal_rather_than_a_missing_record() {
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let mut text = capture(&contract);
        text.push_str("LFW-CFG generation=0 rejected=doctype offset=38\r\n");
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("the appliance refused its own document");
        assert!(
            verdict.contains("refused its own configuration"),
            "{verdict}"
        );
        assert!(verdict.contains("doctype"), "{verdict}");
    }

    #[test]
    fn only_the_configuration_channel_contributes() {
        // The other three things a serial line carries and none of which may be
        // read as a configuration decision: another channel's record, the boot
        // manager's, and prose with no marker at all.
        let capture = "Bootstrapping kernel\r\n\
             librefirewall: booting slot A\r\n\
             LFW-BOOT slot=A state=confirmed\r\n\
             LFW-PD domain=config state=starting\r\n\
             LFW-CFG generation=0 outcome=applied changes=0\r\n";
        assert_eq!(
            config_records(capture),
            ["LFW-CFG generation=0 outcome=applied changes=0"]
        );
    }

    #[test]
    fn prose_quoting_a_record_is_now_indistinguishable_from_one_and_fails_closed() {
        // The price of scanning for the marker, paid deliberately and recorded
        // here rather than discovered later. The marker is the *only* handle
        // MONITORING.md gives a reader, so prose that quotes it is a record; the
        // previous reader ignored such a line only because it happened not to
        // begin one, which is the same accident that hid a torn refusal.
        //
        // What makes the trade the right way round is the direction each
        // mistake fails in. A quoted record is not a record's exact bytes — the
        // prose around it comes with it — so it lands as a mismatch or, for a
        // quoted rejection, as a refusal verdict. Both stop the gate. The
        // behaviour this replaced failed the other way, and passed.
        let quoted = "see LFW-CFG generation=1 outcome=applied changes=16 for details\r\n";
        assert_eq!(
            config_records(quoted),
            ["LFW-CFG generation=1 outcome=applied changes=16 for details"]
        );

        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let text = format!("{}{quoted}", capture(&contract));
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("prose carrying the marker is a record, and an unexpected one");
        assert!(verdict.contains("for details"), "{verdict}");
    }

    #[test]
    fn a_record_written_inside_another_domains_record_is_still_recovered() {
        // The shape every capture under build/image/qemu-*.log carries: one
        // domain's whole record spliced into another's, and the interrupted
        // record's tail — which carries no marker of its own — on the next
        // line. MONITORING.md makes recovering the first the reader's job.
        let capture = "LFW-PD domain=nic-driver staLFW-CFG generation=0 outcome=applied \
                       changes=0\r\nte=ready rx-posted=16\r\n";
        assert_eq!(
            config_records(capture),
            ["LFW-CFG generation=0 outcome=applied changes=0"]
        );
    }

    #[test]
    fn a_transcript_torn_the_way_a_real_boot_tears_it_is_still_judged() {
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let text = tear_every_config_record(&capture(&contract));
        // The premise, asserted rather than assumed: not one line of this
        // capture begins with a configuration record, so the line-splitting
        // reader this replaced would have found an empty transcript and
        // reported all sixteen change records missing.
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with(CONFIG_RECORD_PREFIX)),
            "the torn capture still begins a line with a record:\n{text}"
        );
        contract
            .judge(text.as_bytes(), log())
            .expect("the transcript the document describes, torn across the wire");
    }

    #[test]
    fn a_refusal_written_inside_another_domains_record_is_still_caught() {
        // The asymmetry that made the line-splitting reader dangerous rather
        // than merely fragile. A torn change record shows up as a mismatch and
        // fails loudly; a torn *rejection* failed the prefix filter outright,
        // so the one guard that says "the appliance refused its own
        // configuration" failed open on precisely the boot it exists for.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let mut text = capture(&contract);
        text.push_str(&format!(
            "{TORN_HEAD}LFW-CFG generation=0 rejected=doctype offset=38\r\n{TORN_TAIL}\r\n"
        ));
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("a refusal written inside another domain's record");
        assert!(
            verdict.contains("refused its own configuration"),
            "{verdict}"
        );
        assert!(verdict.contains("doctype"), "{verdict}");
    }

    #[test]
    fn a_record_torn_through_its_own_middle_is_reported_rather_than_silently_accepted() {
        // The limit of the contract, asserted so it is a tested property and
        // not a hope. Scanning for the marker recovers a record that did not
        // begin its line; it cannot reassemble one whose own bytes were split,
        // because the continuation carries no marker and two concurrent writers
        // leave nothing to decide which fragment continues which by. What must
        // hold is that the head fragment is judged as the mismatch it is,
        // rather than the generation being read as switched.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let switched = ConfigContract::switched().unwrap();
        let (head, tail) = switched
            .split_once("outcome=")
            .expect("a generation record names its outcome");
        let text = capture(&contract).replace(
            &format!("{switched}\r\n"),
            &format!("{head}LFW-PD domain=config state=ready\r\n{tail}\r\n"),
        );
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("a record torn through its middle");
        // Sixteen change records, the publisher's summary, and the switch that
        // was torn: the first difference is the last of them.
        assert!(
            verdict.contains("first difference at record 17"),
            "{verdict}"
        );
    }

    #[test]
    fn a_document_the_validator_refuses_yields_no_contract_to_assert() {
        assert!(matches!(
            ConfigContract::from_document(b"<!DOCTYPE evil><configuration/>"),
            Err(ContractError::Refused(_))
        ));
        assert!(matches!(
            ConfigContract::from_document(
                b"<configuration><interfaces/><neighbours/></configuration>"
            ),
            Err(ContractError::MovesNothing)
        ));
    }

    #[test]
    fn every_refusal_reads_as_the_thing_that_is_wrong() {
        let rendered = [
            ContractError::Refused("doctype".to_owned()).to_string(),
            ContractError::MovesNothing.to_string(),
            ContractError::TooManyChanges { total: 999 }.to_string(),
            ContractError::Unrenderable {
                event: "ConfigGeneration { generation: 3 }".to_owned(),
            }
            .to_string(),
        ];
        assert!(rendered[0].contains("doctype"));
        assert!(rendered[1].contains("empty configuration"));
        assert!(rendered[2].contains("999"));
        assert!(rendered[3].contains("generation: 3"));
    }

    /// The renderer is `lfw_log`'s own, so a grammar change lands here rather
    /// than leaving the expectation and the appliance describing the same
    /// commit in two different languages.
    #[test]
    fn a_record_is_rendered_by_the_grammar_the_domain_writes() {
        use lfw_log::{ChangeKind, ObjectKind, Value};
        let event = Event::ConfigChange {
            generation: 1,
            sequence: 0,
            change: ChangeKind::Added,
            object: ObjectKind::Interface,
            key: config::Identifier::new(b"wan").expect("within the alphabet"),
            field: Field::Port,
            from: None,
            to: Some(Value::Port(0)),
        };
        assert_eq!(
            line(&event),
            Ok(
                "LFW-CFG generation=1 seq=0 change=added object=interface key=wan field=port to=0"
                    .to_owned()
            )
        );
    }
}
