//! The configuration transcript one boot must produce on the `LFW-CFG` console
//! channel.
//!
//! This is the [`crate::ab_test`] pattern applied to a second structured
//! channel. The boot manager emits `LFW-BOOT ` records and a scenario declares
//! the exact ordered sequence it must produce; the configuration and forwarding
//! domains emit `LFW-CFG ` records and a scenario declares the same. Nothing
//! here reads prose, and nothing here waits on a clock: the records carry the
//! generation and a per-boot sequence number precisely because no record on
//! this channel is timestamped.
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
//! Two domains write this channel, each into its own ring, and the console
//! domain decides what reaches the line: `log::console::ConsolePrinter::drain`
//! takes at most `BURST_PER_RING` records from a ring per pass and starts each
//! pass one ring further along than the last, which is the fairness rule that
//! stops a flooding ring starving another
//! (`console::tests::each_pass_starts_one_ring_further_along` and
//! `console::tests::the_rotation_serves_the_later_ring_first_when_its_turn_comes`
//! hold it). So *which* domain's record reaches the line first is decided by
//! where that rotation stood, not by which event happened first, and the
//! records carry no timestamp to appeal to. Production order is not
//! emission order, and asserting one as the other asserts against the rotation.
//!
//! The transcript is therefore judged as the merge of two chains — each totally
//! ordered, because one ring has one writer publishing into it in order — with
//! nothing asserted across them:
//!
//! * **The publishing domain's chain.** The change records in `seq` order, then
//!   its own `outcome=applied` summary, which the same call writes after the
//!   last of them. Asserted as a *subsequence*, not a contiguous block: the
//!   chain is longer than one burst, so another domain's records may fall
//!   inside it.
//! * **The forwarding domain's chain.** The fail-closed `generation=0` record
//!   its `init` writes, then its own `outcome=applied` for the generation it
//!   switched to.
//!
//! Everything else is a set: these two chains are the whole of what the channel
//! carried, each record exactly once, and no `rejected=` record among them.
//! Either domain's block may lead, and either may sit inside the other; a
//! record that is missing, doubled, invented, or out of its *own* domain's
//! order is refused.

use std::path::Path;

use config::{Change, Model};
use lfw_log::{Event, GenerationOutcome, MAX_LINE_LEN, Stamp, render};

use crate::console_records::{CONFIG_PREFIX as CONFIG_RECORD_PREFIX, without_time};

/// The first generation a commit can assign: the datastore starts running
/// generation 0 — the fail-closed empty configuration — and the document a
/// domain is built with is the next one.
const FIRST_COMMIT: u32 = 1;

/// Why a document does not describe a transcript worth asserting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ContractError {
    /// `config::load` refused it — the same refusal the appliance would make.
    Refused(String),
    /// The diff from the empty model moved nothing, so the document is the
    /// empty configuration: the domain would report `outcome=unchanged` and
    /// never publish, and there is no generation swap to prove.
    MovesNothing,
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
        Self::from_model(&model)
    }

    /// The transcript a model would produce, which is the half of
    /// [`ConfigContract::from_document`] that does not read bytes.
    ///
    /// Separate because one of its refusals is unreachable from a document: a
    /// configuration that moves nothing is one naming no object at all, and the
    /// schema requires a `<management>` element, so every document a reader
    /// accepts names at least that one.
    ///
    /// # Errors
    /// [`ContractError`], as [`ConfigContract::from_document`].
    fn from_model(model: &Model) -> Result<Self, ContractError> {
        // The same call `pds/config` makes, with the collecting sink this side
        // can afford: an allocator is what separates the two, never a different
        // walk.
        let mut records = Vec::new();
        config::diff(&Model::EMPTY, model, &mut |change: Change| {
            records.push(change);
        });
        if records.is_empty() {
            return Err(ContractError::MovesNothing);
        }

        let mut changes = Vec::with_capacity(records.len());
        for (sequence, change) in records.iter().enumerate() {
            let sequence = u32::try_from(sequence).unwrap_or(u32::MAX);
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
        let carried = config_records(&text);
        let observed = borrowed(&carried);
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

        // The publishing domain's chain: its change records in `seq` order and
        // then its own summary, all written into one ring by one call.
        let mut published: Vec<&str> = self.changes.iter().map(String::as_str).collect();
        published.push(&committed);

        // The whole of what the channel must have carried. Only the set is
        // asserted here — which domain's records the rotation put first is not
        // this contract's to decide — and each chain's own order below.
        let expected: Vec<&str> = published
            .iter()
            .copied()
            .chain([fail_closed.as_str(), switched.as_str()])
            .collect();
        if let Some(mismatch) = set_mismatch(&expected, &observed) {
            return Err(format!(
                "the configuration channel did not carry the records this document \
                 describes\n{mismatch}\n  observed: {observed:#?}\n  full run log: {}",
                log.display()
            ));
        }

        // One ring, one writer, published in order, so the reader sees that
        // order — as a subsequence rather than a contiguous run, the chain
        // being longer than the console's per-ring burst.
        if let Some(inversion) = chain_inversion(&published, &observed) {
            return Err(format!(
                "the configuration domain's records did not reach the line in the `seq` order \
                 one ring with one writer publishes them in\n{inversion}\n  observed: \
                 {observed:#?}\n  full run log: {}",
                log.display()
            ));
        }

        // The forwarding domain's own chain, by the same argument: it emits the
        // fail-closed record in `init` and the switch in a later wakeup, both
        // into one ring, so the first may never be seen after the second.
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

/// Render one event as the console line the domain's own `Sink` would write,
/// less its instant.
///
/// Less its instant because that is the one field the build cannot predict: it
/// is whatever the appliance's counter said at the moment of emission, and two
/// runs of one image disagree about it. Both sides of every comparison below
/// go through this function and through
/// [`console_records::without_time`](crate::console_records::without_time), so
/// a transcript is judged on *what* each record says. What the instant itself
/// owes is [`crate::stamp_contract`]'s, over every record of every channel.
fn line(event: &Event) -> Result<String, ContractError> {
    let unrenderable = || ContractError::Unrenderable {
        event: format!("{event:?}"),
    };
    let mut buffer = [0u8; MAX_LINE_LEN];
    let written = render(Stamp::Unsynchronized, event, &mut buffer).map_err(|_| unrenderable())?;
    let bytes = buffer.get(..written).ok_or_else(unrenderable)?;
    let rendered = String::from_utf8(bytes.to_vec()).map_err(|_| unrenderable())?;
    Ok(without_time(&rendered))
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
/// A record reaches the line through one writer — the console domain renders it
/// and puts the whole line on the port it alone holds — so records no longer
/// splice into one another: no capture under `build/image/` shows the shape
/// `LFW-PD domain=nic-driverLFW-PD domain=nic-driver state=starting`, in either
/// kernel configuration. That is recent. Before the console domain existed
/// every domain wrote its own records through `debug_println!` with nothing
/// serialising them, and one domain's whole record written inside another's,
/// mid-record, is what a capture then routinely carried.
///
/// The reader's obligation outlived the defect, and the console contract still
/// states it — recover records by scanning for the `LFW-`
/// prefix anywhere in the stream, never by assuming a line is a record.
/// [`crate::console_records`] is that scan, held to what the contract obliges
/// rather than to what the current captures happen to contain. The single-writer
/// property is exact only in release: the debug kernel writes the same port for
/// its banner and its fault reports, so a record preceded on its line by kernel
/// prose stays reachable there.
///
/// Splitting on newlines and matching a prefix, which this did before, was not
/// merely fragile but *asymmetrically* so — and that argument rests on the
/// grammar rather than on what any capture shows, so it did not weaken when the
/// tearing stopped. A `LFW-CFG … rejected=` record written after another
/// domain's on one line fails a `starts_with` filter, and
/// [`ConfigContract::judge`]'s refusal guard would then read a node that had
/// refused its own configuration as a clean boot. A guard that fails open on
/// the case it exists for is worse than none.
///
/// What that scan does not do — reassemble a torn record — and what giving up
/// the line boundary costs, are stated where it lives.
fn config_records(text: &str) -> Vec<String> {
    crate::console_records::records_on(text, CONFIG_RECORD_PREFIX)
        .into_iter()
        .map(without_time)
        .collect()
}

/// As [`config_records`], borrowed, which is what every comparison below takes.
fn borrowed(records: &[String]) -> Vec<&str> {
    records.iter().map(String::as_str).collect()
}

/// Name the records the channel did not carry exactly once and those it carried
/// that the document describes none of. `None` where the two sets agree.
///
/// Two lists rather than a positional diff, because the two domains' blocks may
/// interleave in any way: a record's *index* in the observed stream carries no
/// verdict, so reporting one as the difference would name the rotation rather
/// than the defect.
fn set_mismatch(expected: &[&str], observed: &[&str]) -> Option<String> {
    let carried = |record: &str| observed.iter().filter(|line| **line == record).count();
    let absent: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|record| carried(record) == 0)
        .collect();
    let repeated: Vec<(usize, &str)> = expected
        .iter()
        .map(|record| (carried(record), *record))
        .filter(|(times, _)| *times > 1)
        .collect();
    let unexpected: Vec<&str> = observed
        .iter()
        .copied()
        .filter(|line| !expected.iter().any(|record| record == line))
        .collect();
    if absent.is_empty() && repeated.is_empty() && unexpected.is_empty() {
        return None;
    }
    Some(format!(
        "  absent, and the document describes one of each: {absent:#?}\n  \
         carried this many times, where the document describes one: {repeated:#?}\n  \
         carried, and the document describes no such record: {unexpected:#?}"
    ))
}

/// Name the first record of `chain` that reached the line before the record it
/// was published after. `None` where the chain is a subsequence of `observed`.
///
/// It reads a position per record rather than walking the stream once, which
/// [`set_mismatch`] having already passed is what makes sound: every record of
/// `chain` then sits at exactly one position, so the chain is in order exactly
/// when those positions rise. The records are pairwise distinct — the change
/// records by their `seq`, the two summaries by a change count that
/// [`ContractError::MovesNothing`] keeps non-zero — so no position is shared.
fn chain_inversion(chain: &[&str], observed: &[&str]) -> Option<String> {
    let mut previous: Option<(usize, &str)> = None;
    for record in chain {
        let Some(at) = observed.iter().position(|line| line == record) else {
            return Some(format!("  the channel carried no {record:?} at all"));
        };
        if let Some((published_at, published)) = previous
            && at < published_at
        {
            return Some(format!(
                "  {record:?} reached the line at record {at}, before {published:?} at record \
                 {published_at} — which the domain published first"
            ));
        }
        previous = Some((at, record));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED: &[u8] = include_bytes!("../../../systems/qemu-x86_64/configuration.xml");
    const ALTERNATE: &[u8] = include_bytes!("../scenarios/alternate-addressing.xml");

    /// The two halves a `nic-driver` record splits into when a second writer
    /// lands between them — the head that ends a line another domain's record
    /// is spliced onto, and the tail that resumes on the line after.
    ///
    /// The record is `build/image/qemu-generation-swap.log`'s own, which that
    /// capture carries whole; the split is this test's, made where a second
    /// writer would have fallen. Nothing in the tree tears a record any more,
    /// the port having one writer, so the input the reader is held to has to be
    /// constructed rather than quoted — which is the point, the specified
    /// console contract being what this reader answers to.
    const TORN_HEAD: &str = "LFW-PD domain=nic-driver sta";
    const TORN_TAIL: &str = "te=ready rx-posted=16";

    fn log() -> &'static Path {
        Path::new("/nonexistent/qemu.log")
    }

    /// Rewrite a capture the way an unserialised console tore one: every
    /// `LFW-CFG` record is written *inside* a `nic-driver` record, which
    /// resumes on the line after. Nothing about the configuration channel
    /// changes — the same records in the same order — only where the line
    /// breaks fall.
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

    /// Which domain's ring the console's rotation served first, and therefore
    /// which of the two blocks leads the capture.
    #[derive(Clone, Copy, Debug)]
    enum Leading {
        Publisher,
        Forwarder,
    }

    /// The serial capture a boot from `document` produces when the rotation put
    /// `leading`'s ring first. Both orders are the same boot: the two domains
    /// write two rings and the console decides what reaches the line, so this
    /// is the one axis the appliance may vary without anything having gone
    /// wrong.
    fn capture_with(contract: &ConfigContract, leading: Leading) -> String {
        let mut publisher = String::from("LFW-PD domain=config state=starting\r\n");
        for record in &contract.changes {
            publisher.push_str(record);
            publisher.push_str("\r\n");
        }
        publisher.push_str(&contract.committed().unwrap());
        publisher.push_str("\r\nLFW-PD domain=config state=ready\r\n");

        let forwarder = format!(
            "LFW-PD domain=forwarder state=starting\r\n{}\r\n{}\r\nLFW-PD domain=nic-driver \
             state=ready rx-posted=16\r\n",
            ConfigContract::fail_closed().unwrap(),
            ConfigContract::switched().unwrap()
        );

        let (first, second) = match leading {
            Leading::Publisher => (publisher, forwarder),
            Leading::Forwarder => (forwarder, publisher),
        };
        format!("Bootstrapping kernel\r\n{first}{second}")
    }

    /// The publisher-first capture, which every test that edits one record of a
    /// transcript builds on.
    fn capture(contract: &ConfigContract) -> String {
        capture_with(contract, Leading::Publisher)
    }

    #[test]
    fn the_shipped_document_produces_a_record_for_every_value_it_names() {
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        // Two interfaces of five fields, two neighbours of three, two rules of
        // eleven, and the management interface's four: the document's own
        // content, counted rather than restated. A rule reports its own `id` as a
        // field because a rule's records are keyed by its position rather than by
        // its name, so an eleven-attribute rule is eleven records.
        assert_eq!(contract.changes.len(), 2 * 5 + 2 * 3 + 2 * 11 + 4);
        assert!(contract.summary().contains("42"));
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
            // The management interface is one of the document's objects, keyed
            // by the name a record about it carries rather than by an id it does
            // not have.
            "object=management key=management field=mac to=52:54:00:12:34:52",
            "object=management key=management field=address to=10.0.2.15",
        ] {
            assert!(joined.contains(value), "{value} missing from:\n{joined}");
        }
    }

    /// Every record that names an id, an address or a MAC must differ between the
    /// two documents, or a stale table could satisfy both transcripts.
    ///
    /// That is asserted on the shared records themselves rather than inferred
    /// from how many there are, and then the shared set is closed by counting
    /// what each of its records is *about* — so neither half of the claim rests
    /// on a total somebody has to keep in step with the documents.
    ///
    /// What the two documents do share is exhaustively accounted for rather than
    /// excused. A rule's records are keyed by its **position**, so a criterion
    /// both documents state the same way is one record in both — and they state
    /// the same policy on purpose, because that policy is what the forwarding
    /// contract is stated against. `field=id` is the one rule record naming the
    /// rule, and the two documents give their rules different ids for exactly
    /// this reason. Beside those, the management port's `enabled=true`: both
    /// enable that port. None of them carries addressing or identity, so none
    /// can prove anything either way; an interface or a neighbour contributes
    /// nothing at all, being keyed by an id each document coined.
    #[test]
    fn the_alternate_document_produces_a_transcript_that_shares_no_addressing_with_the_shipped_one()
    {
        let shipped = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let alternate = ConfigContract::from_document(ALTERNATE).expect("the alternate document");
        assert_eq!(shipped.changes.len(), alternate.changes.len());

        let shared: Vec<&str> = alternate
            .changes
            .iter()
            .map(String::as_str)
            .filter(|record| shipped.changes.iter().any(|earlier| earlier == record))
            .collect();

        // The property the two documents exist to hold. A shared record naming
        // an identity or an address is precisely what would let a table built
        // from one of them satisfy the other's transcript.
        for record in &shared {
            for identifying in [" field=id ", " field=address ", " field=mac "] {
                assert!(
                    !record.contains(identifying),
                    "both documents produce {record:?}, so a table built from either satisfies \
                     both transcripts"
                );
            }
        }

        // And the set is closed, counted by what each shared record is about so
        // the documents' own values are not restated here.
        let about = |kind: &str| {
            let marker = format!(" object={kind} ");
            shared
                .iter()
                .filter(|record| record.contains(&marker))
                .count()
        };
        let rule_criteria = 2 * (11 - 1);
        assert_eq!(
            [
                about("interface"),
                about("neighbour"),
                about("rule"),
                about("management"),
            ],
            [0, 0, rule_criteria, 1],
            "a transcript both documents produce proves nothing"
        );
        assert_eq!(
            shared.len(),
            rule_criteria + 1,
            "a shared record about none of the four objects the documents name"
        );
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
    fn either_domains_block_may_lead_and_both_orders_are_the_same_boot() {
        // The defect this replaced: the merged stream was asserted as one total
        // order, so the transcript passed only if the publishing domain's
        // records reached the line before the forwarding domain's switch. The
        // console provides no such order — `ConsolePrinter::drain` rotates
        // which ring it serves first on every pass, which
        // `console::tests::the_rotation_serves_the_later_ring_first_when_its_turn_comes`
        // holds as a contract because it is what stops a flooding ring starving
        // another. A real boot took the other rotation
        // (`build/image/qemu-generation-swap.log` carries the forwarding
        // domain's two records ahead of all seventeen of the publisher's) and
        // was judged a failure with every record present and byte-correct.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        for leading in [Leading::Publisher, Leading::Forwarder] {
            let text = capture_with(&contract, leading);
            contract
                .judge(text.as_bytes(), log())
                .unwrap_or_else(|verdict| panic!("{leading:?} first is a passing boot: {verdict}"));
        }
    }

    #[test]
    fn a_publishers_record_out_of_seq_order_is_still_refused() {
        // What keeps the contract above from being a set comparison that any
        // permutation satisfies. The two blocks may interleave, but one ring
        // has one writer publishing in order, so a change record that reached
        // the line before the record published ahead of it did not come off
        // that ring in the order the domain wrote it.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let (earlier, later) = (&contract.changes[3], &contract.changes[4]);
        let text = capture(&contract).replace(
            &format!("{earlier}\r\n{later}\r\n"),
            &format!("{later}\r\n{earlier}\r\n"),
        );
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("two change records swapped");
        assert!(verdict.contains("seq=4"), "{verdict}");
        assert!(verdict.contains("seq=3"), "{verdict}");
        assert!(
            verdict.contains("which the domain published first"),
            "{verdict}"
        );
    }

    #[test]
    fn a_summary_ahead_of_the_changes_it_counts_is_still_refused() {
        // The other half of the publishing domain's chain: the summary is
        // written by the same call, after the last change record, so a capture
        // that carries it first describes a domain that counted a diff it had
        // not yet recorded.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        let committed = contract.committed().unwrap();
        let first = &contract.changes[0];
        let text = capture(&contract)
            .replace(&format!("{committed}\r\n"), "")
            .replace(
                &format!("{first}\r\n"),
                &format!("{committed}\r\n{first}\r\n"),
            );
        let verdict = contract
            .judge(text.as_bytes(), log())
            .expect_err("the summary ahead of the records it summarises");
        // The summary record itself, taken from the contract rather than spelled
        // out: it is what the verdict must name as having reached the line
        // first, and its change count is the document's to decide.
        assert!(verdict.contains(&committed), "{verdict}");
        assert!(
            verdict.contains("which the domain published first"),
            "{verdict}"
        );
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
        // Both halves of the set verdict: this document's records absent, the
        // other document's carried in their place.
        assert!(
            verdict.contains("did not carry the records this document describes"),
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
        // The verdict names the record itself, which is what an operator needs:
        // its index in a merged stream two rotations can order two ways is not.
        assert!(verdict.contains("absent"), "{verdict}");
        assert!(verdict.contains(&dropped), "{verdict}");
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
    fn a_boot_whose_console_said_nothing_at_all_is_refused() {
        // The defect `xtask release` now asserts against, reduced to what the
        // reader sees. A release image whose domains logged through a kernel
        // debug syscall the release kernel does not carry emits not one byte on
        // the serial line, while forwarding exactly as it should — so the only
        // thing that separates it from a healthy node is an empty capture, and
        // this is the reader that must refuse one.
        //
        // A boot that produced no serial output whatsoever, and one that
        // produced a kernel banner and no `LFW-` record, are the same verdict
        // here: neither carried the transcript.
        let contract = ConfigContract::from_document(SHIPPED).expect("the shipped document");
        for silent in [
            b"".as_slice(),
            b"Bootstrapping kernel\r\nAvailable phys memory regions: 1\r\n".as_slice(),
        ] {
            let verdict = contract
                .judge(silent, log())
                .expect_err("a boot whose console carried nothing");
            assert!(verdict.contains("appears 0 times"), "{verdict}");
            assert!(
                verdict.contains("never running the empty table"),
                "{verdict}"
            );
        }
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
        // the console contract gives a reader, so prose that quotes it is a record; the
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
        // One domain's whole record spliced into another's, and the interrupted
        // record's tail — which carries no marker of its own — on the next
        // line. No capture under build/image/ carries this shape now that the
        // port has a single writer; it is what captures carried before, and it
        // is what the contract still makes the reader's job to recover, so the
        // reader is held to the contract rather than to the console of the day.
        let capture = "LFW-PD domain=nic-driver staLFW-CFG generation=0 outcome=applied \
                       changes=0\r\nte=ready rx-posted=16\r\n";
        assert_eq!(
            config_records(capture),
            ["LFW-CFG generation=0 outcome=applied changes=0"]
        );
    }

    #[test]
    fn a_transcript_torn_the_way_an_unserialised_console_tore_it_is_still_judged() {
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
        // The switch record is absent, and the head fragment the tear left
        // behind is reported as a record nothing describes — never read as the
        // switch having happened.
        let (missing, carried) = verdict
            .split_once("carried this many times")
            .expect("the set verdict names what the channel did not carry");
        assert!(missing.contains(&switched), "{verdict}");
        assert!(
            carried.contains(&format!("{:?}", head.trim_end())),
            "{verdict}"
        );
    }

    #[test]
    fn a_document_the_validator_refuses_yields_no_contract_to_assert() {
        assert!(matches!(
            ConfigContract::from_document(b"<!DOCTYPE evil><configuration/>"),
            Err(ContractError::Refused(_))
        ));
        // A document naming no object at all is one no reader accepts: the
        // schema requires a `<management>` element, which is why
        // `ContractError::MovesNothing` is unreachable from a valid document and
        // is exercised against the model directly instead.
        assert!(matches!(
            ConfigContract::from_document(
                b"<configuration><interfaces/><neighbours/><rules/></configuration>"
            ),
            Err(ContractError::Refused(_))
        ));
        assert!(matches!(
            ConfigContract::from_model(&Model::EMPTY),
            Err(ContractError::MovesNothing)
        ));
    }

    #[test]
    fn every_refusal_reads_as_the_thing_that_is_wrong() {
        let rendered = [
            ContractError::Refused("doctype".to_owned()).to_string(),
            ContractError::MovesNothing.to_string(),
            ContractError::Unrenderable {
                event: "ConfigGeneration { generation: 3 }".to_owned(),
            }
            .to_string(),
        ];
        assert!(rendered[0].contains("doctype"));
        assert!(rendered[1].contains("empty configuration"));
        assert!(rendered[2].contains("generation: 3"));
    }

    /// The renderer is `lfw_log`'s own, so a grammar change lands here rather
    /// than leaving the expectation and the appliance describing the same
    /// commit in two different languages.
    #[test]
    fn a_record_is_rendered_by_the_grammar_the_domain_writes() {
        use lfw_log::{ChangeKind, Field, ObjectKind, Value};
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
