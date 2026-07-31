//! Turning a set of shards into Prometheus exposition text.
//!
//! # Total, allocator-free, and refusing rather than truncating
//!
//! Every byte written here ends up on a socket the management-plane attacker
//! opened, and every number written comes out of a region a peer domain owns, so
//! [`Snapshot::render`] is total over both: any `u64` renders, any output length
//! is answered, and there is no path that panics, indexes or allocates. When the
//! caller's storage is too small the answer is [`RenderError::OutOfSpace`] and
//! **nothing partial is claimed** — a truncated exposition is one a scraper
//! parses happily and reads short values from, which is worse than no scrape at
//! all (ENG-12).
//!
//! [`MAX_EXPOSITION_LEN`] makes that refusal unreachable for the appliance's own
//! staging buffer: it is the exact worst case of the catalogue, computed at
//! build time, so the buffer is sized by the tables rather than by a guess.
//!
//! # Why families are the outer loop
//!
//! The exposition format asks for every sample of a metric family to arrive as
//! one group, under one `# HELP`/`# TYPE` pair. A family's samples are spread
//! across up to eight shards — `librefirewall_log_records_dropped_total` has one
//! per protection domain — so the loop walks [`ALL_METRICS`] outermost and the
//! shards within it. That costs a scan of every shard per family and buys an
//! output a strict parser accepts.

use crate::catalog::{ALL_METRICS, Label, Metric, SHARD_COUNT, SHARDS, Series};
use crate::{STATS_SLOTS, StatsShard};

/// Why an exposition was not written.
///
/// One variant, because there is one thing that can go wrong: the caller's
/// storage. Every other input — the counter values — is a `u64` this renders
/// whatever it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// The output buffer is shorter than the exposition. Nothing was written
    /// that a caller may send.
    OutOfSpace {
        /// What the caller offered.
        capacity: usize,
    },
}

/// Digits `u64::MAX` takes, which is what a slot contributes to the worst case.
const MAX_DIGITS: usize = 20;

/// One reading of every shard, taken before anything is rendered.
///
/// Taken whole so the exposition is one pass over one set of numbers rather than
/// a re-read per metric family: a family loop that read the shards again each
/// time would let a counter appear to move backwards *within* a single scrape,
/// which is the one shape of inconsistency a reader cannot explain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    values: [[u64; STATS_SLOTS]; SHARD_COUNT],
}

impl Snapshot {
    /// A snapshot of stated values, for a test or a fuzz harness that has no
    /// shared region.
    #[must_use]
    pub const fn new(values: [[u64; STATS_SLOTS]; SHARD_COUNT]) -> Self {
        Self { values }
    }

    /// Read every shard once, in [`SHARDS`] order.
    #[must_use]
    pub fn read(shards: [&StatsShard; SHARD_COUNT]) -> Self {
        let mut values = [[0u64; STATS_SLOTS]; SHARD_COUNT];
        for (target, shard) in values.iter_mut().zip(shards) {
            *target = shard.sample();
        }
        Self { values }
    }

    /// Write the whole exposition into `out`, answering its length.
    ///
    /// # Errors
    /// [`RenderError::OutOfSpace`] when `out` is shorter than the exposition. A
    /// buffer of at least [`MAX_EXPOSITION_LEN`] bytes can never provoke it.
    pub fn render(&self, out: &mut [u8]) -> Result<usize, RenderError> {
        let capacity = out.len();
        let mut writer = Writer { out, at: 0 };
        for metric in ALL_METRICS {
            if self.render_family(metric, &mut writer).is_err() {
                return Err(RenderError::OutOfSpace { capacity });
            }
        }
        Ok(writer.at)
    }

    /// One family: its two comment lines, then every series of it any shard
    /// holds.
    fn render_family(&self, metric: &Metric, writer: &mut Writer<'_>) -> Result<(), Full> {
        writer.bytes(b"# HELP ")?;
        writer.bytes(metric.name.as_bytes())?;
        writer.bytes(b" ")?;
        writer.bytes(metric.help.as_bytes())?;
        writer.bytes(b"\n# TYPE ")?;
        writer.bytes(metric.name.as_bytes())?;
        writer.bytes(b" ")?;
        writer.bytes(metric.kind.token().as_bytes())?;
        writer.bytes(b"\n")?;

        for (spec, values) in SHARDS.iter().zip(&self.values) {
            for (slot, series) in spec.series.iter().enumerate() {
                if series.metric.name != metric.name {
                    continue;
                }
                writer.bytes(metric.name.as_bytes())?;
                writer.bytes(b"{")?;
                writer.label(&Label::new("domain", spec.domain))?;
                for label in series.labels {
                    writer.bytes(b",")?;
                    writer.label(label)?;
                }
                writer.bytes(b"} ")?;
                // A slot past the shard is unreachable — every table is asserted
                // to fit `STATS_SLOTS` — and reads as zero rather than as a
                // panic, ENG-5 admitting none on a path a peer's region reaches.
                writer.number(values.get(slot).copied().unwrap_or(0))?;
                writer.bytes(b"\n")?;
            }
        }
        Ok(())
    }
}

/// The output ran out. Private, because a caller is told which buffer was too
/// small rather than which byte did not fit.
struct Full;

/// A bounded cursor over the caller's storage.
struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Full> {
        let end = self.at.checked_add(bytes.len()).ok_or(Full)?;
        let target = self.out.get_mut(self.at..end).ok_or(Full)?;
        target.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    fn label(&mut self, label: &Label) -> Result<(), Full> {
        self.bytes(label.name.as_bytes())?;
        self.bytes(b"=\"")?;
        self.bytes(label.value.as_bytes())?;
        self.bytes(b"\"")
    }

    /// A decimal `u64`, formatted into a fixed array back to front so no
    /// allocator and no `core::fmt` machinery is involved.
    fn number(&mut self, value: u64) -> Result<(), Full> {
        let mut digits = [b'0'; MAX_DIGITS];
        let mut at = MAX_DIGITS;
        let mut rest = value;
        loop {
            at = at.checked_sub(1).ok_or(Full)?;
            if let Some(digit) = digits.get_mut(at) {
                *digit = b'0'.saturating_add((rest % 10) as u8);
            }
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        self.bytes(digits.get(at..).unwrap_or_default())
    }
}

/// The exact length of the longest exposition this catalogue can produce: every
/// family's two comment lines, plus every series of every shard with a
/// twenty-digit value.
///
/// Computed from the tables rather than measured from a run, so the staging
/// buffer a protection domain reserves is sized by the metrics that exist and a
/// new one cannot quietly outgrow it — the assertion that binds the two lives at
/// the buffer (`lfw_ip_endpoint::http`).
pub const MAX_EXPOSITION_LEN: usize = exposition_bound();

pub(crate) const fn exposition_bound() -> usize {
    let mut total = 0;
    let mut index = 0;
    while index < ALL_METRICS.len() {
        total += family_header_len(ALL_METRICS[index]);
        index += 1;
    }
    let mut shard = 0;
    while shard < SHARD_COUNT {
        let spec = &SHARDS[shard];
        let mut series = 0;
        while series < spec.series.len() {
            total += series_line_len(&spec.series[series], spec.domain);
            series += 1;
        }
        shard += 1;
    }
    total
}

/// `# HELP <name> <help>\n# TYPE <name> <kind>\n`.
pub(crate) const fn family_header_len(metric: &Metric) -> usize {
    let help = 7 + metric.name.len() + 1 + metric.help.len() + 1;
    let kind = 7 + metric.name.len() + 1 + metric.kind.token().len() + 1;
    help + kind
}

/// `<name>{domain="<d>"[,<k>="<v>"]…} <value>\n`.
pub(crate) const fn series_line_len(series: &Series, domain: &str) -> usize {
    // `{`, `domain="…"`, `}`, the space, the digits and the newline.
    let mut len = series.metric.name.len() + 1 + label_len("domain", domain) + 1;
    let mut index = 0;
    while index < series.labels.len() {
        let label = &series.labels[index];
        len += 1 + label_len(label.name, label.value);
        index += 1;
    }
    len + 1 + MAX_DIGITS + 1
}

/// `<name>="<value>"`.
pub(crate) const fn label_len(name: &str, value: &str) -> usize {
    name.len() + 3 + value.len()
}
