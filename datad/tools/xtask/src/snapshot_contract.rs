//! What a booted appliance's metric readings must agree with.
//!
//! The recorder writes the whole metric surface into the connection history as a
//! PEN-tagged Custom Block, and the same boot answers `GET /metrics` out of the
//! same shards. Those are two independent renderings of one set of counters, so
//! a defect that hides inside either shows up as a disagreement between them —
//! which is the property this holds, on the terms every other surface in this
//! gate is held to.
//!
//! # Why the comparison is an inequality and an equality both
//!
//! The two are not read at the same instant: a reading is published, framed and
//! flushed to a medium, and the scrape happens afterwards. So for a **counter**
//! the only sound relation is that the recording's value does not exceed the
//! scrape's — a counter only rises, and a recording that claimed more than the
//! appliance has counted would be a recording describing work that never
//! happened, which is exactly the direction worth catching.
//!
//! A **constant** is the other half and the sharper one: the medium's capacity
//! in sectors is a device fact that does not move between the two readings, so
//! it must be **equal**. That is what proves the slots are being read at the
//! right offsets rather than merely being plausible numbers — an off-by-one in
//! the catalogue would leave every counter still under its scrape and would move
//! this one.

use std::fmt::Write as _;

use lfw_metrics::{SHARDS, Series};

use crate::recording_contract::Snapshot;

/// One slot's identity, as a caller names it: the shard's domain, the family,
/// and the labels that pick the series out within it.
///
/// Borrowed rather than `'static`, because the labels a caller names are not
/// all fixed at compile time: a drop reason comes out of this build's
/// vocabulary and a rule id out of the document under test, and a contract that
/// could only name a literal would be one that stopped short of exactly the
/// series a configuration decides.
#[derive(Debug)]
pub struct SeriesAt<'a> {
    pub domain: &'a str,
    pub family: &'a str,
    pub labels: &'a [(&'a str, &'a str)],
}

/// Every series of one family, wherever the catalogue puts it and whatever else
/// labels it — the reading's counterpart to an exposition summed over its
/// pipelines.
///
/// Several families carry one series per pipeline, and what a recording is held
/// to is the total across them: a per-pipeline slot compared alone would pass an
/// appliance that counted one direction twice and the other never. So the shape
/// of the comparison follows the shape of the number, and a family with no slot
/// at all is `None` rather than a zero nothing distinguishes from an unlabelled
/// silence.
#[must_use]
pub fn total_of(reading: &Snapshot, family: &str, labels: &[(&str, &str)]) -> Option<u64> {
    let mut base = 0;
    let mut total = None;
    for spec in &SHARDS {
        for (at, series) in spec.series.iter().enumerate() {
            if series.metric.name == family
                && labels.iter().all(|(name, value)| {
                    series
                        .labels
                        .iter()
                        .any(|held| held.name == *name && held.value == *value)
                })
                && let Some(held) = reading.slot(base + at)
            {
                total = Some(total.unwrap_or(0_u64).saturating_add(held));
            }
        }
        base += spec.series.len();
    }
    total
}

/// Where a named series sits in a reading.
///
/// Read out of `lfw_metrics::SHARDS` because the catalogue **is** the mapping:
/// a harness that restated four hundred positions would be restating the thing
/// under test. What the harness does not take from the appliance is how a
/// reading is *framed* — that is read by the offsets the contract page states
/// (`crate::recording_contract`), which is the half a management server writes
/// from the page rather than from this code.
///
/// # Errors
/// A name no shard declares, which is a harness naming a series that has moved.
pub fn slot_of(wanted: &SeriesAt) -> Result<usize, String> {
    let mut base = 0;
    for spec in &SHARDS {
        if spec.domain == wanted.domain {
            for (at, series) in spec.series.iter().enumerate() {
                if matches(series, wanted) {
                    return Ok(base + at);
                }
            }
        }
        base += spec.series.len();
    }
    Err(format!(
        "no series {}{:?} in the {} shard, so this contract names one the catalogue has moved",
        wanted.family, wanted.labels, wanted.domain
    ))
}

fn matches(series: &Series, wanted: &SeriesAt) -> bool {
    series.metric.name == wanted.family
        && series.labels.len() == wanted.labels.len()
        && series
            .labels
            .iter()
            .zip(wanted.labels)
            .all(|(held, (name, value))| held.name == *name && held.value == *value)
}

/// One agreement the reading and the scrape must satisfy.
#[derive(Debug)]
pub struct Agreed<'a> {
    pub series: SeriesAt<'a>,
    /// Whether the reading is the sum of every series of the family the labels
    /// select, rather than one slot. `true` for a family the exposition itself
    /// sums over its pipelines, so the two sides are the same quantity.
    pub summed: bool,
    /// What the scrape reported for it.
    pub scraped: u64,
    /// Whether the two must be equal, or whether the reading may only be no
    /// larger — see the module header.
    pub constant: bool,
}

/// What the comparison established, for a run log to carry.
#[derive(Debug)]
pub struct Agreement {
    pub lines: Vec<String>,
}

impl Agreement {
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut out = String::from(
            "  the metric readings the connection history carries, held to the same boot's scrape:",
        );
        for line in &self.lines {
            out.push('\n');
            out.push_str(line);
        }
        out
    }
}

/// Hold every reading a recording carries to the boot's own scrape.
///
/// # Errors
/// A recording with no reading at all, a reading whose slot count is not the
/// catalogue's, or any named series where the two disagree.
pub fn judge(
    target: &str,
    snapshots: &[Snapshot],
    agreed: &[Agreed],
    fingerprint: u32,
) -> Result<Agreement, String> {
    let Some(last) = snapshots.last() else {
        return Err(format!(
            "GET {target} holds no metric reading at all, so the recorder never framed one and \
             the management server would have nothing to store"
        ));
    };
    for (at, reading) in snapshots.iter().enumerate() {
        if reading.fingerprint != fingerprint {
            return Err(format!(
                "GET {target} holds a reading (the {} of {}) stamped with catalogue {:#010x} and \
                 this build declares {fingerprint:#010x}, so a management server would refuse it \
                 whole",
                at + 1,
                snapshots.len(),
                reading.fingerprint
            ));
        }
        if reading.values.len() != lfw_metrics::SNAPSHOT_SLOTS {
            return Err(format!(
                "GET {target} holds a reading of {} slots and the catalogue declares {}",
                reading.values.len(),
                lfw_metrics::SNAPSHOT_SLOTS
            ));
        }
    }

    let mut lines = vec![format!(
        "    {target}: {} reading(s), {} slots each, catalogue {fingerprint:#010x}",
        snapshots.len(),
        lfw_metrics::SNAPSHOT_SLOTS
    )];
    for want in agreed {
        let (at, held) = if want.summed {
            let total = total_of(last, want.series.family, want.series.labels).ok_or_else(|| {
                format!(
                    "GET {target}'s last reading carries no slot of {} under {:?} at all, so the \
                     catalogue has moved the family this contract names",
                    want.series.family, want.series.labels
                )
            })?;
            (None, total)
        } else {
            let at = slot_of(&want.series)?;
            let held = last.slot(at).ok_or_else(|| {
                format!(
                    "GET {target}'s last reading has no slot {at}, which is where {} sits",
                    want.series.family
                )
            })?;
            (Some(at), held)
        };
        let ok = if want.constant {
            held == want.scraped
        } else {
            held <= want.scraped
        };
        if !ok {
            let relation = if want.constant { "equal" } else { "at most" };
            return Err(format!(
                "GET {target}'s last reading puts {} of the {} domain at {held}, and the same \
                 boot's scrape reports {}; the recording must be {relation} the scrape — a \
                 recording claiming more than the appliance counted describes work that never \
                 happened",
                want.series.family, want.series.domain, want.scraped
            ));
        }
        let mut line = String::new();
        let _ = write!(
            line,
            "    {}: {}{{domain=\"{}\"{}}} reads {held} in the recording and {} in the \
             scrape ({})",
            match at {
                Some(at) => format!("slot {at}"),
                None => format!("every slot of the family under {:?}", want.series.labels),
            },
            want.series.family,
            want.series.domain,
            want.series
                .labels
                .iter()
                .map(|(name, value)| format!(",{name}=\"{value}\""))
                .collect::<String>(),
            want.scraped,
            if want.constant {
                "a constant, so equal"
            } else {
                "a counter, so no larger"
            }
        );
        lines.push(line);
    }
    Ok(Agreement { lines })
}

#[cfg(test)]
mod tests;
