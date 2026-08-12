//! The metric catalogue, as the management server reads it.
//!
//! A metric snapshot the appliance writes into a recording is four hundred-odd
//! bare `u64`s: what each of them *means* is the series table this build
//! compiles in, and the server that turns them into rows has to hold the same
//! table. Two hand-kept copies of a four-hundred-entry table in two languages is
//! a drift with no failing test behind it, so there is one copy — this one,
//! generated from `lfw_metrics` and committed under `ctrld/priv/` — and this
//! check holds the committed file to what the code would generate now.
//!
//! **It is a comparison and never a write.** The gate is offline and its
//! container filesystem is read only, and a check that quietly regenerated its
//! own input would pass on a tree nobody had reviewed. Regeneration is a
//! deliberate act (`cargo run -p xtask -- metric-catalogue`), and this is what
//! makes forgetting it a failure rather than a silent divergence.
//!
//! The fingerprint travels in every snapshot and is compared by the server
//! before a single slot is mapped, so a *stale* catalogue on the server is
//! already safe — every snapshot it cannot map is refused whole rather than
//! misread. What this check buys is that it never has to be: the two move
//! together or the gate fails.
//!
//! # The protection-domain vocabulary crosses the same way
//!
//! A console line the appliance records carries the ring it was drained from as
//! one byte, and what that byte *means* is the same kind of build-time table: the
//! ten protection domains this system has, in discriminant order. It is ten
//! entries rather than four hundred, and it is generated here anyway — one
//! command, one check and one drift story is worth more than a short list being
//! easy to retype, and a server naming the wrong domain on a stored log line has
//! no fingerprint to catch it.

use std::{fmt::Write as _, fs, path::Path};

use lfw_log::Domain;
use lfw_metrics::{CATALOGUE_FINGERPRINT, SHARDS, SNAPSHOT_SLOTS};

use crate::util::Error;

/// Where the generated catalogue lives, relative to the repository root.
pub const CATALOGUE_PATH: &str = "ctrld/priv/metric_catalogue.json";

/// As [`CATALOGUE_PATH`], for the protection-domain vocabulary a recorded console
/// line's origin byte is read through.
pub const DOMAINS_PATH: &str = "ctrld/priv/log_domains.json";

/// The catalogue as JSON: the fingerprint both ends compare, the slot count, and
/// one entry per slot in the order a snapshot lays them out.
///
/// Written by hand rather than through a serialisation crate, because `xtask`
/// carries no JSON dependency and the shape is four fields. Every string that
/// reaches it comes from the catalogue's own `&'static str`s, which are
/// identifiers and label values in a closed alphabet — but the writer escapes
/// anyway, so a family whose help text one day carries a quote cannot produce a
/// file that will not parse.
#[must_use]
pub fn render() -> String {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(out, "  \"fingerprint\": {CATALOGUE_FINGERPRINT},");
    let _ = writeln!(out, "  \"slots\": {SNAPSHOT_SLOTS},");
    out.push_str("  \"series\": [\n");
    let mut first = true;
    for spec in &SHARDS {
        for series in spec.series {
            if !first {
                out.push_str(",\n");
            }
            first = false;
            let _ = write!(
                out,
                "    {{\"domain\": {}, \"family\": {}, \"labels\": {{",
                quoted(spec.domain),
                quoted(series.metric.name)
            );
            for (at, label) in series.labels.iter().enumerate() {
                if at > 0 {
                    out.push_str(", ");
                }
                let _ = write!(out, "{}: {}", quoted(label.name), quoted(label.value));
            }
            out.push_str("}}");
        }
    }
    out.push_str("\n  ]\n}\n");
    out
}

/// The protection-domain vocabulary as JSON: one token per discriminant, in
/// discriminant order, so a server indexes the array with the origin byte a
/// recorded console line carries.
#[must_use]
pub fn render_domains() -> String {
    let mut out = String::from("{\n  \"domains\": [\n");
    for (at, domain) in Domain::ALL.iter().enumerate() {
        if at > 0 {
            out.push_str(",\n");
        }
        let _ = write!(out, "    {}", quoted(domain.name()));
    }
    out.push_str("\n  ]\n}\n");
    out
}

fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other if (other as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", other as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Write both generated tables over their committed files. The one thing that
/// does.
pub fn write(repository_root: &Path) -> Result<(), Error> {
    let path = repository_root.join(CATALOGUE_PATH);
    fs::write(&path, render()).map_err(|error| Error::io("write", &path, error))?;
    let domains = repository_root.join(DOMAINS_PATH);
    fs::write(&domains, render_domains()).map_err(|error| Error::io("write", &domains, error))?;
    println!(
        "metric-catalogue: wrote {SNAPSHOT_SLOTS} series under fingerprint {CATALOGUE_FINGERPRINT} \
         to {CATALOGUE_PATH}, and {} protection domains to {DOMAINS_PATH}",
        Domain::ALL.len()
    );
    Ok(())
}

/// Hold the committed catalogue to what this build would generate.
pub fn check(repository_root: &Path) -> Result<(), Error> {
    let path = repository_root.join(CATALOGUE_PATH);
    let committed = fs::read_to_string(&path).map_err(|error| {
        Error::invalid(format!(
            "{CATALOGUE_PATH} is the catalogue the management server maps a metric snapshot \
             through and it could not be read ({error}). Generate it with `cargo run -p xtask -- \
             metric-catalogue`"
        ))
    })?;
    let owed = render();
    if committed == owed {
        println!(
            "metric-catalogue: {CATALOGUE_PATH} is the {SNAPSHOT_SLOTS} series this build \
             declares, under fingerprint {CATALOGUE_FINGERPRINT}"
        );
        return Ok(());
    }
    Err(Error::invalid(format!(
        "{CATALOGUE_PATH} is not what `lfw_metrics` declares. The appliance stamps every metric \
         snapshot with fingerprint {CATALOGUE_FINGERPRINT} over {SNAPSHOT_SLOTS} series, and a \
         server holding another table refuses every snapshot it receives rather than mapping one \
         slot wrongly — so this is a surface that stops working, not one that goes quietly wrong. \
         Regenerate it with `cargo run -p xtask -- metric-catalogue`"
    )))
}

/// Hold the committed protection-domain vocabulary to this build's, on
/// [`check`]'s terms.
///
/// Unlike a snapshot, a recorded console line carries no fingerprint: its origin
/// is a bare index. So a stale table here is not safe the way a stale catalogue
/// is — it names the wrong domain on a stored log line and nothing downstream can
/// tell. This check is the whole of what keeps the two in step.
pub fn check_domains(repository_root: &Path) -> Result<(), Error> {
    let path = repository_root.join(DOMAINS_PATH);
    let committed = fs::read_to_string(&path).map_err(|error| {
        Error::invalid(format!(
            "{DOMAINS_PATH} is the vocabulary the management server reads a recorded console \
             line's origin byte through and it could not be read ({error}). Generate it with \
             `cargo run -p xtask -- metric-catalogue`"
        ))
    })?;
    if committed == render_domains() {
        println!(
            "metric-catalogue: {DOMAINS_PATH} is the {} protection domains this build declares",
            Domain::ALL.len()
        );
        return Ok(());
    }
    Err(Error::invalid(format!(
        "{DOMAINS_PATH} is not the vocabulary `lfw_log::Domain` declares. A recorded console line \
         carries its origin as a bare index with no fingerprint in front of it, so a stale table \
         names the wrong protection domain on a stored log line and nothing downstream can tell. \
         Regenerate it with `cargo run -p xtask -- metric-catalogue`"
    )))
}

#[cfg(test)]
mod tests;
