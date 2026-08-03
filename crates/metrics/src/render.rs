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
//! all.
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

use wire::CheckedIdentifier;

use crate::catalog::{
    ALL_METRICS, FORWARDER_SHARD, INTERFACE_INFO, Label, Metric, RULE_HITS, SHARD_COUNT, SHARDS,
    Series,
};
use crate::interfaces::{
    InterfaceInfo, InterfaceInventory, MANAGEMENT_PORT_DOMAIN, MAX_INTERFACE_SERIES, PORT_DOMAINS,
    Role,
};
use crate::rules::{MAX_RULE_SERIES, RuleInventory};
use crate::sample::RULE_HITS_BASE;
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

/// The value every info series carries — a constant, not a measurement.
const INFO_VALUE: &[u8] = b"1";

/// One lower-case hexadecimal digit of `nibble`'s low four bits.
///
/// Arithmetic rather than an index into a table: the value is bounded by the mask
/// and the sums cannot leave a `u8`, so there is no index to be out of range and
/// no addition to overflow.
const fn hex_digit(nibble: u8) -> u8 {
    let low = nibble & 0x0f;
    if low < 10 {
        b'0'.saturating_add(low)
    } else {
        b'a'.saturating_add(low - 10)
    }
}

/// Bytes `255.255.255.255` takes — the longest dotted quad.
const MAX_ADDRESS_LEN: usize = 15;

/// Bytes `ff:ff:ff:ff:ff:ff` takes; a MAC is always written in full.
const MAC_LEN: usize = 17;

/// Digits a prefix length takes. Three rather than two, a validated document
/// refusing anything past 32 while this crate's own type takes a `u8`: the bound
/// is what the *renderer* can be handed.
const MAX_PREFIX_DIGITS: usize = 3;

/// One reading of every shard, taken before anything is rendered.
///
/// Taken whole so the exposition is one pass over one set of numbers rather than
/// a re-read per metric family: a family loop that read the shards again each
/// time would let a counter appear to move backwards *within* a single scrape,
/// which is the one shape of inconsistency a reader cannot explain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    values: [[u64; STATS_SLOTS]; SHARD_COUNT],
    /// The configured interfaces, which come from the committed configuration
    /// and not from a shard: no protection domain counts them, and their
    /// identity is text rather than a number. Empty is the honest state of a node
    /// running generation 0.
    interfaces: InterfaceInventory,
    /// The rules the running policy declares, on the same terms. Only the
    /// *identity* comes from the configuration here — every hit count is in the
    /// forwarding domain's shard above, joined to an id by position.
    rules: RuleInventory,
}

impl Snapshot {
    /// A snapshot of stated values, for a test or a fuzz harness that has no
    /// shared region.
    #[must_use]
    pub const fn new(values: [[u64; STATS_SLOTS]; SHARD_COUNT]) -> Self {
        Self {
            values,
            interfaces: InterfaceInventory::EMPTY,
            rules: RuleInventory::EMPTY,
        }
    }

    /// The same counters, reporting the interfaces a configuration named.
    ///
    /// Separate from the constructors because the two halves have two sources: a
    /// caller reads the shards whenever it likes and learns of a configuration
    /// only when one is committed.
    #[must_use]
    pub const fn with_interfaces(self, interfaces: InterfaceInventory) -> Self {
        Self { interfaces, ..self }
    }

    /// The same counters, reporting the rules a configuration declared — which is
    /// what turns the per-rule block of the forwarder's shard into named series.
    #[must_use]
    pub const fn with_rules(self, rules: RuleInventory) -> Self {
        Self { rules, ..self }
    }

    /// Read every shard once, in [`SHARDS`] order.
    #[must_use]
    pub fn read(shards: [&StatsShard; SHARD_COUNT]) -> Self {
        let mut values = [[0u64; STATS_SLOTS]; SHARD_COUNT];
        for (target, shard) in values.iter_mut().zip(shards) {
            *target = shard.sample();
        }
        Self {
            values,
            interfaces: InterfaceInventory::EMPTY,
            rules: RuleInventory::EMPTY,
        }
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
                // panic: a path a peer's region reaches admits none.
                writer.number(values.get(slot).copied().unwrap_or(0))?;
                writer.bytes(b"\n")?;
            }
        }
        // Two families' samples are not in any shard's table, so the loop above
        // contributes nothing to either. Pointer equality rather than a name
        // comparison: `ALL_METRICS` holds a reference to the one declaration.
        if core::ptr::eq(metric, &INTERFACE_INFO) {
            for info in self.interfaces.entries() {
                Self::render_interface(metric, info, writer)?;
            }
        }
        if core::ptr::eq(metric, &RULE_HITS) {
            for (position, id) in self.rules.entries() {
                self.render_rule(metric, position, id, writer)?;
            }
        }
        Ok(())
    }

    /// One interface's series, whose labels are the whole of what it says.
    fn render_interface(
        metric: &Metric,
        info: &InterfaceInfo,
        writer: &mut Writer<'_>,
    ) -> Result<(), Full> {
        writer.bytes(metric.name.as_bytes())?;
        writer.bytes(b"{")?;
        writer.label(&Label::new("domain", info.domain()))?;
        writer.bytes(b",interface=\"")?;
        // A `CheckedIdentifier` is proof of `[a-z0-9-]{1,16}`, so no byte of it can
        // close the quoted value early (`wire::ConfigImage::check`).
        writer.bytes(info.interface().as_bytes())?;
        writer.bytes(b"\",")?;
        writer.label(&Label::new("role", info.role().token()))?;
        writer.bytes(b",address=\"")?;
        writer.address(info.address())?;
        writer.bytes(b"\",prefix_length=\"")?;
        writer.number(u64::from(info.prefix_length()))?;
        writer.bytes(b"\",mac=\"")?;
        writer.mac(info.mac())?;
        writer.bytes(b"\"} ")?;
        writer.bytes(INFO_VALUE)?;
        writer.bytes(b"\n")
    }

    /// One rule's hit counter: the id the document gave it, and the count the
    /// forwarding domain wrote at that rule's position.
    ///
    /// The count is read out of the shard rather than carried in the inventory,
    /// which is the whole of the join: a number only the forwarder could have
    /// stored, under a name only the configuration could have chosen. A slot past
    /// the shard is unreachable — `RULE_HITS_BASE + MAX_RULE_SERIES` is asserted
    /// to fit `STATS_SLOTS` — and reads as zero rather than as a panic, on the
    /// terms every other slot read here does.
    fn render_rule(
        &self,
        metric: &Metric,
        position: usize,
        id: CheckedIdentifier,
        writer: &mut Writer<'_>,
    ) -> Result<(), Full> {
        let hits = RULE_HITS_BASE
            .checked_add(position)
            .and_then(|slot| self.values.get(FORWARDER_SHARD)?.get(slot).copied())
            .unwrap_or(0);
        writer.bytes(metric.name.as_bytes())?;
        writer.bytes(b"{")?;
        writer.label(&Label::new("domain", SHARDS[FORWARDER_SHARD].domain))?;
        writer.bytes(b",rule=\"")?;
        // A `CheckedIdentifier` is proof of `[a-z0-9-]{1,16}`, so no byte of it
        // can close the quoted value early (`wire::ConfigImage::check`).
        writer.bytes(id.as_bytes())?;
        writer.bytes(b"\"} ")?;
        writer.number(hits)?;
        writer.bytes(b"\n")
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

    /// A dotted quad, as an address appears in a configuration document.
    fn address(&mut self, octets: [u8; 4]) -> Result<(), Full> {
        for (index, octet) in octets.into_iter().enumerate() {
            if index > 0 {
                self.bytes(b".")?;
            }
            self.number(u64::from(octet))?;
        }
        Ok(())
    }

    /// A MAC in the lower-case colon-separated form every other surface of this
    /// appliance writes one in, both nibbles always — one alphabet on every surface.
    fn mac(&mut self, mac: [u8; 6]) -> Result<(), Full> {
        for (index, octet) in mac.into_iter().enumerate() {
            if index > 0 {
                self.bytes(b":")?;
            }
            self.bytes(&[hex_digit(octet >> 4), hex_digit(octet)])?;
        }
        Ok(())
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
    total + MAX_INTERFACE_SERIES * info_line_len() + MAX_RULE_SERIES * rule_line_len()
}

/// The longest per-rule line, and one a real policy can actually produce: a rule
/// named at the full identifier width, hit `u64::MAX` times.
///
/// Reachable rather than merely safe, as the info bound is: the id length is the
/// configuration reader's own bound, so a document can name a rule that wide.
pub(crate) const fn rule_line_len() -> usize {
    // `{`, the two labels with their separating comma, `}`, the space, the digits
    // and the newline.
    RULE_HITS.name.len()
        + 1
        + label_len("domain", SHARDS[FORWARDER_SHARD].domain)
        + 1
        + label_len_of("rule", wire::LOG_IDENTIFIER_BYTES)
        + 1
        + 1
        + MAX_DIGITS
        + 1
}

/// The longest info series line, and one a full inventory can actually be made of
/// — which keeps the declared bound reachable, and so testable against a real
/// render rather than merely safe.
///
/// The roles are bounded separately because a role fixes its own `interface`
/// label: dataplane carries an id of up to [`wire::LOG_IDENTIFIER_BYTES`] bytes
/// beside the shorter token, management the fixed word beside the longer one.
/// Maximising each label independently would bound a line no inventory can hold.
pub(crate) const fn info_line_len() -> usize {
    let dataplane = info_line_len_for(Role::Dataplane, wire::LOG_IDENTIFIER_BYTES);
    let management = info_line_len_for(Role::Management, wire::CheckedIdentifier::MANAGEMENT.len());
    if dataplane > management {
        dataplane
    } else {
        management
    }
}

/// One line of a stated role, with an `interface` label of `id_len` bytes and
/// every other label at its widest.
const fn info_line_len_for(role: Role, id_len: usize) -> usize {
    // `{`, the six labels with their separating commas, `}`, the space, the
    // constant value and the newline.
    INTERFACE_INFO.name.len()
        + 1
        + label_len_of("domain", max_domain_len())
        + 1
        + label_len_of("interface", id_len)
        + 1
        + label_len_of("role", role.token().len())
        + 1
        + label_len_of("address", MAX_ADDRESS_LEN)
        + 1
        + label_len_of("prefix_length", MAX_PREFIX_DIGITS)
        + 1
        + label_len_of("mac", MAC_LEN)
        + 1
        + 1
        + INFO_VALUE.len()
        + 1
}

/// The longest `domain` value an info series can carry, over the driver domains
/// alone: no other domain drives a port.
const fn max_domain_len() -> usize {
    let mut longest = MANAGEMENT_PORT_DOMAIN.len();
    let mut port = 0;
    while port < PORT_DOMAINS.len() {
        if PORT_DOMAINS[port].len() > longest {
            longest = PORT_DOMAINS[port].len();
        }
        port += 1;
    }
    longest
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
    label_len_of(name, value.len())
}

/// [`label_len`] for a value whose width is known and whose bytes are not.
pub(crate) const fn label_len_of(name: &str, value_len: usize) -> usize {
    name.len() + 3 + value_len
}
