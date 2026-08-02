//! The comment and `unsafe` ratchets: recorded budgets that the gate only
//! ever lets fall.
//!
//! Both budgets are of the same shape. Prose is a liability — nothing fails
//! when a comment becomes false — so the comment-line ratio of a production
//! file may shrink but never grow. Every `unsafe` block obliges a safety
//! claim the compiler cannot check, so the per-crate `unsafe` count may
//! shrink but never grow. Neither is a threshold anybody can
//! pick a defensible number for; both are *ratchets* against a recorded state,
//! and this module is that recording plus the comparison.
//!
//! # Why this reads Rust rather than grepping it
//!
//! A ratchet that mis-measures is worse than none: it reports a number nobody
//! can act on and it fails on edits that changed nothing. Three constructs in
//! this very workspace defeat the obvious line-prefix approach, and each of
//! them is the *normal* way to write the thing it expresses:
//!
//! * `crates/queue/src/lib.rs` documents the rule against an ``unsafe impl``
//!   resting on an unkeepable promise — inside a `//!` doc comment. A grep for
//!   `unsafe impl` counts the sentence warning against one.
//! * A crate root here declares a `#[cfg(test)] mod NAME;` near the top of a
//!   file whose production code runs on for another thousand lines.
//!   "Everything after the first `#[cfg(test)]` is test code" would discard
//!   almost all of it — the ratchet would defend the header and nothing else.
//! * A `//` inside a string literal is a comment to a prefix match and to
//!   nothing else.
//!
//! So the scanner is a real (small) Rust lexer: it tracks comments, strings,
//! raw strings, char literals against lifetimes, attributes, and brace depth,
//! and it classifies only what it is actually looking at. It is not a parser
//! and does not need to be — it needs to know *which lexical state a byte is
//! in*, which is exactly what separates a comment from a sentence about one.
//!
//! # Loud on anything it does not understand
//!
//! Every construct the scanner cannot classify is an error that fails the
//! gate, never a value quietly left out of a count. An `unsafe` keyword in
//! a form this module does not know how to count, a `cfg` gate mentioning
//! `test` in a shape other than the exact `#[cfg(test)]`, an unterminated
//! block comment, a file recorded in the baseline that no longer exists — all
//! of them stop the gate and name themselves. A budget check that silently
//! measures less than it claims is the defect class the whole ratchet exists
//! to prevent.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

/// The recorded budgets, relative to the workspace root.
pub(crate) const BASELINE: &str = "tools/xtask/budgets.toml";

/// The trees whose files and crates are measured. `tools/` is deliberately
/// absent: `xtask` is build orchestration that never runs on a deployed
/// appliance, the same reason it is outside the coverage floor, and a ratchet
/// on the orchestrator's own prose would defend nothing about
/// the product.
const MEASURED_TREES: &[&str] = &["crates", "pds"];

/// Path components that mark a file as harness rather than product. A criterion
/// bench and an integration-test binary are neither shipped nor part of the
/// documentation surface the comment budget constrains.
const HARNESS_DIRS: &[&str] = &["benches", "tests", "examples"];

/// Decimal places a recorded ratio is stored with. Four keeps the file
/// diffable and is finer than any single comment line moves the ratio in a file
/// of plausible size.
const RATIO_DECIMALS: usize = 4;

/// How far a measured ratio may exceed its recorded value before the gate
/// fails: one unit in the last recorded place, which absorbs the rounding of
/// [`RATIO_DECIMALS`] and nothing more. A single added comment line moves a
/// 5000-line file by 0.0002 — twice this — so the tolerance cannot swallow a
/// real increase in any file this workspace will hold.
const RATIO_EPSILON: f64 = 1e-4;

/// How to re-record after a deliberate reduction. Named once and quoted in
/// every failure, because a ratchet the author cannot reset is a ratchet that
/// gets bypassed.
const HOW_TO_RERECORD: &str = "re-record with `LIBREFIREWALL_BUDGETS_UPDATE=1 cargo test -p xtask update_the_recorded_budgets`, \
     and state in the commit message why the budget moved";

/// What the `unsafe` budget counts, kept as three kinds rather than one so a
/// failure can tell the author which construct to remove: they are not
/// interchangeable, and the work to delete one is not the work to delete
/// another.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum UnsafeKind {
    /// An `unsafe { … }` expression block.
    Block,
    /// An `unsafe fn` declaration — a caller obligation across the boundary.
    Function,
    /// An `unsafe impl` — a promise about a type the compiler cannot check.
    Implementation,
}

impl UnsafeKind {
    /// The baseline section this kind is recorded under.
    fn section(self) -> &'static str {
        match self {
            Self::Block => "unsafe-blocks",
            Self::Function => "unsafe-fns",
            Self::Implementation => "unsafe-impls",
        }
    }

    /// What the author has to delete to bring this count down, spelled out in
    /// the failure so the number is actionable rather than merely accusing.
    fn what_it_counts(self) -> &'static str {
        match self {
            Self::Block => "`unsafe { … }` blocks",
            Self::Function => "`unsafe fn` declarations",
            Self::Implementation => "`unsafe impl` items",
        }
    }

    /// Every kind, in the order they are written to the baseline.
    fn all() -> [Self; 3] {
        [Self::Block, Self::Function, Self::Implementation]
    }
}

/// One production file's comment budget.
#[derive(Clone, Copy, PartialEq, Debug)]
struct CommentBudget {
    /// Production lines whose first non-whitespace byte opens or continues a
    /// comment.
    comment_lines: usize,
    /// Lines outside every `#[cfg(test)]` item, blank lines included — the
    /// denominator the comment ratio is expressed against.
    production_lines: usize,
}

impl CommentBudget {
    /// The recorded quantity. A file with no production lines at all is 0.0
    /// rather than a division by zero; it can only arise from a file that is
    /// entirely test-gated, which the discovery step has already dropped.
    fn ratio(self) -> f64 {
        if self.production_lines == 0 {
            0.0
        } else {
            self.comment_lines as f64 / self.production_lines as f64
        }
    }

    /// The ratio at recorded precision, so what is compared is what is written.
    fn recorded_ratio(self) -> f64 {
        let scale = 10_f64.powi(
            i32::try_from(RATIO_DECIMALS).expect("RATIO_DECIMALS is a single-digit constant"),
        );
        (self.ratio() * scale).round() / scale
    }
}

/// Everything measured from the tree in one pass.
#[derive(Default, Debug)]
struct Measured {
    /// Per production file, keyed by its workspace-relative path.
    files: BTreeMap<String, CommentBudget>,
    /// Per crate directory, per kind. Every crate appears under every kind,
    /// including with a zero: recording an absence is what makes the *first*
    /// `unsafe` in a crate that has none fail the gate — keeping `unsafe`
    /// confined to the crates that need it, stated as a number.
    unsafes: BTreeMap<(UnsafeKind, String), usize>,
}

/// The recorded budgets, in the same shape as [`Measured`].
#[derive(Default, Debug)]
struct Baseline {
    ratios: BTreeMap<String, f64>,
    unsafes: BTreeMap<(UnsafeKind, String), usize>,
}

/// Enforce both ratchets against the recorded baseline.
///
/// Every finding is collected before anything is reported: a documentation
/// reduction touches many files at once, and failing on the first one would
/// make the author rerun the gate once per file to discover the rest.
pub(crate) fn enforce(root: &Path) -> Result<(), String> {
    let measured = measure(root)?;
    let baseline_path = root.join(BASELINE);
    let baseline = read_baseline(&baseline_path)?;

    let mut findings = Vec::new();
    check_comment_ratios(&measured, &baseline, &mut findings);
    check_unsafe_counts(&measured, &baseline, &mut findings);

    if findings.is_empty() {
        println!(
            "budgets: {} production files and {} crates are within their recorded comment and \
             `unsafe` budgets",
            measured.files.len(),
            crate_count(&measured)
        );
        return Ok(());
    }

    let mut report = format!(
        "{} budget violation(s) against {}:\n",
        findings.len(),
        baseline_path.display()
    );
    for finding in &findings {
        report.push_str("  - ");
        report.push_str(finding);
        report.push('\n');
    }
    report.push_str("A budget may only fall. If the rise is deliberate and human-approved, ");
    report.push_str(HOW_TO_RERECORD);
    report.push('.');
    Err(report)
}

/// Re-record the baseline from the current tree. Deliberately not reachable
/// from [`enforce`]: a check that can rewrite its own expectation is not a
/// check, so the only way to move a budget is to ask for it explicitly.
///
/// It has no subcommand yet: `main.rs`'s dispatch is owned by another change
/// in flight, so the only caller today is the env-gated
/// [`tests::update_the_recorded_budgets`] and the binary build sees this as
/// dead. The `allow` is the whole of that gap and comes off together with one
/// line in `main::run`:
///
/// ```text
/// "budgets" => budgets::update(&root)?,
/// ```
///
/// `expect` would state it better than `allow` — it fails once obsolete — but
/// it has to be `cfg_attr`'d off for the test build, where the function *is*
/// used, and that combination currently ICEs the pinned nightly in
/// `check_mod_deathness`.
#[allow(
    dead_code,
    reason = "no `xtask budgets` subcommand yet; re-recording runs through the env-gated test"
)]
pub(crate) fn update(root: &Path) -> Result<(), String> {
    let measured = measure(root)?;
    let path = root.join(BASELINE);
    fs::write(&path, render_baseline(&measured))
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    println!(
        "budgets: recorded {} production files and {} crates into {}",
        measured.files.len(),
        crate_count(&measured),
        path.display()
    );
    Ok(())
}

fn crate_count(measured: &Measured) -> usize {
    measured
        .unsafes
        .keys()
        .map(|(_, krate)| krate.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn check_comment_ratios(measured: &Measured, baseline: &Baseline, findings: &mut Vec<String>) {
    for (path, budget) in &measured.files {
        let current = budget.recorded_ratio();
        match baseline.ratios.get(path) {
            // A new file with no recorded budget cannot be allowed through:
            // that is exactly how a file enters the tree unmeasured and stays
            // that way, and the ratchet would then defend everything except
            // whatever was written most recently.
            None => findings.push(format!(
                "comment budget {path}: no recorded comment ratio. A new production file enters the \
                 ratchet at the ratio it is written with ({current:.RATIO_DECIMALS$}, \
                 {}/{} lines) — {HOW_TO_RERECORD}",
                budget.comment_lines, budget.production_lines,
            )),
            Some(&recorded) if current > recorded + RATIO_EPSILON => findings.push(format!(
                "comment budget {path}: comment ratio rose to {current:.RATIO_DECIMALS$} \
                 ({}/{} production lines) from the recorded {recorded:.RATIO_DECIMALS$}",
                budget.comment_lines, budget.production_lines,
            )),
            Some(_) => {}
        }
    }
    for path in baseline.ratios.keys() {
        if !measured.files.contains_key(path) {
            findings.push(format!(
                "comment budget {path}: recorded in the baseline but no longer a production file. A \
                 stale entry hides whether the budget was met or the file merely vanished — \
                 {HOW_TO_RERECORD}"
            ));
        }
    }
}

fn check_unsafe_counts(measured: &Measured, baseline: &Baseline, findings: &mut Vec<String>) {
    for (&(kind, ref krate), &count) in &measured.unsafes {
        match baseline.unsafes.get(&(kind, krate.clone())) {
            None => findings.push(format!(
                "unsafe budget {krate}: no recorded budget in [{}]. It currently has {count} {} — \
                 {HOW_TO_RERECORD}",
                kind.section(),
                kind.what_it_counts(),
            )),
            Some(&recorded) if count > recorded => findings.push(format!(
                "unsafe budget {krate}: {} rose to {count} from the recorded {recorded}. This count is \
                 {} in production code (outside every `#[cfg(test)]` item), and every one of \
                 them obliges a safety claim the compiler cannot check",
                kind.what_it_counts(),
                kind.what_it_counts(),
            )),
            Some(_) => {}
        }
    }
    for (kind, krate) in baseline.unsafes.keys() {
        if !measured.unsafes.contains_key(&(*kind, krate.clone())) {
            findings.push(format!(
                "unsafe budget {krate}: recorded in [{}] but is no longer a crate under {} — \
                 {HOW_TO_RERECORD}",
                kind.section(),
                MEASURED_TREES.join("/ or "),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// Scan every production file under the measured trees.
///
/// Two passes, because whether a file is production at all is stated in a
/// *different* file: `#[cfg(test)] mod fake_device;` in a crate root makes
/// `fake_device.rs` test-support code, and the file itself says nothing about
/// it. The first pass scans everything and collects those declarations; the
/// second keeps the files no declaration excluded.
fn measure(root: &Path) -> Result<Measured, String> {
    let mut measured = Measured::default();
    for tree in MEASURED_TREES {
        let tree_path = root.join(tree);
        if !tree_path.is_dir() {
            return Err(format!(
                "{} is not a directory, so the comment and `unsafe` budgets would silently measure \
                 nothing there",
                tree_path.display()
            ));
        }
        for krate in crate_dirs(&tree_path)? {
            measure_crate(root, &krate, &mut measured)?;
        }
    }
    if measured.files.is_empty() {
        return Err(
            "no production files were found under crates/ or pds/, which cannot be right; the \
             budgets would pass while measuring nothing"
                .to_owned(),
        );
    }
    Ok(measured)
}

fn measure_crate(root: &Path, krate: &Path, measured: &mut Measured) -> Result<(), String> {
    let mut sources = Vec::new();
    collect_rust_sources(krate, &mut sources)?;
    sources.sort();

    let mut scans = Vec::new();
    let mut test_only = BTreeSet::new();
    for path in sources {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        let scan = scan(&source).map_err(|error| format!("{}: {error}", path.display()))?;
        for module in &scan.test_only_modules {
            test_only.insert(module.clone());
        }
        scans.push((path, scan));
    }

    let krate_key = relative(root, krate)?;
    let mut counts: BTreeMap<UnsafeKind, usize> = UnsafeKind::all()
        .into_iter()
        .map(|kind| (kind, 0))
        .collect();

    for (path, scan) in scans {
        if is_test_only_module_file(&path, &test_only) {
            continue;
        }
        let key = relative(root, &path)?;
        measured.files.insert(
            key,
            CommentBudget {
                comment_lines: scan.comment_lines,
                production_lines: scan.production_lines,
            },
        );
        for (kind, count) in scan.unsafes {
            *counts.entry(kind).or_default() += count;
        }
    }

    for (kind, count) in counts {
        measured.unsafes.insert((kind, krate_key.clone()), count);
    }
    Ok(())
}

/// Whether `path` is the file backing a `#[cfg(test)] mod NAME;` declaration —
/// either `NAME.rs` or `NAME/mod.rs`. Such a file is compiled only under
/// `cfg(test)`, so every line in it is test-support code however few
/// `#[cfg(test)]` attributes it contains itself.
fn is_test_only_module_file(path: &Path, test_only: &BTreeSet<String>) -> bool {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned());
    match stem.as_deref() {
        Some("mod") => path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|dir| test_only.contains(&dir.to_string_lossy().into_owned())),
        Some(name) => test_only.contains(name),
        None => false,
    }
}

/// The crate directories directly under a measured tree: those holding a
/// `Cargo.toml`.
fn crate_dirs(tree: &Path) -> Result<Vec<PathBuf>, String> {
    let mut dirs = Vec::new();
    let entries =
        fs::read_dir(tree).map_err(|error| format!("read dir {}: {error}", tree.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read dir {}: {error}", tree.display()))?;
        let path = entry.path();
        if path.is_dir() && path.join("Cargo.toml").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// Every `.rs` file under a crate that is product source rather than harness.
fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|error| format!("read dir {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read dir {}: {error}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !HARNESS_DIRS.contains(&name.as_str()) && !name.starts_with('.') && name != "target"
            {
                collect_rust_sources(&path, out)?;
            }
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "{} is not inside the workspace root {}",
            path.display(),
            root.display()
        )
    })?;
    Ok(relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/"))
}

// ---------------------------------------------------------------------------
// The scanner
// ---------------------------------------------------------------------------

/// What one file yielded.
#[derive(Default, PartialEq, Debug)]
struct Scan {
    comment_lines: usize,
    production_lines: usize,
    unsafes: BTreeMap<UnsafeKind, usize>,
    /// Names from `#[cfg(test)] mod NAME;`, so the sibling file they refer to
    /// can be dropped from the production set.
    test_only_modules: Vec<String>,
}

/// The lexical state a byte sits in. Everything the ratchet must not
/// mis-attribute — a keyword inside a doc comment, a `//` inside a string, a
/// brace inside a char literal — is separated by exactly this.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lex {
    Code,
    LineComment,
    /// Rust block comments nest, so the depth is carried rather than a flag.
    BlockComment(u32),
    Str,
    /// A raw string, carrying the hash count that must close it.
    RawStr(u32),
    Char,
}

/// How a line is counted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LineKind {
    /// Blank, or whitespace only. Counted in the denominator: the ratio is
    /// against production *lines*, and re-deriving which of them are "real"
    /// would make the recorded number depend on a second judgement call.
    Blank,
    Comment,
    Code,
}

/// A `#[cfg(test)]`-gated item, tracked until its extent is known.
struct Gate {
    start_line: usize,
    /// `None` while still in the item's header (before `;` or `{`), then the
    /// brace depth inside its body.
    body_depth: Option<u32>,
    paren: u32,
    bracket: u32,
    /// Identifier tokens of the header, so `mod NAME;` can be recognised.
    header: Vec<String>,
}

/// An attribute being consumed, so nothing inside it is mistaken for code.
struct Attribute {
    start_line: usize,
    text_start: usize,
    depth: u32,
    inner: bool,
}

/// Lex `source` into the counts the comment and `unsafe` budgets use.
///
/// Errors, rather than a best guess, on anything it cannot classify: an
/// unterminated comment or string, an unbalanced `#[cfg(test)]` item, a
/// `cfg(...)` mentioning `test` in an unrecognised shape, or an `unsafe`
/// keyword in a form this counter does not know.
fn scan(source: &str) -> Result<Scan, String> {
    let bytes = source.as_bytes();
    let mut lines = vec![LineKind::Blank];
    let mut state = Lex::Code;
    let mut line = 0_usize;
    let mut pending_first_nonws = true;
    let mut excluded: Vec<(usize, usize)> = Vec::new();
    let mut unsafe_sites: Vec<UnsafeKind> = Vec::new();
    let mut test_only_modules = Vec::new();
    let mut gate: Option<Gate> = None;
    let mut attribute: Option<Attribute> = None;
    let mut whole_file_is_test = false;
    let mut i = 0_usize;

    while i < bytes.len() {
        let byte = bytes[i];

        if byte == b'\n' {
            if state == Lex::LineComment {
                state = Lex::Code;
            }
            line += 1;
            lines.push(LineKind::Blank);
            pending_first_nonws = true;
            i += 1;
            continue;
        }
        if pending_first_nonws && !byte.is_ascii_whitespace() {
            pending_first_nonws = false;
            lines[line] = classify_line_start(state, bytes, i);
        }

        match state {
            Lex::LineComment => {
                i += 1;
            }
            Lex::BlockComment(depth) => {
                if bytes[i..].starts_with(b"/*") {
                    state = Lex::BlockComment(depth + 1);
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    state = if depth == 1 {
                        Lex::Code
                    } else {
                        Lex::BlockComment(depth - 1)
                    };
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Lex::Str | Lex::Char => {
                let terminator = if state == Lex::Str { b'"' } else { b'\'' };
                if byte == b'\\' {
                    i += 2;
                } else {
                    if byte == terminator {
                        state = Lex::Code;
                    }
                    i += 1;
                }
            }
            Lex::RawStr(hashes) => {
                if byte == b'"'
                    && bytes[i + 1..]
                        .iter()
                        .take(hashes as usize)
                        .filter(|&&b| b == b'#')
                        .count()
                        == hashes as usize
                {
                    state = Lex::Code;
                    i += 1 + hashes as usize;
                } else {
                    i += 1;
                }
            }
            Lex::Code => {
                // Comment and literal openers take precedence over everything:
                // a `#`, a brace or a keyword inside one of them is text.
                if bytes[i..].starts_with(b"//") {
                    state = Lex::LineComment;
                    i += 2;
                    continue;
                }
                if bytes[i..].starts_with(b"/*") {
                    state = Lex::BlockComment(1);
                    i += 2;
                    continue;
                }
                if let Some((next, hashes)) = raw_string_at(bytes, i) {
                    state = Lex::RawStr(hashes);
                    i = next;
                    continue;
                }
                if byte == b'"' {
                    state = Lex::Str;
                    i += 1;
                    continue;
                }
                if byte == b'\'' {
                    // A lifetime and a char literal open identically; only the
                    // shape after the tick tells them apart, and treating
                    // `&'a str` as a literal would swallow the rest of the file.
                    if char_literal_at(bytes, i) {
                        state = Lex::Char;
                    }
                    i += 1;
                    continue;
                }

                if let Some(open) = &mut attribute {
                    match byte {
                        b'[' => open.depth += 1,
                        b']' => {
                            open.depth -= 1;
                            if open.depth == 0 {
                                let text = normalize(&source[open.text_start..i]);
                                let (start_line, inner) = (open.start_line, open.inner);
                                attribute = None;
                                if is_unrecognised_test_cfg(&text) {
                                    return Err(format!(
                                        "line {}: `#[{text}]` gates on `test` in a shape this \
                                         budget scanner cannot account for. Only the exact \
                                         `#[cfg(test)]` is recognised; anything else would \
                                         silently count test code as production",
                                        start_line + 1
                                    ));
                                }
                                if text == "cfg(test)" {
                                    if inner {
                                        // `#![cfg(test)]` gates the whole file.
                                        whole_file_is_test = true;
                                    } else if gate.is_none() {
                                        gate = Some(Gate {
                                            start_line,
                                            body_depth: None,
                                            paren: 0,
                                            bracket: 0,
                                            header: Vec::new(),
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                    continue;
                }
                if byte == b'#' {
                    let inner = bytes.get(i + 1) == Some(&b'!');
                    let bracket = if inner { i + 2 } else { i + 1 };
                    if bytes.get(bracket) == Some(&b'[') {
                        attribute = Some(Attribute {
                            start_line: line,
                            text_start: bracket + 1,
                            depth: 1,
                            inner,
                        });
                        i = bracket + 1;
                        continue;
                    }
                    i += 1;
                    continue;
                }

                if is_ident_start(byte) {
                    let end = ident_end(bytes, i);
                    let word = &source[i..end];
                    if let Some(open) = &mut gate
                        && open.body_depth.is_none()
                    {
                        open.header.push(word.to_owned());
                    }
                    // Only production `unsafe` is counted; inside a gated item
                    // it is test code, and classifying it would also make an
                    // exotic-but-harmless test construct fail the gate.
                    if word == "unsafe" && gate.is_none() {
                        unsafe_sites.push(classify_unsafe(bytes, source, end, line)?);
                    }
                    i = end;
                    continue;
                }

                if let Some(open) = &mut gate {
                    match open.body_depth {
                        None => match byte {
                            b'(' => open.paren += 1,
                            b')' => open.paren = open.paren.saturating_sub(1),
                            b'[' => open.bracket += 1,
                            b']' => open.bracket = open.bracket.saturating_sub(1),
                            // A `;` or `{` at depth zero ends the item header:
                            // a declaration outright, a braced body by opening
                            // it. Depth matters because `[u8; 4]` and a
                            // parameter list both carry a `;` that ends nothing.
                            b';' if open.paren == 0 && open.bracket == 0 => {
                                if let Some(name) = declared_module(open) {
                                    test_only_modules.push(name);
                                }
                                excluded.push((open.start_line, line));
                                gate = None;
                            }
                            b'{' if open.paren == 0 && open.bracket == 0 => {
                                open.body_depth = Some(1);
                            }
                            _ => {}
                        },
                        Some(depth) => match byte {
                            b'{' => open.body_depth = Some(depth + 1),
                            b'}' => {
                                if depth == 1 {
                                    excluded.push((open.start_line, line));
                                    gate = None;
                                } else {
                                    open.body_depth = Some(depth - 1);
                                }
                            }
                            _ => {}
                        },
                    }
                }
                i += 1;
            }
        }
    }

    if state != Lex::Code && state != Lex::LineComment {
        return Err(format!(
            "the file ends inside {}, so every count taken from it would be guesswork",
            match state {
                Lex::BlockComment(_) => "an unterminated block comment",
                Lex::Str | Lex::RawStr(_) => "an unterminated string literal",
                _ => "an unterminated character literal",
            }
        ));
    }
    if attribute.is_some() {
        return Err("the file ends inside an unterminated attribute".to_owned());
    }
    if let Some(open) = gate {
        return Err(format!(
            "the `#[cfg(test)]` item starting on line {} is never closed, so the production \
             line range cannot be determined",
            open.start_line + 1
        ));
    }

    if whole_file_is_test {
        return Ok(Scan::default());
    }

    // A file ending in a newline has no line after it. Counting the empty
    // remainder as one would put a line in the denominator that no editor
    // shows and no `wc -l` agrees with, and rustfmt gives every file here that
    // trailing newline — so the inflation would be silent and universal. This
    // is `str::lines()`'s rule, applied to a scan that had to track the newline
    // itself to know which state each line begins in.
    if source.is_empty() || source.ends_with('\n') {
        lines.pop();
    }

    let mut scan = Scan {
        test_only_modules,
        ..Scan::default()
    };
    for (number, kind) in lines.iter().enumerate() {
        if excluded
            .iter()
            .any(|&(start, end)| number >= start && number <= end)
        {
            continue;
        }
        scan.production_lines += 1;
        if *kind == LineKind::Comment {
            scan.comment_lines += 1;
        }
    }
    for kind in unsafe_sites {
        *scan.unsafes.entry(kind).or_default() += 1;
    }
    Ok(scan)
}

/// Classify a line by the state its first non-whitespace byte sits in.
///
/// A line inside a block comment is a comment line whatever it starts with,
/// which is what counts a `*`-continued body without a separate rule for it. A
/// line whose first byte is inside a multi-line string is *not* — that byte is
/// payload, and a `//` there is two characters of data.
fn classify_line_start(state: Lex, bytes: &[u8], at: usize) -> LineKind {
    match state {
        Lex::BlockComment(_) | Lex::LineComment => LineKind::Comment,
        Lex::Str | Lex::RawStr(_) | Lex::Char => LineKind::Code,
        Lex::Code => {
            if bytes[at] == b'/' && matches!(bytes.get(at + 1), Some(b'/' | b'*')) {
                LineKind::Comment
            } else {
                LineKind::Code
            }
        }
    }
}

/// The module name a finished `;`-terminated gated item declares, if it
/// declares one: the `NAME` of `#[cfg(test)] mod NAME;`, whose backing file is
/// then test-support code in its entirety.
fn declared_module(gate: &Gate) -> Option<String> {
    let at = gate.header.iter().position(|token| token == "mod")?;
    gate.header.get(at + 1).cloned()
}

/// Decide what an `unsafe` keyword introduces, by the next token that is not
/// whitespace or a comment.
///
/// An unrecognised form is an error and not a zero: `unsafe extern`, `unsafe
/// trait` and the 2024 `#[unsafe(...)]` attributes all exist, and a counter
/// that silently ignores the ones it was not taught would report a falling
/// budget while `unsafe` grew.
fn classify_unsafe(
    bytes: &[u8],
    source: &str,
    after: usize,
    line: usize,
) -> Result<UnsafeKind, String> {
    let at = next_significant(bytes, after);
    let Some(at) = at else {
        return Err(format!(
            "line {}: `unsafe` is the last token in the file",
            line + 1
        ));
    };
    if bytes[at] == b'{' {
        return Ok(UnsafeKind::Block);
    }
    if is_ident_start(bytes[at]) {
        let word = &source[at..ident_end(bytes, at)];
        return match word {
            "fn" => Ok(UnsafeKind::Function),
            "impl" => Ok(UnsafeKind::Implementation),
            other => Err(format!(
                "line {}: `unsafe {other}` is a form the `unsafe` budget does not know how to \
                 count. Teach `classify_unsafe` about it rather than letting it go uncounted",
                line + 1
            )),
        };
    }
    Err(format!(
        "line {}: `unsafe` is followed by `{}`, which is neither a block nor an item the `unsafe` \
         budget knows how to count",
        line + 1,
        char::from(bytes[at])
    ))
}

/// The next byte after `from` that is neither whitespace nor inside a comment.
fn next_significant(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            let mut depth = 1_u32;
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        return (i < bytes.len()).then_some(i);
    }
}

/// Whether an attribute gates on `test` in a shape the scanner cannot honour.
///
/// `cfg_attr` is deliberately not a gate: it applies another attribute
/// conditionally and never removes the item, so `#![cfg_attr(not(test),
/// no_std)]` is production code and must not trip this.
fn is_unrecognised_test_cfg(text: &str) -> bool {
    text != "cfg(test)" && text.starts_with("cfg(") && contains_ident(text, "test")
}

/// Whether `needle` appears in `text` as a whole identifier rather than as a
/// substring of a longer one, so a `cfg(feature="fastest")` is not read as a
/// test gate.
fn contains_ident(text: &str, needle: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(at) = text[from..].find(needle) {
        let start = from + at;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Strip every whitespace character, so `#[ cfg( test ) ]` compares equal to
/// `#[cfg(test)]`. The result is also quoted back in the unrecognised-gate
/// diagnostic, which is why it stays a `&str` operation: rebuilding it from
/// bytes would render a non-ASCII attribute as mojibake in the one message
/// whose whole job is to show the author what was rejected.
fn normalize(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// A raw-string opener at `i`, yielding the index just past its quote and the
/// hash count that must close it. Handles the `r`, `br` and `cr` prefixes.
fn raw_string_at(bytes: &[u8], i: usize) -> Option<(usize, u32)> {
    let mut at = i;
    match bytes.get(at) {
        Some(b'r') => at += 1,
        Some(b'b' | b'c') if bytes.get(at + 1) == Some(&b'r') => at += 2,
        _ => return None,
    }
    // A raw string may not be preceded by an identifier byte, or `for` would
    // end in a raw-string prefix.
    if i > 0 && is_ident_byte(bytes[i - 1]) {
        return None;
    }
    let mut hashes = 0_u32;
    while bytes.get(at) == Some(&b'#') {
        hashes += 1;
        at += 1;
    }
    (bytes.get(at) == Some(&b'"')).then_some((at + 1, hashes))
}

/// Whether the tick at `quote` opens a character literal rather than a
/// lifetime. `'a'` is a literal; `&'a str` and `'static` are not. A non-ASCII
/// byte after the tick can only be a literal, since a lifetime name is an
/// ASCII identifier here.
fn char_literal_at(bytes: &[u8], quote: usize) -> bool {
    match bytes.get(quote + 1) {
        None => false,
        Some(b'\\') => true,
        Some(&byte) if !byte.is_ascii() => true,
        Some(_) => bytes.get(quote + 2) == Some(&b'\''),
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn ident_end(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    end
}

// ---------------------------------------------------------------------------
// The baseline file
// ---------------------------------------------------------------------------

/// The sections the baseline may contain, in write order.
const SECTIONS: &[&str] = &[
    "comment-ratio",
    "unsafe-blocks",
    "unsafe-fns",
    "unsafe-impls",
];

fn render_baseline(measured: &Measured) -> String {
    let mut out = String::new();
    out.push_str(
        "# Recorded comment and `unsafe` budgets — ratchets the gate only lets fall.\n\
         #\n\
         # Generated by `tools/xtask/src/budgets.rs`; do not hand-edit. Every number here may\n\
         # fall and may never rise: the gate (`xtask test`) fails on any increase. Re-record\n\
         # after a deliberate, human-approved reduction with\n\
         #\n\
         #     LIBREFIREWALL_BUDGETS_UPDATE=1 cargo test -p xtask update_the_recorded_budgets\n\
         #\n\
         # [comment-ratio] is comment lines / production lines per production file. A comment\n\
         # line is one whose first non-whitespace byte opens or continues a comment; production\n\
         # lines are every line outside a `#[cfg(test)]` item, blank lines included. Benches,\n\
         # integration tests and files backing a `#[cfg(test)] mod NAME;` are not production.\n\
         #\n\
         # [unsafe-*] are per-crate counts of production `unsafe { … }` blocks, `unsafe fn`\n\
         # declarations and `unsafe impl` items. A crate with none is recorded as 0, so its\n\
         # first `unsafe` fails the gate.\n",
    );
    out.push_str("\n[comment-ratio]\n");
    for (path, budget) in &measured.files {
        let _ = writeln!(
            out,
            "\"{path}\" = {:.RATIO_DECIMALS$}",
            budget.recorded_ratio()
        );
    }
    for kind in UnsafeKind::all() {
        let _ = write!(out, "\n[{}]\n", kind.section());
        for (&(entry_kind, ref krate), &count) in &measured.unsafes {
            if entry_kind == kind {
                let _ = writeln!(out, "\"{krate}\" = {count}");
            }
        }
    }
    out
}

/// Parse the baseline strictly.
///
/// Nothing is tolerated: an unknown section, a malformed entry, a duplicate key
/// or an out-of-range value fails with the line number. A budget file is the
/// gate's entire notion of what is allowed, so a line it cannot read is a line
/// it must not skip.
fn read_baseline(path: &Path) -> Result<Baseline, String> {
    let text = fs::read_to_string(path).map_err(|error| {
        format!(
            "read {}: {error}. The comment and `unsafe` budgets have no recorded state to compare \
             against — {HOW_TO_RERECORD}",
            path.display()
        )
    })?;

    let mut baseline = Baseline::default();
    let mut section: Option<&str> = None;
    let mut seen_sections = BTreeSet::new();

    for (number, raw) in text.lines().enumerate() {
        let at = number + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if !SECTIONS.contains(&name) {
                return Err(format!(
                    "{}:{at}: unknown section [{name}]; expected one of {SECTIONS:?}",
                    path.display()
                ));
            }
            if !seen_sections.insert(name.to_owned()) {
                return Err(format!(
                    "{}:{at}: section [{name}] appears twice",
                    path.display()
                ));
            }
            section = Some(SECTIONS.iter().find(|s| **s == name).copied().unwrap_or(""));
            continue;
        }

        let Some(current) = section else {
            return Err(format!(
                "{}:{at}: entry before any section header: {line}",
                path.display()
            ));
        };
        let (key, value) = parse_entry(line)
            .ok_or_else(|| format!("{}:{at}: malformed entry: {line}", path.display()))?;

        if current == "comment-ratio" {
            let ratio: f64 = value
                .parse()
                .map_err(|_| format!("{}:{at}: `{value}` is not a ratio", path.display()))?;
            if !(0.0..=1.0).contains(&ratio) {
                return Err(format!(
                    "{}:{at}: ratio {ratio} is outside 0.0..=1.0",
                    path.display()
                ));
            }
            if baseline.ratios.insert(key.clone(), ratio).is_some() {
                return Err(format!(
                    "{}:{at}: duplicate entry for {key}",
                    path.display()
                ));
            }
        } else {
            let kind = UnsafeKind::all()
                .into_iter()
                .find(|kind| kind.section() == current)
                .ok_or_else(|| format!("{}:{at}: unhandled section {current}", path.display()))?;
            let count: usize = value
                .parse()
                .map_err(|_| format!("{}:{at}: `{value}` is not a count", path.display()))?;
            if baseline
                .unsafes
                .insert((kind, key.clone()), count)
                .is_some()
            {
                return Err(format!(
                    "{}:{at}: duplicate entry for {key} in [{current}]",
                    path.display()
                ));
            }
        }
    }

    if baseline.ratios.is_empty() || baseline.unsafes.is_empty() {
        return Err(format!(
            "{} records no budgets, so the gate would pass without checking anything — \
             {HOW_TO_RERECORD}",
            path.display()
        ));
    }
    Ok(baseline)
}

/// Split a `"key" = value` entry. The quoted key is required: paths contain
/// characters a bare key could not carry, and requiring the quotes keeps the
/// file valid TOML for an editor.
fn parse_entry(line: &str) -> Option<(String, &str)> {
    let rest = line.strip_prefix('"')?;
    let (key, rest) = rest.split_once('"')?;
    let value = rest.trim_start().strip_prefix('=')?.trim();
    (!key.is_empty() && !value.is_empty()).then(|| (key.to_owned(), value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scan a snippet, failing the test with the scanner's own diagnostic.
    fn scanned(source: &str) -> Scan {
        scan(source).unwrap_or_else(|error| panic!("scan failed: {error}"))
    }

    fn unsafes(source: &str) -> BTreeMap<UnsafeKind, usize> {
        scanned(source).unsafes
    }

    #[test]
    fn the_line_count_is_the_one_an_editor_shows() {
        // The scanner has to see the newline to know which lexical state the
        // next line opens in, which makes it easy to count an empty remainder
        // after the last one. rustfmt puts a trailing newline on every file
        // here, so that off-by-one would apply to all of them at once and
        // quietly disagree with `wc -l`.
        assert_eq!(scanned("a();\nb();\n").production_lines, 2);
        assert_eq!(
            scanned("a();\nb();").production_lines,
            2,
            "no trailing newline"
        );
        assert_eq!(scanned("").production_lines, 0);
        assert_eq!(scanned("\n").production_lines, 1, "one empty line");
    }

    #[test]
    fn a_comment_line_is_one_that_starts_with_a_comment() {
        let scan = scanned(
            "//! header\n\
             /// doc\n\
             // plain\n\
             let x = 1; // trailing is not a comment line\n\
             \n",
        );
        assert_eq!(scan.production_lines, 5, "the blank line counts");
        assert_eq!(scan.comment_lines, 3, "the trailing comment is code");
    }

    #[test]
    fn a_block_comment_body_counts_however_its_lines_begin() {
        let scan = scanned("/* open\n * starred\nnot starred\nstill inside\n*/\ncode();\n");
        assert_eq!(scan.comment_lines, 5);
        assert_eq!(scan.production_lines, 6);
    }

    #[test]
    fn block_comments_nest_so_the_first_close_does_not_end_them() {
        // Rust block comments nest. Ending at the first `*/` would count the
        // remaining body as code and, worse, read the rest of the file in the
        // wrong state.
        let scan = scanned("/* outer /* inner */ still a comment\n*/\ncode();\n");
        assert_eq!(scan.comment_lines, 2);
        assert_eq!(scan.production_lines, 3);
    }

    #[test]
    fn a_slash_slash_inside_a_string_is_payload_not_a_comment() {
        // The line begins inside a multi-line string literal, so its leading
        // `//` is two characters of data. A prefix match counts it as prose and
        // reports a ratio nobody can reconcile with the file.
        let scan = scanned("let banner = \"first\n// looks like a comment\n\";\ncode();\n");
        assert_eq!(scan.comment_lines, 0);
        assert_eq!(scan.production_lines, 4);
    }

    #[test]
    fn a_raw_string_needs_its_hashes_to_close() {
        let scan = scanned("let re = r#\"a \" quote\n// inside the raw string\n\"#;\ncode();\n");
        assert_eq!(scan.comment_lines, 0);
        assert_eq!(scan.production_lines, 4);
    }

    #[test]
    fn an_unsafe_keyword_inside_a_comment_is_not_counted() {
        // `crates/queue/src/lib.rs` documents the rule against an `unsafe impl`
        // resting on an unkeepable promise. A grep counts the warning as the
        // thing it warns about.
        let scan = scanned(
            "//! Never write an `unsafe impl` on a promise the API cannot keep.\n\
             // unsafe { } would also be miscounted here\n\
             let s = \"unsafe fn\";\n",
        );
        assert!(scan.unsafes.is_empty(), "got {:?}", scan.unsafes);
    }

    #[test]
    fn the_three_unsafe_forms_are_counted_apart() {
        let counts = unsafes(
            "unsafe impl Sync for T {}\n\
             pub unsafe fn a() { unsafe { b() } }\n\
             fn c() { unsafe { d() }; unsafe { e() } }\n",
        );
        assert_eq!(counts[&UnsafeKind::Implementation], 1);
        assert_eq!(counts[&UnsafeKind::Function], 1, "the fn body is separate");
        assert_eq!(counts[&UnsafeKind::Block], 3);
    }

    #[test]
    fn an_unsafe_form_the_counter_does_not_know_fails_loudly() {
        // The failure that matters: a form silently uncounted reports a falling
        // budget while `unsafe` grows.
        let error = scan("unsafe trait Frobnicate {}\n").unwrap_err();
        assert!(error.contains("unsafe trait"), "got: {error}");
        assert!(error.contains("classify_unsafe"), "got: {error}");

        let error = scan("unsafe extern \"C\" { fn f(); }\n").unwrap_err();
        assert!(error.contains("unsafe extern"), "got: {error}");
    }

    #[test]
    fn an_unsafe_attribute_is_not_an_unsafe_block() {
        // Rust 2024 spells `#[unsafe(no_mangle)]`. It is an attribute, not a
        // block, and must neither be counted nor rejected as unknown.
        let scan = scanned("#[unsafe(no_mangle)]\npub extern \"C\" fn f() {}\n");
        assert!(scan.unsafes.is_empty(), "got {:?}", scan.unsafes);
    }

    #[test]
    fn a_comment_between_unsafe_and_its_block_does_not_hide_it() {
        let counts = unsafes("unsafe /* why */ { f() }\nunsafe // why\n{ g() }\n");
        assert_eq!(counts[&UnsafeKind::Block], 2);
    }

    #[test]
    fn a_lifetime_is_not_a_character_literal() {
        // Treating `&'a str` as an open char literal swallows the rest of the
        // file into a literal, and every count after it is nonsense.
        let scan = scanned(
            "fn f<'a>(x: &'a str) -> &'static str { x }\n\
             // a real comment after the lifetimes\n\
             unsafe { g() }\n",
        );
        assert_eq!(scan.comment_lines, 1);
        assert_eq!(scan.unsafes[&UnsafeKind::Block], 1);
    }

    #[test]
    fn a_character_literal_holding_a_quote_or_a_brace_is_still_one_token() {
        let scan = scanned("let a = '\\'';\nlet b = '{';\nunsafe { f() }\n");
        assert_eq!(scan.unsafes[&UnsafeKind::Block], 1);
        assert_eq!(scan.production_lines, 3);
    }

    #[test]
    fn production_resumes_after_a_test_gated_declaration() {
        // The defect a "first `#[cfg(test)]` wins" rule causes, at the shape
        // it really takes in this workspace: a crate root declares its
        // test-support module near the top, and cutting there would discard
        // every production line below it.
        let scan = scanned(
            "//! header\n\
             #[cfg(test)]\n\
             mod fake_device;\n\
             // production comment after the gate\n\
             pub fn real() {}\n",
        );
        assert_eq!(scan.production_lines, 3, "only the two gated lines are cut");
        assert_eq!(scan.comment_lines, 2);
        assert_eq!(scan.test_only_modules, vec!["fake_device".to_owned()]);
    }

    #[test]
    fn a_test_gated_function_cuts_only_that_function() {
        // A `#[cfg(test)]` helper fn sits well above the real test module in
        // this workspace, with production code in between; the gate must end
        // at the helper's closing brace, not run on to the module.
        let scan = scanned(
            "pub fn a() {}\n\
             #[cfg(test)]\n\
             pub(crate) fn helper<D: Trait>(d: D) -> Offered<D> {\n\
                 Offered { d }\n\
             }\n\
             // production again\n\
             pub fn b() {}\n",
        );
        assert_eq!(scan.production_lines, 3);
        assert_eq!(scan.comment_lines, 1);
        assert!(scan.test_only_modules.is_empty(), "a fn is not a mod");
    }

    #[test]
    fn a_test_module_cuts_to_its_closing_brace() {
        let scan = scanned(
            "pub fn a() {}\n\
             #[cfg(test)]\n\
             mod tests {\n\
                 // a comment that must not count\n\
                 fn t() { if x { y } }\n\
             }\n",
        );
        assert_eq!(scan.production_lines, 1);
        assert_eq!(scan.comment_lines, 0);
    }

    #[test]
    fn a_semicolon_inside_brackets_does_not_end_a_gated_item() {
        // `[u8; 4]` carries a `;` that ends nothing. Ending the gate there
        // would leave the array's own body counted as production.
        let scan = scanned(
            "#[cfg(test)]\n\
             const SEEDS: [u8; 4] = [0; 4];\n\
             // production\n\
             pub fn a() {}\n",
        );
        assert_eq!(scan.production_lines, 2);
        assert_eq!(scan.comment_lines, 1);
    }

    #[test]
    fn further_attributes_on_a_gated_item_do_not_disturb_its_extent() {
        let scan = scanned(
            "#[cfg(test)]\n\
             #[allow(clippy::all)]\n\
             mod tests {\n\
                 fn t() {}\n\
             }\n\
             pub fn a() {}\n",
        );
        assert_eq!(scan.production_lines, 1);
    }

    #[test]
    fn a_whitespaced_cfg_test_is_still_a_gate() {
        let scan = scanned("#[ cfg( test ) ]\nmod tests { fn t() {} }\npub fn a() {}\n");
        assert_eq!(scan.production_lines, 1);
    }

    #[test]
    fn cfg_attr_on_test_is_production_and_not_a_gate() {
        // `#![cfg_attr(not(test), no_std)]` heads five crates here. It applies
        // an attribute conditionally and removes nothing, so reading it as a
        // gate would blank every one of those files.
        let scan = scanned("#![cfg_attr(not(test), no_std)]\n// a comment\npub fn a() {}\n");
        assert_eq!(scan.production_lines, 3);
        assert_eq!(scan.comment_lines, 1);
    }

    #[test]
    fn an_unrecognised_test_gate_fails_rather_than_counting_test_code() {
        let error = scan("#[cfg(any(test, feature = \"x\"))]\nmod t { }\n").unwrap_err();
        assert!(error.contains("cannot account for"), "got: {error}");

        let error = scan("#[cfg(not(test))]\npub fn a() {}\n").unwrap_err();
        assert!(error.contains("cannot account for"), "got: {error}");
    }

    #[test]
    fn a_cfg_feature_merely_containing_test_is_not_a_test_gate() {
        // `fastest` contains `test`. A substring match would reject a perfectly
        // ordinary feature gate.
        let scan = scanned("#[cfg(feature = \"fastest\")]\npub fn a() {}\n");
        assert_eq!(scan.production_lines, 2);
    }

    #[test]
    fn an_inner_cfg_test_blanks_the_whole_file() {
        let scan = scanned("#![cfg(test)]\n// everything here is test code\npub fn a() {}\n");
        assert_eq!(scan.production_lines, 0);
        assert_eq!(scan.comment_lines, 0);
    }

    #[test]
    fn an_unterminated_construct_is_a_hard_failure_not_a_guess() {
        // A gate that cannot read its input must fail, never default to
        // a passing measurement.
        for (source, expected) in [
            ("/* never closed\n", "unterminated block comment"),
            ("let s = \"never closed\n", "unterminated string"),
            ("#[cfg(test)]\nmod tests {\n", "never closed"),
            ("#[cfg(test", "unterminated attribute"),
        ] {
            let error = scan(source).unwrap_err();
            assert!(error.contains(expected), "{source:?} gave: {error}");
        }
    }

    #[test]
    fn a_file_with_no_production_lines_has_a_zero_ratio_not_a_division_by_zero() {
        let budget = CommentBudget {
            comment_lines: 0,
            production_lines: 0,
        };
        assert!((budget.ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_ratio_is_recorded_at_the_precision_it_is_compared_at() {
        let budget = CommentBudget {
            comment_lines: 1,
            production_lines: 3,
        };
        assert!((budget.recorded_ratio() - 0.3333).abs() < f64::EPSILON);
    }

    #[test]
    fn a_test_only_module_file_is_recognised_by_either_spelling() {
        let test_only: BTreeSet<String> = ["fake_device".to_owned()].into_iter().collect();
        assert!(is_test_only_module_file(
            Path::new("crates/c/src/fake_device.rs"),
            &test_only
        ));
        assert!(is_test_only_module_file(
            Path::new("crates/c/src/fake_device/mod.rs"),
            &test_only
        ));
        assert!(!is_test_only_module_file(
            Path::new("crates/c/src/port.rs"),
            &test_only
        ));
    }

    #[test]
    fn the_baseline_round_trips_through_its_own_writer_and_reader() {
        let mut measured = Measured::default();
        measured.files.insert(
            "crates/a/src/lib.rs".to_owned(),
            CommentBudget {
                comment_lines: 1,
                production_lines: 4,
            },
        );
        for kind in UnsafeKind::all() {
            measured.unsafes.insert((kind, "crates/a".to_owned()), 2);
        }
        let rendered = render_baseline(&measured);

        let path = scratch("roundtrip");
        fs::write(&path, &rendered).unwrap();
        let baseline = read_baseline(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert!((baseline.ratios["crates/a/src/lib.rs"] - 0.25).abs() < f64::EPSILON);
        assert_eq!(
            baseline.unsafes[&(UnsafeKind::Block, "crates/a".to_owned())],
            2
        );
    }

    #[test]
    fn a_malformed_baseline_fails_with_its_line_number() {
        for (body, expected) in [
            ("[nonsense]\n\"a\" = 1\n", "unknown section"),
            ("\"a\" = 0.5\n", "before any section"),
            ("[comment-ratio]\nnot an entry\n", "malformed entry"),
            ("[comment-ratio]\n\"a\" = wat\n", "is not a ratio"),
            ("[comment-ratio]\n\"a\" = 1.5\n", "outside 0.0..=1.0"),
            (
                "[comment-ratio]\n\"a\" = 0.1\n\"a\" = 0.2\n",
                "duplicate entry",
            ),
            (
                "[comment-ratio]\n\"a\" = 0.1\n[comment-ratio]\n",
                "appears twice",
            ),
            ("[unsafe-blocks]\n\"a\" = -1\n", "is not a count"),
            ("[comment-ratio]\n\"a\" = 0.1\n", "records no budgets"),
        ] {
            let path = scratch("malformed");
            fs::write(&path, body).unwrap();
            let error = read_baseline(&path).unwrap_err();
            fs::remove_file(&path).unwrap();
            assert!(error.contains(expected), "{body:?} gave: {error}");
        }
    }

    #[test]
    fn a_missing_baseline_says_how_to_create_one() {
        let error = read_baseline(&scratch("absent")).unwrap_err();
        assert!(
            error.contains("LIBREFIREWALL_BUDGETS_UPDATE"),
            "got: {error}"
        );
    }

    #[test]
    fn a_risen_ratio_fails_and_a_fallen_one_passes() {
        let mut measured = Measured::default();
        measured.files.insert(
            "a.rs".to_owned(),
            CommentBudget {
                comment_lines: 30,
                production_lines: 100,
            },
        );
        let mut baseline = Baseline::default();

        baseline.ratios.insert("a.rs".to_owned(), 0.2000);
        let mut findings = Vec::new();
        check_comment_ratios(&measured, &baseline, &mut findings);
        assert_eq!(findings.len(), 1, "0.30 above a recorded 0.20 must fail");
        assert!(findings[0].contains("0.3000") && findings[0].contains("0.2000"));

        baseline.ratios.insert("a.rs".to_owned(), 0.4000);
        let mut findings = Vec::new();
        check_comment_ratios(&measured, &baseline, &mut findings);
        assert!(findings.is_empty(), "falling below the budget is the point");
    }

    #[test]
    fn the_epsilon_absorbs_rounding_without_hiding_a_real_comment_line() {
        let mut baseline = Baseline::default();
        baseline.ratios.insert("a.rs".to_owned(), 0.3333);

        // The same file re-measured: 1/3 rounds to the recorded 0.3333.
        let mut measured = Measured::default();
        measured.files.insert(
            "a.rs".to_owned(),
            CommentBudget {
                comment_lines: 1,
                production_lines: 3,
            },
        );
        let mut findings = Vec::new();
        check_comment_ratios(&measured, &baseline, &mut findings);
        assert!(findings.is_empty(), "rounding must not fail the gate");

        // One comment line added to a large file moves the ratio by ~0.0002,
        // which is twice the tolerance and must still be caught.
        let mut baseline = Baseline::default();
        baseline.ratios.insert("big.rs".to_owned(), 0.2000);
        let mut measured = Measured::default();
        measured.files.insert(
            "big.rs".to_owned(),
            CommentBudget {
                comment_lines: 1001,
                production_lines: 5000,
            },
        );
        let mut findings = Vec::new();
        check_comment_ratios(&measured, &baseline, &mut findings);
        assert_eq!(findings.len(), 1, "a single added comment line must fail");
    }

    #[test]
    fn a_file_absent_from_the_baseline_fails_rather_than_entering_unmeasured() {
        let mut measured = Measured::default();
        measured.files.insert(
            "new.rs".to_owned(),
            CommentBudget {
                comment_lines: 9,
                production_lines: 10,
            },
        );
        let mut findings = Vec::new();
        check_comment_ratios(&measured, &Baseline::default(), &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].contains("no recorded comment ratio"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_baseline_entry_with_no_file_left_is_reported_as_stale() {
        let mut baseline = Baseline::default();
        baseline.ratios.insert("gone.rs".to_owned(), 0.1);
        let mut findings = Vec::new();
        check_comment_ratios(&Measured::default(), &baseline, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].contains("no longer a production file"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_risen_unsafe_count_names_what_to_delete() {
        let mut measured = Measured::default();
        measured
            .unsafes
            .insert((UnsafeKind::Block, "crates/a".to_owned()), 27);
        let mut baseline = Baseline::default();
        baseline
            .unsafes
            .insert((UnsafeKind::Block, "crates/a".to_owned()), 26);

        let mut findings = Vec::new();
        check_unsafe_counts(&measured, &baseline, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("unsafe budget"), "{findings:?}");
        // The definition must travel with the number, or the author cannot tell
        // which construct the count is even about.
        assert!(
            findings[0].contains("`unsafe { … }` blocks"),
            "{findings:?}"
        );
        assert!(findings[0].contains("27") && findings[0].contains("26"));
    }

    #[test]
    fn the_first_unsafe_in_a_crate_recorded_at_zero_fails() {
        // Recording the absence as a number means a crate with no
        // hardware or ABI reason for `unsafe` cannot acquire one quietly.
        let mut measured = Measured::default();
        measured
            .unsafes
            .insert((UnsafeKind::Block, "crates/queue".to_owned()), 1);
        let mut baseline = Baseline::default();
        baseline
            .unsafes
            .insert((UnsafeKind::Block, "crates/queue".to_owned()), 0);

        let mut findings = Vec::new();
        check_unsafe_counts(&measured, &baseline, &mut findings);
        assert_eq!(findings.len(), 1, "0 -> 1 is a rise: {findings:?}");
    }

    #[test]
    fn the_real_tree_scans_cleanly_and_matches_its_recorded_budgets() {
        // The scanner's own acceptance test: every rule above is exercised
        // against snippets, and this proves the corpus it was built for is
        // actually covered by them — a scanner that passes its unit tests and
        // then fails on `crates/` has proved nothing.
        let root = crate::util::workspace_root().expect("the workspace root");
        let measured = measure(&root).expect("the tree must scan");
        assert!(
            measured.files.len() >= 10,
            "only {} production files found; discovery is broken",
            measured.files.len()
        );
        assert!(
            !measured
                .files
                .contains_key("crates/nic-driver-core/src/fake_device.rs"),
            "a `#[cfg(test)] mod` file is test support, not production"
        );
        assert!(
            !measured.files.keys().any(|path| path.contains("/benches/")),
            "a criterion harness is not production"
        );
        enforce(&root).expect("the recorded budgets must hold");
    }

    /// The re-record path. It is a test rather than a subcommand because
    /// `main.rs`'s dispatch is owned elsewhere in this change; the operation is
    /// the same either way, and keeping it out of [`enforce`] is what stops a
    /// check from rewriting its own expectation.
    ///
    /// The value must be non-empty, not merely present. A container runner that
    /// forwards `--env NAME="$NAME"` with `NAME` unset passes it through as the
    /// empty string, which `var_os(…).is_none()` reads as *set* — and this
    /// harness then rewrites the baseline on every ordinary gate run, so the
    /// ratchet silently records whatever it just measured and can never fail.
    /// That is not hypothetical: it is how this very check was first observed
    /// passing against numbers it had just written for itself.
    #[test]
    fn update_the_recorded_budgets() {
        if !asked_to_update(std::env::var_os(UPDATE_REQUEST).as_deref()) {
            return;
        }
        let root = crate::util::workspace_root().expect("the workspace root");
        update(&root).expect("re-record the budgets");
    }

    /// The environment variable that asks for a re-record.
    const UPDATE_REQUEST: &str = "LIBREFIREWALL_BUDGETS_UPDATE";

    /// Whether a value asks for a re-record — a pure function of the value, so
    /// the decision can be tested without mutating the process environment.
    /// Setting it in a test would race [`update_the_recorded_budgets`] running
    /// on another harness thread, and losing that race means rewriting the
    /// baseline: the exact accident being guarded against.
    fn asked_to_update(value: Option<&std::ffi::OsStr>) -> bool {
        value.is_some_and(|value| !value.is_empty() && value != "0")
    }

    #[test]
    fn an_empty_or_zero_update_request_is_not_a_request() {
        use std::ffi::OsStr;
        assert!(!asked_to_update(None));
        assert!(
            !asked_to_update(Some(OsStr::new(""))),
            "the forwarded-unset case"
        );
        assert!(!asked_to_update(Some(OsStr::new("0"))));
        assert!(asked_to_update(Some(OsStr::new("1"))));
    }

    fn scratch(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "librefirewall-budgets-{name}-{}-{unique}",
            std::process::id()
        ))
    }
}
