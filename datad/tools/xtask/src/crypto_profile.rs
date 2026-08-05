//! The cryptography profile page held to the hardware it describes.
//!
//! The page is an operator's statement of what a deployment's processor must
//! provide and of what the appliance proves on it, and both halves are
//! checkable against something that is not prose:
//!
//! * the **enabled target features** against the target specification the two
//!   SIMD protection domains are compiled with, in both directions — a feature
//!   the page claims and the specification does not enable is a claim the
//!   binary cannot keep, and one the specification enables and the page omits
//!   is a hardware requirement a deployment was never told about; and
//! * the **primitives** against `lfw_log::Primitive::ALL`, the vocabulary the
//!   cryptography domain reports in and `crypto_contract` judges its records
//!   by, so a primitive can be claimed on the page only if the domain must
//!   report it and the QEMU gate must see it.
//!
//! Those two run in the fast gate: they read a Markdown file, a JSON file and
//! an in-process array, and cost milliseconds.
//!
//! # The third check needs a binary, so it runs where one exists
//!
//! [`check_image`] disassembles the protection-domain ELFs the build just
//! produced and asserts what no source file can: that the accelerated
//! instructions are *in* them, and that the deferred tier is not. The adopted
//! cryptography crates choose a backend through compile-time feature
//! detection, so "we have AES-NI" is decided at build time and is exactly the
//! kind of fact that goes quietly untrue — a dependency bump, a target-feature
//! edit, or a `default-features` change flips it with nothing failing. Reading
//! the shipped instructions is the one check that cannot be satisfied by
//! anything except the instructions being there.
//!
//! The absence half is the more important one, and it is two absences rather
//! than one.
//!
//! The **register file**: the pinned kernel saves x87 and SSE state per thread
//! and *not* the wider vector state, so an AVX instruction executing in a
//! protection domain is state the kernel will not preserve across a context
//! switch — silent corruption rather than a fault. What keeps that tier out
//! today is that the adopted crates' runtime detection compiles to a constant
//! false on this target, which is a property of the target specification's
//! operating-system field and not something any source file states.
//!
//! The **encoding**: an instruction carrying a VEX or EVEX prefix does not
//! execute under the emulator this image is proved on, whatever registers it
//! names. The emulator refuses a vector-encoded instruction unless the vector
//! state is enabled — `CR4.OSXSAVE` and the vector bit in `XCR0` — and the
//! pinned kernel's XSAVE feature set covers x87 and SSE only, so it never
//! enables it. Real hardware imposes no such condition on the VEX-encoded
//! general-purpose instructions, which is why an image carrying them runs under
//! KVM and takes an invalid-opcode fault under emulation. A shipped instruction
//! the gate cannot exercise is one the gate's verdict does not cover, and this
//! project's rule is that the shipped profile is the tested profile — so the
//! encoding is forbidden outright rather than tolerated on the accelerator that
//! happens to run it.
//!
//! # No adversary
//!
//! Source-controlled inputs and a just-built binary, compared against each
//! other on a developer's machine. What it defends against is the ordinary
//! edit that moves one and not the other.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use lfw_log::Primitive;

use crate::{crypto_contract, image};

/// The page this module reads.
const PAGE: &str = "book/src/reference/crypto-profile.md";

/// The target specification the SIMD protection domains compile against.
const SPECIFICATION: &str = "support/targets/x86_64-sel4-simd.json";

/// Mnemonics whose presence proves an accelerated backend was compiled in, and
/// the feature each belongs to. `aesenc` and `aeskeygenassist` are AES-NI;
/// `pclmul` is the carry-less multiply GHASH runs on. A build that lost either
/// backend loses every instruction of it, because the fallback is a different
/// module rather than a different path through the same one.
const REQUIRED_INSTRUCTIONS: &[(&str, &str)] = &[("aesenc", "aes"), ("pclmul", "pclmulqdq")];

/// What must appear nowhere. `%ymm` is the register file the pinned kernel's
/// XSAVE feature set does not save, so an instruction naming one is state that
/// does not survive a context switch — and the failure would be silent
/// corruption of a cipher's internals rather than a fault.
const FORBIDDEN_OPERAND: &str = "%ymm";

/// The first byte of every vector-encoded instruction: `c4` and `c5` are the
/// three- and two-byte VEX prefixes, `62` is EVEX. In 64-bit code each of them
/// is unambiguous — `c4`/`c5` are the 32-bit-only `les`/`lds` and `62` the
/// 32-bit-only `bound`, none of which decode in long mode — so a decoded
/// instruction whose bytes start with one of these *is* vector-encoded,
/// whatever its mnemonic. That is why the check keys on the encoding and not on
/// a list of mnemonics: a list goes stale the first time a compiler picks an
/// instruction nobody wrote down, and `mulx`, `shrx`, `rorx` and `bzhi` are
/// only the ones this image happened to contain.
///
/// This is one half of what keeps the deferred tier out; the [`FORBIDDEN_OPERAND`]
/// scan below is the other. They forbid different things and neither implies
/// the other: this one refuses an *encoding* the emulator will not execute,
/// including the VEX-encoded general-purpose instructions that name no vector
/// register at all, while that one refuses a *register file* the kernel does
/// not save.
const VECTOR_ENCODING_PREFIXES: &[&str] = &["c4", "c5", "62"];

/// Hold the profile page to the target specification and to the primitive
/// vocabulary.
///
/// # Errors
/// Every disagreement found, together, so one run fixes all of them.
pub(crate) fn check(root: &Path, repository_root: &Path) -> Result<(), String> {
    let page = read(repository_root, PAGE)?;
    let mut findings = Vec::new();
    check_features(root, &page, &mut findings)?;
    check_primitives(&page, &mut findings);
    if findings.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the cryptography profile page and what this build actually does disagree:\n  - {}",
        findings.join("\n  - ")
    ))
}

/// The page's stated target features against the specification's own.
fn check_features(root: &Path, page: &str, findings: &mut Vec<String>) -> Result<(), String> {
    let path = root.join(SPECIFICATION);
    let specification =
        fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let enabled = enabled_features(&specification).ok_or_else(|| {
        format!(
            "{}: no \"features\" string, and it is what the page's feature table is compared \
             against",
            path.display()
        )
    })?;
    let stated = table_column(page, "enabled target feature");
    for feature in enabled.difference(&stated) {
        findings.push(format!(
            "{SPECIFICATION} enables `{feature}` and {PAGE} does not list it, so a deployment is \
             never told its processor must provide it — and a part without it takes an \
             invalid-opcode fault on the first instruction, not a slow path"
        ));
    }
    for feature in stated.difference(&enabled) {
        findings.push(format!(
            "{PAGE} lists `{feature}` and {SPECIFICATION} does not enable it, so the page claims \
             an acceleration the shipped binary was never compiled to use"
        ));
    }
    Ok(())
}

/// The page's stated primitives against the console vocabulary, and its
/// measured column against the ceilings the QEMU judge holds them to.
fn check_primitives(page: &str, findings: &mut Vec<String>) {
    let owed: BTreeSet<&str> = Primitive::ALL.iter().map(|one| one.name()).collect();
    let stated = table_column(page, "primitive");
    for primitive in owed.difference(&stated.iter().map(String::as_str).collect()) {
        findings.push(format!(
            "`{primitive}` is in the console's primitive vocabulary and {PAGE} does not list it, \
             so the appliance proves a primitive the page never claims"
        ));
    }
    for primitive in stated.iter().filter(|one| !owed.contains(one.as_str())) {
        findings.push(format!(
            "{PAGE} lists `{primitive}` and it is in no console vocabulary, so nothing on a \
             booted node can report it and the claim is unprovable"
        ));
    }

    let measured: BTreeSet<&str> = crypto_contract::measured_primitives()
        .iter()
        .map(|one| one.name())
        .collect();
    let claimed = table_column_where(page, "primitive", "measured", "yes");
    for primitive in measured.difference(&claimed.iter().map(String::as_str).collect()) {
        findings.push(format!(
            "the QEMU judge holds `{primitive}` to a cycles-per-byte ceiling and {PAGE} does not \
             mark it measured"
        ));
    }
    for primitive in claimed
        .iter()
        .filter(|one| !measured.contains(one.as_str()))
    {
        findings.push(format!(
            "{PAGE} marks `{primitive}` measured and no ceiling holds it, so the number it \
             reports is judged by nothing"
        ));
    }
}

/// Disassemble the SIMD protection domains just built and hold them to the
/// two halves of the acceleration claim.
///
/// # Errors
/// Every disagreement found, together.
pub(crate) fn check_image(build: &Path) -> Result<(), String> {
    let mut findings = Vec::new();
    for pd in image::SIMD_SYSTEM_PDS {
        let elf = build.join(format!("{pd}.elf"));
        let text = disassemble(&elf)?;
        if *pd == "crypto" {
            for (mnemonic, feature) in REQUIRED_INSTRUCTIONS {
                if !text.contains(mnemonic) {
                    findings.push(format!(
                        "{} carries no `{mnemonic}` instruction, so the `{feature}` backend the \
                         profile claims is not the one that was compiled in — the adopted crates \
                         chose their portable fallback and every published vector would still \
                         answer",
                        elf.display()
                    ));
                }
            }
        }
        if text.contains(FORBIDDEN_OPERAND) {
            findings.push(format!(
                "{} names a `{FORBIDDEN_OPERAND}` register. The pinned kernel saves x87 and SSE \
                 state per thread and not the wider vector state, so that register does not \
                 survive a context switch: this is silent corruption of whatever holds it, not a \
                 fault an operator would see",
                elf.display()
            ));
        }
        if let Some((mnemonic, count)) = vector_encoded(&text) {
            findings.push(format!(
                "{} carries {count} vector-encoded instruction(s), `{mnemonic}` among them. The \
                 emulator this image is proved on refuses a VEX- or EVEX-encoded instruction \
                 unless the vector state is enabled, and the pinned kernel's XSAVE feature set \
                 covers x87 and SSE only, so it never is: the instruction takes an invalid-opcode \
                 fault under emulation and runs under KVM, which makes the gate's verdict depend \
                 on the machine it ran on. The shipped profile is the tested profile, so this \
                 encoding is refused rather than shipped on the accelerator that happens to \
                 execute it — disable the target feature that produced it",
                elf.display()
            ));
        }
    }
    if findings.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the shipped protection domains do not carry the instructions the cryptography profile \
         claims:\n  - {}",
        findings.join("\n  - ")
    ))
}

/// The first vector-encoded instruction in a disassembly, with how many there
/// are — the mnemonic so a reader knows what to look for, the count so a reader
/// knows whether it is one stray instruction or a whole backend.
///
/// objdump lays out a disassembled line as address, raw bytes and text,
/// tab-separated, which is why [`disassemble`] asks for the bytes: the leading
/// byte of the middle field is the encoding itself, and reading it is what makes
/// this check unable to go stale.
fn vector_encoded(text: &str) -> Option<(String, usize)> {
    let mut first = None;
    let mut count = 0;
    for line in text.lines() {
        let mut fields = line.split('\t');
        let (Some(_address), Some(bytes), Some(instruction)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(leading) = bytes.split_whitespace().next() else {
            continue;
        };
        if !VECTOR_ENCODING_PREFIXES.contains(&leading) {
            continue;
        }
        count += 1;
        if first.is_none() {
            first = Some(
                instruction
                    .split_whitespace()
                    .next()
                    .unwrap_or(instruction)
                    .to_owned(),
            );
        }
    }
    first.map(|mnemonic| (mnemonic, count))
}

fn disassemble(elf: &PathBuf) -> Result<String, String> {
    let output = Command::new("objdump")
        .arg("--disassemble")
        .arg(elf)
        .output()
        .map_err(|error| format!("disassemble {}: {error}", elf.display()))?;
    if !output.status.success() {
        return Err(format!(
            "disassemble {}: objdump exited {}",
            elf.display(),
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The `+`-prefixed entries of a target specification's `features` string.
fn enabled_features(specification: &str) -> Option<BTreeSet<String>> {
    let at = specification.find("\"features\"")?;
    let rest = specification.get(at..)?;
    let open = rest.find(':')? + 1;
    let quoted = rest.get(open..)?;
    let start = quoted.find('"')? + 1;
    let body = quoted.get(start..)?;
    let end = body.find('"')?;
    Some(
        body.get(..end)?
            .split(',')
            .filter_map(|entry| entry.strip_prefix('+'))
            .map(str::to_owned)
            .collect(),
    )
}

/// The backticked tokens in the column headed `heading`, across every table on
/// the page that has one.
fn table_column(page: &str, heading: &str) -> BTreeSet<String> {
    collect(page, heading, None)
}

/// The same, kept to the rows whose `filter` column reads `wanted`.
fn table_column_where(page: &str, heading: &str, filter: &str, wanted: &str) -> BTreeSet<String> {
    collect(page, heading, Some((filter, wanted)))
}

fn collect(page: &str, heading: &str, filter: Option<(&str, &str)>) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut columns: Option<Vec<String>> = None;
    for line in page.lines() {
        let trimmed = line.trim();
        let Some(body) = trimmed.strip_prefix('|').and_then(|l| l.strip_suffix('|')) else {
            columns = None;
            continue;
        };
        let cells: Vec<String> = body.split('|').map(|cell| cell.trim().to_owned()).collect();
        // A separator row (`|---|---|`) follows the header and carries no
        // values, so it is skipped rather than read as one.
        if cells
            .iter()
            .all(|cell| !cell.is_empty() && cell.bytes().all(|byte| byte == b'-' || byte == b':'))
        {
            continue;
        }
        let Some(header) = &columns else {
            columns = Some(cells);
            continue;
        };
        let Some(at) = header.iter().position(|name| name == heading) else {
            continue;
        };
        if let Some((filter_name, wanted)) = filter {
            let Some(which) = header.iter().position(|name| name == filter_name) else {
                continue;
            };
            if cells.get(which).map(String::as_str) != Some(wanted) {
                continue;
            }
        }
        if let Some(token) = cells.get(at).and_then(|cell| backticked(cell)) {
            found.insert(token);
        }
    }
    found
}

/// The content of the first pair of backticks in `cell`, which is how every
/// token on the page is written.
fn backticked(cell: &str) -> Option<String> {
    let start = cell.find('`')? + 1;
    let rest = cell.get(start..)?;
    let end = rest.find('`')?;
    Some(rest.get(..end)?.to_owned())
}

fn read(repository_root: &Path, page: &str) -> Result<String, String> {
    let path = repository_root.join(page);
    fs::read_to_string(&path).map_err(|error| {
        format!(
            "read {}: {error}. The profile page is what this check compares against, so a page \
             that cannot be read is a failure rather than a check that passes",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests;
