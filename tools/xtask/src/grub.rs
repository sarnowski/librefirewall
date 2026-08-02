//! The signed GRUB boot base.
//!
//! GRUB is the boot manager: a minimal standalone `x86_64-efi`
//! core image built with a curated module allowlist
//! (`third-party/grub/modules.txt`), an immutable embedded configuration
//! (`third-party/grub/grub.cfg`), and the librefirewall public key baked in —
//! which is what makes signature verification on every subsequently loaded file
//! mandatory. This module builds that core image and seeds the initial grubenv
//! that the A/B slot-selection scheme reads.

use std::{fs, path::Path, process::Command};

use crate::util::{Error, capture_stdout, run_command};

const GRUB_MODULES_DIR: &str = "/opt/grub/lib/grub/x86_64-efi";

/// Where conventional memory ends on a PC-compatible machine. Above this sit
/// the VGA aperture and the option ROMs, which firmware reports as reserved, so
/// no allocator places a boot module there.
const CONVENTIONAL_LOW_MEMORY_END: u64 = 0x000A_0000;

/// Build the standalone GRUB `x86_64-efi` core image at `output`, embedding
/// `pubkey` as the trust anchor.
///
/// Embedding the key is what makes verification *mandatory*: GRUB refuses to
/// load any file lacking a valid detached signature from a key it was built
/// with, so this image and the payload signatures must come from the same key.
pub(crate) fn build_grub_efi(root: &Path, pubkey: &Path, output: &Path) -> Result<(), Error> {
    let modules_path = root.join("third-party/grub/modules.txt");
    let modules_file = fs::read_to_string(&modules_path)
        .map_err(|error| Error::io("read", &modules_path, error))?;
    // One module per line; `#` comments (the header documenting the allowlist)
    // and blank lines are ignored.
    let modules = modules_file
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    let config = root.join("third-party/grub/grub.cfg");
    run_command(
        Command::new("grub-mkstandalone")
            .current_dir(root)
            .arg(format!("--directory={GRUB_MODULES_DIR}"))
            .arg("--format=x86_64-efi")
            .arg(format!("--modules={modules}"))
            .arg("--pubkey")
            .arg(pubkey)
            .arg("--output")
            .arg(output)
            .arg(format!("boot/grub/grub.cfg={}", config.display())),
        "build standalone grub EFI image",
    )
}

/// Refuse a system image small enough for GRUB to load below the seL4 kernel.
///
/// seL4's x86 boot derives the userland image's load address from the end of
/// the last boot module, and its available-region list still contains the
/// memory its own kernel image occupies — so a boot module placed *below* the
/// kernel makes seL4 load the userland image on top of the running kernel and
/// triple-fault before any protection domain executes. `grub.cfg` therefore
/// cuts conventional memory between [`low_memory_window`]'s bounds; what is
/// left is [`low_memory_window`] bytes, and an image that fits is one GRUB may
/// still place there.
///
/// This is the check that keeps that reservation honest, because nothing else
/// would: the failure is a triple fault before the first byte of output, in a
/// configuration whose kernel cannot print, and it is reached only when a
/// system image happens to shrink past the window.
///
/// # Errors
/// [`Error::Invalid`] naming both sizes when the image would fit, and whatever
/// [`low_memory_window`] rejects about the configuration itself.
pub(crate) fn check_boot_module_placement(root: &Path, system_image: &Path) -> Result<(), Error> {
    let window = low_memory_window(root)?;
    let size = fs::metadata(system_image)
        .map_err(|error| Error::io("read", system_image, error))?
        .len();
    judge_boot_module_size(system_image, size, window)
}

/// The verdict [`check_boot_module_placement`] reaches once it has both
/// numbers. Separate so the decision — and the sentence it fails with, which is
/// the whole of what an operator gets — is host-testable without a build tree.
///
/// Strictly greater, not greater-or-equal: an image exactly the size of the
/// window still fits it.
fn judge_boot_module_size(system_image: &Path, size: u64, window: u64) -> Result<(), Error> {
    if size > window {
        return Ok(());
    }
    Err(Error::invalid(format!(
        "{} is {size} bytes, which fits the {window} bytes of conventional memory below 1 MiB \
         that third-party/grub/grub.cfg still leaves GRUB. A boot module placed there sits below \
         the seL4 kernel image, and seL4 then loads the userland image over its own kernel and \
         triple-faults before any protection domain runs. Lower the reservation's first bound in \
         grub.cfg so the remaining window is smaller than this image.",
        system_image.display()
    )))
}

/// The largest run of conventional memory below 1 MiB that `grub.cfg` still
/// leaves GRUB to allocate a boot module from.
///
/// Read out of the configuration rather than restated here, so the bound this
/// build is checked against is the bound the shipped boot manager applies
/// — one fact, stated once, in the file that acts on it.
///
/// # Errors
/// [`Error::Invalid`] when the configuration carries no `cutmem` reservation at
/// all, or one whose bounds do not parse — either of which would silently
/// restore the whole 640 KiB and with it the fault above.
fn low_memory_window(root: &Path) -> Result<u64, Error> {
    let path = root.join("third-party/grub/grub.cfg");
    let config = fs::read_to_string(&path).map_err(|error| Error::io("read", &path, error))?;
    let window = parse_low_memory_window(&config).ok_or_else(|| {
        Error::invalid(format!(
            "{} carries no parsable `cutmem <from> <to>` reservation. Without it GRUB may place \
             the boot module in the 640 KiB below 1 MiB, which puts it below the seL4 kernel \
             image and makes seL4 load the userland image over its own kernel.",
            path.display()
        ))
    })?;
    Ok(window)
}

/// The window [`low_memory_window`] reports, computed from a configuration's
/// text. Separate so the arithmetic is host-testable without a checkout layout.
///
/// Every `cutmem FROM TO` line is applied to the conventional region
/// `[0, CONVENTIONAL_LOW_MEMORY_END)` and the widest surviving run is returned.
/// `None` when no line parsed, which is a configuration that reserves nothing.
fn parse_low_memory_window(config: &str) -> Option<u64> {
    let mut cuts = Vec::new();
    for line in config.lines() {
        // The reservation sits inside grub.cfg's fail-closed `if ! cutmem …;
        // then` guard, so both the leading test and the trailing `; then` are
        // part of the line the bounds must be read out of.
        let statement = line
            .trim()
            .trim_start_matches("if ! ")
            .trim_start_matches("! ");
        let statement = statement.split(';').next().unwrap_or(statement);
        let Some(rest) = statement.strip_prefix("cutmem ") else {
            continue;
        };
        let mut bounds = rest.split_whitespace();
        let from = bounds.next().and_then(parse_address)?;
        let to = bounds.next().and_then(parse_address)?;
        if from > to {
            return None;
        }
        cuts.push((from, to));
    }
    if cuts.is_empty() {
        return None;
    }
    cuts.sort_unstable();
    // Walk the conventional region, taking the widest gap between the cuts. A
    // cut that starts below the cursor only moves it forward.
    let mut widest = 0;
    let mut cursor = 0;
    for (from, to) in cuts {
        if from > cursor {
            widest = widest.max(from.min(CONVENTIONAL_LOW_MEMORY_END) - cursor);
        }
        cursor = cursor.max(to.saturating_add(1));
        if cursor >= CONVENTIONAL_LOW_MEMORY_END {
            return Some(widest);
        }
    }
    Some(widest.max(CONVENTIONAL_LOW_MEMORY_END - cursor))
}

/// A `cutmem` bound, hexadecimal or decimal as GRUB itself accepts.
fn parse_address(text: &str) -> Option<u64> {
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or_else(
            || text.parse::<u64>().ok(),
            |hex| u64::from_str_radix(hex, 16).ok(),
        )
}

/// Report the version of the GRUB installation the core image is built from.
///
/// The manifest records the pinned GRUB version as provenance, so the build
/// asks the tool that will actually produce the boot base rather than trusting
/// the pin to describe whatever happens to be installed.
pub(crate) fn installed_version(pinned: &str) -> Result<(), Error> {
    let reported = capture_stdout(
        Command::new("grub-mkstandalone").arg("--version"),
        "read grub version",
    )?;
    // `grub-mkstandalone (GRUB) 2.14` — the pin is a substring, not the whole
    // line, and distribution builds append a packaging suffix.
    if reported.contains(pinned) {
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "GRUB at {GRUB_MODULES_DIR} reports {:?}, expected the pinned version {pinned:?}",
            reported.trim()
        )))
    }
}

/// Seed the initial boot-selection env: slot A confirmed, B staged but
/// unconfirmed, A tried first. This is the state the freshly built base image
/// ships with; the A/B harness and (later) the update PD rewrite it.
pub(crate) fn seed_grubenv(grubenv: &Path) -> Result<(), Error> {
    run_command(
        Command::new("grub-editenv").arg(grubenv).arg("create"),
        "create grubenv",
    )?;
    run_command(
        Command::new("grub-editenv")
            .arg(grubenv)
            .arg("set")
            .arg("ORDER=A B")
            .arg("A_OK=1")
            .arg("A_TRY=0")
            .arg("B_OK=0")
            .arg("B_TRY=0"),
        "seed grubenv",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reservation the shipped configuration actually applies. This is the
    /// test that fails on a tree where the `cutmem` line is absent or has been
    /// widened back — which is the state that boots a release image into a
    /// triple fault with no output at all.
    #[test]
    fn the_shipped_configuration_reserves_low_memory_away_from_the_boot_module() {
        let config = include_str!("../../../third-party/grub/grub.cfg");
        let window =
            parse_low_memory_window(config).expect("grub.cfg must carry a cutmem reservation");
        // A ceiling, met at equality: the shipped reservation leaves exactly
        // this much, so the window may shrink freely and may never widen. Small
        // enough that no system image this project assembles can fit — the
        // release image, the smallest yet built, is over half a megabyte.
        const CEILING: u64 = 64 * 1024;
        assert!(
            window <= CEILING,
            "grub.cfg leaves GRUB {window} bytes below 1 MiB for a boot module, past the \
             {CEILING}-byte ceiling"
        );
    }

    #[test]
    fn an_image_that_fits_the_remaining_window_fails_the_build_by_name() {
        // The branch the whole guard exists for. It must name both numbers:
        // the fix is to lower the reservation's bound, and an operator cannot
        // pick a new one without knowing what the image and the window are.
        let image = Path::new("build/image/release/system.img");
        let refused = judge_boot_module_size(image, 40_000, 0x10000)
            .expect_err("an image smaller than the window must be refused");
        let message = refused.to_string();
        assert!(message.contains("40000"), "{message}");
        assert!(message.contains("65536"), "{message}");
        assert!(message.contains("system.img"), "{message}");

        // The boundary: equal still fits the window, so it is refused too.
        assert!(judge_boot_module_size(image, 0x10000, 0x10000).is_err());
        assert!(judge_boot_module_size(image, 0x10001, 0x10000).is_ok());
    }

    #[test]
    fn the_shipped_system_image_sizes_clear_the_shipped_window() {
        // The two sizes this defect was actually decided by: the release image
        // that fitted low memory and triple-faulted, and the debug image that
        // did not and booted. Under the reservation both clear the window, so
        // neither can be placed below the kernel.
        let window = parse_low_memory_window(include_str!("../../../third-party/grub/grub.cfg"))
            .expect("grub.cfg must carry a cutmem reservation");
        let image = Path::new("system.img");
        assert!(judge_boot_module_size(image, 589_556, window).is_ok());
        assert!(judge_boot_module_size(image, 603_012, window).is_ok());
    }

    #[test]
    fn a_configuration_with_no_reservation_is_refused() {
        // The pre-fix state: nothing is cut, so the whole 640 KiB is a place
        // GRUB may put the boot module.
        assert_eq!(parse_low_memory_window("set timeout=0\nboot\n"), None);
    }

    #[test]
    fn the_window_is_what_the_cut_leaves_below_conventional_memory() {
        assert_eq!(
            parse_low_memory_window("cutmem 0x10000 0x9ffff\n"),
            Some(0x10000)
        );
        // Cutting from zero leaves only the tail above the cut.
        assert_eq!(
            parse_low_memory_window("cutmem 0x0 0x7ffff\n"),
            Some(CONVENTIONAL_LOW_MEMORY_END - 0x80000)
        );
        // The whole conventional region cut leaves nothing.
        assert_eq!(parse_low_memory_window("cutmem 0x0 0x9ffff\n"), Some(0));
    }

    #[test]
    fn the_reservation_is_recognised_through_the_fail_closed_wrapper() {
        // grub.cfg guards the command so a refused reservation halts rather
        // than boots; the bound must still be read out of that form.
        assert_eq!(
            parse_low_memory_window("if ! cutmem 0x10000 0x9ffff; then\n  halt\nfi\n"),
            Some(0x10000)
        );
    }

    #[test]
    fn several_cuts_report_the_widest_surviving_run() {
        // Two disjoint cuts leaving 0x10000..0x20000 and 0x30000..0xa0000; the
        // second is wider and is the one a boot module could use.
        assert_eq!(
            parse_low_memory_window("cutmem 0x0 0xffff\ncutmem 0x20000 0x2ffff\n"),
            Some(CONVENTIONAL_LOW_MEMORY_END - 0x30000)
        );
    }

    #[test]
    fn an_unparsable_or_inverted_bound_is_refused_rather_than_ignored() {
        // Silently skipping a malformed line would report the window of the
        // lines that did parse and call a broken reservation good.
        assert_eq!(parse_low_memory_window("cutmem 0x10000\n"), None);
        assert_eq!(parse_low_memory_window("cutmem lo hi\n"), None);
        assert_eq!(parse_low_memory_window("cutmem 0x9ffff 0x10000\n"), None);
    }

    #[test]
    fn both_radices_grub_accepts_are_read() {
        assert_eq!(parse_address("0x10000"), Some(0x10000));
        assert_eq!(parse_address("65536"), Some(65536));
        assert_eq!(parse_address("0xzz"), None);
    }
}
