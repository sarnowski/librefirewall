# Updates and secure boot

The appliance updates as a **whole signed system image using two A/B slots**, not by patching a
running system. This suits the static Microkit component model — where the hardware topology is
fixed at build time, so a hardware change is a new image (see
[Configuration](configuration.md#static-hardware-dynamic-configuration)) — and gives an automatic,
power-fail-safe path back to the last known-good software.

## On-disk layout

The deployable artifact is a GPT disk image (`librefirewall-qemu-x86_64.img`) with fixed slots:

| Partition | Purpose |
|---|---|
| **ESP** | The boot manager (`EFI/BOOT/BOOTX64.EFI`) |
| **STATE** | Mutable boot-selection state (`grubenv`) |
| **SLOT_A** | A complete signed release: seL4 kernel + Microkit system image (+ detached signatures) |
| **SLOT_B** | The second release slot, identical structure |
| **DATA** | The node's own state — configuration, identity, and secrets (see [Management plane](management.md) and [Configuration](configuration.md)) — and nothing that grows with traffic |

Each slot is self-contained because x86 Microkit boots a separate seL4 kernel ELF plus the Microkit
system image as a Multiboot2 module — both must be present and version-matched in the slot.

**This table describes the boot medium, not the whole of a node's storage.** Configuration and
identity are written in bytes per day and belong here, so that a node carries everything it needs to
come up as itself. The [recording rings](recording.md) do not: a capture ring rewrites its medium
continuously, its write-endurance profile is not comparable to configuration's, and a single
sequential writer per device is what obtains a device's bandwidth. Rings are therefore bound to
their own devices or partitions, resolved at boot (see
[Storage devices and binding](recording.md#storage-devices-and-binding)), and how many devices a
build drives is part of its static topology — so a deployment target's storage is this layout plus
whatever that variant grants it to record onto.

## Boot manager and slot selection

The boot manager is **GRUB** (built from pinned source as a minimal standalone `x86_64-efi`
image with an embedded, immutable configuration and a curated module allowlist). GRUB is chosen
because it is the one common bootloader that natively speaks the x86 Multiboot2 contract seL4
requires, while also supporting UEFI, signature verification, and a persistent environment.

Selection uses the proven `OK`/`TRY`/`ORDER` scheme (as in RAUC's GRUB integration), which is what
stock GRUB scripting can express without arithmetic: a confirmed slot (`*_OK`) boots immediately; an
unconfirmed slot is tried once (its `*_TRY` flag is set before hand-off) and, if it never confirms
health, the next slot in `ORDER` is used. The single-attempt model is a deliberate limitation of
in-bootloader logic; a multi-attempt counter and a redundant, generation-numbered state log belong
to the writable-state owner below, not to GRUB.

Confirming a freshly booted slot as healthy (setting `*_OK`) is done **off the boot path**, by an
in-system update/health protection domain holding capabilities to exactly the inactive slot and
the STATE partition and nothing else. That component is where staged installation, health
confirmation, multi-attempt counting, and redundant crash-safe state live.

## Payload trust

Every slot's kernel and system image is signed; GRUB carries the corresponding public key embedded
in its core image and **enforces detached-signature verification** on every file it loads. This
authenticates the payload independently of the medium it sits on. The boot-selection state is
loaded unverified (it only *chooses among* already-signed slots and can never inject code).

Development builds generate a local, throwaway signing key (never committed); the release manifest
records `trust_profile: development` and the key fingerprint so a development-signed image can never
be mistaken for a production one.

## Firmware and the seL4 hand-off contract

The target is **UEFI** (a prerequisite for the eventual Secure Boot goal). Booting seL4 under
UEFI+GRUB imposes hand-off constraints that shape the boot chain:

- seL4's x86 Multiboot2 path takes the **ACPI RSDP from the Multiboot2 ACPI tag** GRUB provides, so
  ACPI works under UEFI without the legacy BIOS memory scan.
- The seL4 boot module (the Microkit system image) must load **above** the kernel image; GRUB's
  relocator satisfies this, but it remains a real constraint on memory-constrained targets.
- **The debug kernel takes its serial console from the kernel command line**, so the kernel must be
  given its `console_port`/`debug_port` on the Multiboot2 command line or it boots silently. The
  **IOMMU is left enabled** (Microkit's x86 default); on a platform without VT-d seL4 reports zero
  IOMMUs.

## Deliberately deferred

- **UEFI Secure Boot** and its key hierarchy (enrolling a librefirewall platform key; signing the
  EFI binary). The payload-signing and A/B mechanics above are independent of, and ready for, it.
- **TPM-backed anti-rollback** (a monotonic security epoch preventing downgrade to a known-vulnerable
  signed release).
- **The in-system update/health PD** and the staged, transactional, multi-cluster rollout that
  builds on the [configuration-management workflow](configuration.md).
- **Redundant, crash-safe boot state.** Stock `grubenv` is a single in-place block; torn-write-safe
  redundant state is part of the update-PD work, not the bootloader.
- **Virtualised/cloud targets** (Proxmox, Azure) are expected to use image/generation replacement at
  the hypervisor or load-balancer level rather than guest-managed A/B, reusing the same signed
  release and compatibility contract.
