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
| **DATA** | Reserved and unused — the node's own state lives on the [store device](#the-store-device), not on the boot medium |

Each slot is self-contained because x86 Microkit boots a separate seL4 kernel ELF plus the Microkit
system image as a Multiboot2 module — both must be present and version-matched in the slot.

**This table describes the boot medium, and the boot medium carries software, never state.**
Nothing inside seL4 holds a capability on the boot disk, and nothing inside seL4 parses a partition
table or a filesystem — the FAT the slots use is written host-side at build time and read by GRUB,
which is C code inside the signed boot base and outside this codebase. A node's own state and its
[recording rings](recording.md) live on devices of their own, in raw sectors under first-party
formats, resolved at boot (see
[Storage devices and binding](recording.md#storage-devices-and-binding)). How many devices a build
drives is part of its static topology — so a deployment target's storage is this layout plus the
store device below plus whatever that variant grants it to record onto.

## The store device

The node's own state — the device identity, the delivered trust anchor and endpoint, the onboarding
state, and the [configuration history](configuration.md#persistence) — lives on a **third virtio-blk
device, owned by a dedicated store domain**. The alternatives were rejected: widening the recorder
would put the device private key in the highest-throughput writer domain in the system, and two
domains cannot own one virtio-blk device — so a domain of its own is the only shape that keeps the
key where the [architecture](architecture.md#key-custody) requires it, held and used by exactly one
domain.

The store is **raw sectors under a first-party format** — the double-buffered state record and slot
array of the [configuration design](configuration.md#persistence) — never a filesystem. Downloading
and installing new appliance software is deliberately **not** part of the management plane: it has a
different medium (the boot disk, which nothing inside seL4 can reach), a different owner (the
update/health protection domain), a different format, and a different threat model. Because of that
split the boot disk never needs to be reached from inside the system for management's sake, and no
filesystem implementation exists in the appliance at all.

## Factory reset

Factory reset is **local-only and never remotely triggerable** — no channel operation, no
configuration document, and no management-server action can invoke it, because it is the mechanism
that revokes a management plane's ownership and must not be reachable by one. It wipes the device
private key, the issued certificate, the trust anchor, the endpoint, the configuration history, and
the recordings, returning the appliance to unowned — ready for
[onboarding](management.md#onboarding) as if factory-fresh. It **overwrites** the stored bytes
rather than marking them free, because the store medium holds the key in plaintext (see the
[threat model](threat-model.md)) and a freed sector is a kept secret. It emits a console record, so
the one surface an unowned appliance has states what happened.

## Boot manager and slot selection

The boot manager is **GRUB**, reduced to the modules it needs and carrying an embedded, immutable
configuration — so the selection logic is part of the verified boot base rather than something read
from writable media. GRUB is chosen because it is the one common bootloader that natively speaks the
x86 Multiboot2 contract seL4 requires, while also supporting UEFI, signature verification, and a
persistent environment.

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

A release records the trust profile it was signed under, so a development-signed image can never be
mistaken for a production one. Signature verification authenticates a release but does not order
releases, so downgrade to a known-vulnerable signed release is prevented separately, by a monotonic
security epoch held in a TPM.

## Firmware and the seL4 hand-off contract

The target is **UEFI** (a prerequisite for the eventual Secure Boot goal). Booting seL4 under
UEFI+GRUB imposes hand-off constraints that shape the boot chain:

- seL4's x86 Multiboot2 path takes the **ACPI RSDP from the Multiboot2 ACPI tag** GRUB provides, so
  ACPI works under UEFI without the legacy BIOS memory scan.
- The seL4 boot module (the Microkit system image) must load **above** the kernel image. seL4 places
  the userland image at the end of the last boot module and never checks that against where its own
  kernel sits, so a module loaded below the kernel makes seL4 write the userland image over the
  kernel it is running on, before any protection domain starts. **GRUB does not honour this
  contract**: its relocator takes the lowest free range that fits, and on `x86_64-efi` the
  conventional memory below 1 MiB is free. What holds the property is therefore the embedded
  configuration reserving that memory away from GRUB, together with a build-time check refusing a
  system image small enough to fit whatever the reservation leaves. Neither is redundant, and the
  failure they prevent is silent.
- **The debug kernel takes its serial console from the kernel command line**, so the kernel must be
  given its `console_port`/`debug_port` on the Multiboot2 command line or it boots silently.
- The **IOMMU is left enabled** (Microkit's x86 default), and on a platform without VT-d seL4
  reports zero IOMMUs. Enabling it is not confinement: a device's DMA is bounded only once that
  device is placed in an IOMMU domain, which is what the
  [threat model's DMA isolation](threat-model.md#isolation-model) requires and what the hand-off
  contract alone does not provide.

## Scope of the slot mechanism

**Virtualised and cloud targets do not use guest-managed A/B.** On Proxmox and Azure an update is
image or generation replacement at the hypervisor or load-balancer level, reusing the same signed
release and compatibility contract rather than the slot mechanics above.
