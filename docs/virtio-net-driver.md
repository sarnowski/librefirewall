# ADR: virtio-net driver protection domain

## Status

Implemented (two-port zero-copy forwarding), QEMU q35, and shipped as **the** deployable system:
`systems/qemu-x86_64/librefirewall.system` is what `make image` assembles into the signed A/B
disk. `pds/nic-driver` brings up a modern virtio-net-pci device from static capabilities and
drives both its receive and transmit virtqueues; the same binary is instantiated once per NIC,
each instance patched with its own device windows. `pds/forwarder` sits between the two ports and
moves frame descriptors from each port's receive ring to the other port's transmit ring;
`crates/virtio` carries the split virtqueue and the first-party PCI transport (`pci.rs`). The
`test-system` gate (in `make ci`) boots the disk through OVMF and GRUB with two `socket` netdevs,
injects a distinct frame into each port, and asserts each egresses byte-identical on the opposite
port; the A/B fallback scenarios use the same forwarding contract as their boot-health proof.
MSI-X interrupts (the drivers poll) and real-hardware bring-up (BAR discovery, VT-d) remain future
work — see Open decisions below, which are kept as the record of what the QEMU slice deliberately
does not yet solve.

The constraints and decisions below reflect what the working driver relies on; where the QEMU slice
resolved a decision, it is marked **[resolved for QEMU]**.

## Context

The current system is two Rust PDs joined by a Microkit channel, with a synthetic producer feeding
a consumer and a serial success marker verified in QEMU. The next dataplane slice
(AGENTS dev-order step 3; CONCEPT §6.2) is a real Rx source:

```text
virtio driver -> Rx queue -> classifier -> filter shard -> Tx queue
```

virtio-net is the foundational NIC driver (CONCEPT §9) and is written from scratch in Rust,
drawing on ixy.rs register logic (CONCEPT §8), over our own split virtqueue (`crates/virtio`) —
not the external `virtio-drivers` crate. rust-sel4 v5.0.0 ships `sel4-virtio-net` /
`sel4-virtio-hal-impl` and the `virtio-drivers` crate, but every shipped example is virtio-MMIO on
ARM: there is no x86 PCI example and no PCI wiring in the SDK, so those crates do not carry the
work for us here.

## Constraints (seL4 Microkit 2.3.0 + rust-sel4 v5.0.0, board `x86_64_generic`)

These are binding, not preferences.

- **Target/boot.** x86_64 only. Boot is OVMF (UEFI) -> GRUB -> Multiboot2 -> seL4 (already in
  place; CONCEPT §14), machine QEMU q35.
- **Static topology.** Device MMIO, IRQ, and DMA capabilities are fixed at build time in the
  `.system` description and enforced by the kernel. There is no runtime device discovery-and-grant
  path: "dynamic hardware addressing" is not a runtime configuration concern but a build-time
  pinning problem.
- **Transport.** On QEMU q35, virtio-net is a PCI device (`virtio-net-pci`, virtio 1.0 modern),
  not MMIO.

The `.system` mechanisms available on x86 (Microkit manual) the driver PD must use:

- **Device MMIO (BARs):** `<memory_region ... phys_addr="0x…"/>` mapped with
  `<map ... cached="false" setvar_vaddr="…"/>`.
- **DMA regions** (virtqueue rings + packet buffers the device DMAs into): a `<memory_region>` used
  with `<setvar symbol=… region_paddr=…/>` **must** declare an explicit `phys_addr` on x86 — a
  region without one fails `region_paddr`. DMA regions therefore need a fixed `phys_addr`, both
  `setvar_vaddr` and `region_paddr`, and are mapped cached.
- **Interrupts:** `<irq>` in IOAPIC form (`id`, `pin`, `vector`, `ioapic?`, `trigger?`,
  `polarity?`) or MSI form (`id`, `pcidev` as `BUS:DEV.FUNC` hex, `handle`, `vector`). The
  interrupt reaches the PD as a Microkit channel notification, acked via `Channel::irq_ack`. The
  `IRQControl` root cap is held by tooling, not the PD; the source→IRQ mapping is declarative in the
  `.system`, and the PD only ever holds a notification + ack cap.
- **x86 port I/O:** `<ioport addr= size= id=/>` grants ports; runtime access is via the C helpers
  `microkit_x86_ioport_read/write_{8,16,32}`. There is **no** Rust binding in `sel4-microkit`
  v5.0.0, so any port I/O requires a small FFI/asm shim.
- **IOMMU/VT-d:** Microkit leaves the IOMMU enabled by default on x86 (CONCEPT §14.4), so device
  DMA is blocked unless an `<io_address_space>` (`name`, `peripheral_id` matching the IOMMU device
  id, `domain_id`) with `<iomap mr= iovaddr= perms=/>` maps the DMA regions into the device's IO
  address space. This is also the CONCEPT §7 DMA-isolation mechanism.

## Open decisions

To be resolved in the driver PD step; framed here, not settled.

### PCI config-space access (central risk — CONCEPT §13.2)

No SDK helper exists. Options: (a) map ECAM/MMCONFIG as a `phys_addr` `<memory_region>` and read
config space over MMIO; or (b) grant the legacy `0xCF8`/`0xCFC` config ports via `<ioport>` and
drive them (requires the port-I/O FFI shim above). The tension is a chicken-and-egg: the modern
virtio BARs must be known at build time to map them as `phys_addr` regions, but BARs are assigned
by firmware at runtime. Because the `.system` model forces static mapping, we must either pin the
BAR layout or discover-then-map — and static pinning is what the model actually permits.

**[resolved for QEMU]** Each driver instance maps the q35 ECAM page of its pinned device
(`00:02.0` and `00:03.0`) and reads config space over MMIO — option (a), no `<ioport>` shim
needed. The ECAM base is firmware-programmed (PCIEXBAR) and therefore part of the boot contract:
OVMF places it at `0xE0000000`, which is what the `.system` pins (SeaBIOS would use `0xB0000000`,
but the deployable image boots only through OVMF). The driver then sidesteps the chicken-and-egg
by **reprogramming** the device's modern MMIO BAR to the fixed address that instance pre-maps
(`0x50000000` / `0x50004000`, patched into the binary via `region_paddr`), so the `.system` is
self-consistent and independent of what the firmware assigned. On real hardware the reprogram
target must be a validated free MMIO range (and BAR discovery/sizing generalised); that remains
open and ties to CONCEPT §13.2.

### IRQ model

MSI-X (the natural fit for virtio-pci) vs a legacy IOAPIC line. The Microkit `<irq>` MSI form needs
the device BDF (`pcidev`) and a `handle`; the IOAPIC form needs `pin`/`vector`.

**[resolved for QEMU]** The drivers take **no interrupt** — each polls its receive and transmit
used rings by never returning from `init`, throttled by the scheduler, with the forwarder at
higher priority so the busy loops do not starve it (research confirmed Microkit has no periodic
wakeup, so this is the only interrupt-free option; the two same-priority drivers round-robin on
timeslice). MSI-X remains the target for a production, latency-sensitive driver; it needs the MSI
Message-Address encoding, which the SDK does not document (seL4 Reference Manual, §x86
interrupts).

### DMA / IOMMU

Whether to declare an `<io_address_space>` for the virtio device or to run with the IOMMU's effects
understood. Either way DMA regions need fixed `phys_addr`.

**[resolved for QEMU]** Plain q35 exposes **no** vIOMMU, so seL4 reports zero IOMMUs and device DMA
is unrestricted — no `<io_address_space>` is used, and `virtio-net-pci iommu_platform=off` means the
device DMAs to raw physical addresses. The virtqueue regions (`0x30000000`/`0x30001000`) and the
two pipeline regions (`0x31000000`/`0x31040000`) are RAM pinned with `region_paddr`. On real
hardware (or with `-device intel-iommu`) VT-d confinement per CONCEPT §7 becomes mandatory and this
decision reopens.

### Untrusted-device hardening

The device is external input and is not trusted (AGENTS: treat neighbours as untrusted; bound
externally-driven state). The `crates/virtio` queue already rejects an out-of-range used `id` so a
malformed completion cannot drive an out-of-bounds recycle. The driver PD owns the rest: it
rejects completions for descriptors not currently in flight (double-completion) on both queues,
bounds the device-reported receive length against the buffer, and validates every transmit
descriptor arriving from the neighbouring forwarder PD (index, span, header room) before touching
the span — none of these panic on device- or neighbour-controlled input. Accounting for
leaked/never-completed descriptors and handling `DEVICE_NEEDS_RESET` remain open.

### Alternative considered: QEMU `microvm`

The `microvm` machine exposes virtio-MMIO at fixed addresses with IOAPIC IRQs and no PCI, which
would sidestep PCI config-space discovery entirely. It does not fit our OVMF/GRUB/A-B UEFI boot
chain (CONCEPT §14), so it is at most a fallback/experiment for isolating the virtqueue/driver
logic, never the target.

## Design (as built)

The system is the two-port forwarding dataplane of AGENTS dev-order step 3: two instances of the
**`nic-driver` PD** (one per NIC) joined through the **`forwarder` PD** by one `Pipeline` region
per direction (`crates/pd-runtime`). Each driver instance owns its device's MMIO (ECAM page +
relocated BAR) and both its virtqueues, and plays two roles at once:

- **Rx** on the pipeline it owns: the receive buffers *are* that pipeline's buffer pool
  (`crates/packet-buffer`), so the NIC DMAs each frame directly into a buffer every downstream
  stage reads in place. On a completion the driver publishes a descriptor for the frame span
  (offset 12, after the virtio-net header; `wire::Descriptor` carries the offset) on the
  pipeline's `rx` ring and reposts buffers returned on its `free` ring.
- **Tx** on the other pipeline: it dequeues descriptors the forwarder queued on that pipeline's
  `tx` ring, validates each (untrusted neighbour), zeroes the 12 virtio-net header bytes in front
  of the frame — space the receive side reserved in the same buffer — and hands the device that
  very buffer to DMA out of. On the transmit completion the buffer returns to its pool-owning
  peer on the `free` ring.

The forwarder moves descriptors `rx -> tx` per pipeline and is the seat where the classifier and
filter shards will later sit. A frame thus crosses the whole system — NIC0 DMA in -> driver0 ->
forwarder -> driver1 -> NIC1 DMA out — with only its descriptor ever moving: **zero-copy end to
end** over one pool per direction. This requires the pipeline regions to carry fixed physical
addresses (both NICs' DMA target) — see the DMA/IOMMU decision. Per AGENTS, the PDs stay thin
adapters around the reusable libraries, with the transport's pure logic (cap walk, offsets) and
the three-stage ownership chain tested on the host and the whole path tested under seL4 in QEMU
(`make test-system`, which boots the signed A/B disk through OVMF/GRUB and asserts byte-identical
frame egress in both directions).

## References

- CONCEPT.md §6 (system architecture, two data paths), §8 (technology stack: first-party Rust NIC
  drivers, ixy.rs), §9 (deployment targets; virtio-net as foundational driver), §13.2 (x86_64
  Microkit maturity; no existing x86 NIC driver — the BAR-pinning risk), §14 (UEFI/GRUB/Multiboot2
  boot chain; IOMMU default-on).
- seL4 Microkit manual — `.system` elements `memory_region`, `map`, `setvar`, `irq`, `ioport`,
  `io_address_space`/`iomap`; x86_64 BSP examples in the pinned SDK.
- AGENTS.md — development order (step 3: two-port virtio forwarding), intended repository structure,
  test strategy.
