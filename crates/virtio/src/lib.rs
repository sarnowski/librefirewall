//! First-party virtio primitives for the NIC driver protection domain.
//!
//! This crate is the device-facing counterpart to `crates/queue`: where the
//! SPSC ring moves buffer ownership between two of our protection domains, a
//! virtqueue moves buffer ownership between our driver and a virtio device over
//! DMA. It is implemented from scratch per CONCEPT §8 rather than reusing an
//! upstream virtio crate, and is transport-agnostic — the same split virtqueue
//! backs virtio-pci (QEMU/bare metal) and virtio-mmio.
//!
//! Only the driver side of the split-virtqueue protocol lives here (virtio 1.0,
//! [`queue`]), together with the virtio-net data types a driver parses
//! ([`net`]). Transport bring-up (PCI config space, BAR mapping, feature
//! negotiation, MSI/IOAPIC wiring, VT-d DMA) belongs to the driver PD and is
//! planned in `docs/virtio-net-driver.md`.

#![cfg_attr(not(test), no_std)]

pub mod net;
pub mod pci;
pub mod queue;

pub use queue::{QueueLayout, SplitVirtqueue, Token};
