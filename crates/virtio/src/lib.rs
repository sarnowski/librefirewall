//! First-party virtio primitives for the NIC driver protection domain.
//!
//! This crate is the device-facing counterpart to `crates/queue`: where the
//! SPSC ring moves buffer ownership between two of our protection domains, a
//! virtqueue moves buffer ownership between our driver and a virtio device over
//! DMA. It is implemented from scratch per CONCEPT §8 rather than reusing an
//! upstream virtio crate. The split-virtqueue protocol ([`queue`]) is itself
//! transport-agnostic; the concrete transport shipped here is the modern x86
//! PCI one ([`pci`]) — there is no MMIO transport yet.
//!
//! The driver side of the split-virtqueue protocol lives here (virtio 1.0,
//! [`queue`]), together with the virtio-net data types ([`net`]) and the modern
//! x86 PCI transport ([`pci`]). The driver PD (`pds/nic-driver`) owns policy and
//! capability use: PCI/BAR bring-up and feature negotiation run there for QEMU.
//! Interrupt delivery (MSI-X) and VT-d-confined DMA on real hardware are open
//! items tracked in CONCEPT §13 and reflected in the README status, not here.

#![cfg_attr(not(test), no_std)]

pub mod net;
pub mod pci;
pub mod queue;

pub use queue::{QueueLayout, SplitVirtqueue, Token};
