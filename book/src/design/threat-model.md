# Threat model and isolation

## Assets, adversaries, and trust boundaries

The design starts from what must be protected, who the attacker is, and where the trust boundaries
lie.

**Assets**, in rough order of value: the TLS-interception **CA signing key**; the **running
configuration** and management credentials; **flow and connection state** (including per-connection
TLS material on the proxy path); and the **packet buffers** in flight.

**Adversaries the design assumes:**

- **Untrusted network traffic** on every dataplane port — arbitrary, adversarial bytes at line
  rate. This is the primary attack surface and the reason every parser is memory-safe and isolated.
- **A hostile or malfunctioning NIC device.** A driver treats everything the device writes
  (descriptors, used rings, config space) as untrusted input and must never be driven to
  out-of-bounds access, unbounded work, or a panic by device behaviour.
- **A compromised parser or inspection PD.** Because parsers are the most-exposed code, each runs
  in its own least-privilege PD; a full compromise of one must not reach flows, memory, or keys it
  holds no capability for.
- **A byzantine neighbour PD.** Every PD treats the queues and messages from adjacent PDs as
  untrusted: malformed descriptors, stale or forged ownership, and backpressure are rejected
  safely, never allowed to corrupt state or crash a well-behaved PD.
- **A management-plane attacker** reaching the API, and a **connection-flood / state-exhaustion
  attacker** targeting the proxy (see [Isolation model](#isolation-model)).

**Trust boundaries.** The **seL4 kernel and its boot/loader chain are the trusted computing base**;
runtime capability isolation is enforced by the kernel and is relied upon. The **`rust-sel4` /
Microkit runtime** is likewise trusted. Everything above — every first-party PD — is mutually
distrustful across the queue and channel boundaries fixed by the static system description. A
physical attacker with arbitrary hardware access is out of scope for the software design; Secure
Boot and TPM measures raise that bar separately (see
[Updates and secure boot](updates.md)).

**Consequence for verification.** Because the kernel and runtime are the trusted base, the project
does not test them — it assumes seL4, Microkit, and `rust-sel4` are correct — and instead
exhaustively tests and fuzzes all first-party logic: parsers, queues, ownership, policy, and state
machines. "Reject untrusted input safely; fail visibly on internal invariant violation" is the
dividing line those tests enforce; the project's
[engineering practices](../developers/engineering.md) describe the testing approach in detail.

## Isolation model

- **Least-privilege PDs.** Every component holds only the capabilities it needs. A compromise of
  one component cannot reach flows, memory, or keys it has no capability for.
- **Parser isolation.** Each protocol parser runs in its own PD so that a parser compromise is
  contained; faulting PDs are restartable.
- **CA signing key isolation.** The private CA key used for TLS interception lives in its own
  **sign-only** PD, ideally HSM/TPM-backed. It is never exposed to any other component; components
  can request signatures but cannot read the key.
- **Management-plane isolation.** The management API runs in its own isolated PD. A full compromise
  of that PD must not be able to reach dataplane packet buffers or the CA key.
- **Configuration validator isolation.** Parsing and validation of configuration input runs in an
  isolated, capability-minimal, restartable PD, so that an exploit attempt against the config
  mechanism cannot reach the dataplane or keys.
- **DMA isolation.** The IOMMU (VT-d) is used to confine NIC DMA.
- **Denial-of-service resilience.** Because the terminating proxy commits per-connection state
  (TCP and TLS) at connection setup, it is a target for connection-flood and state-exhaustion
  attacks. The appliance resists these with standard measures such as SYN cookies, connection-rate
  limiting, and bounded flow tables with eviction.
- **Trusted time.** TLS certificate validation — of upstream server certificates and of the
  appliance's own re-signed certificates — depends on accurate, trusted time, so the appliance
  requires a trusted time source. The choice of source mechanism is still open (see
  [development status](../status.md)).
