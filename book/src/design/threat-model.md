# Threat model and isolation

## Assets, adversaries, and trust boundaries

The design starts from what must be protected, who the attacker is, and where the trust boundaries
lie.

**Assets**, in rough order of value: the TLS-interception **CA signing key**; the **device identity
key** and with it the **trust anchor and management endpoint** the appliance dials (together, who
may manage this appliance); the **running configuration**; the **recordings** — the on-appliance
evidence of what crossed the network; **flow and connection state** (including per-connection TLS
material on the proxy path); and the **packet buffers** in flight.

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
- **A management-plane attacker, up to and including a compromised management server.** The
  management server is the configuration authority, so the design does not pretend it cannot be
  hostile — it bounds what a hostile one can do (see
  [below](#the-compromised-management-server)).
- **A connection-flood / state-exhaustion attacker** targeting the proxy (see
  [Isolation model](#isolation-model)).

**Trust boundaries.** The **seL4 kernel and its boot/loader chain are the trusted computing base**;
runtime capability isolation is enforced by the kernel and is relied upon. The **`rust-sel4` /
Microkit runtime** is likewise trusted. Everything above — every first-party PD — is mutually
distrustful across the queue and channel boundaries fixed by the static system description. Adopted
cryptography libraries are deliberately **not** in the trusted base — they are pinned, audited for
provenance, and proven against published test vectors on the shipped image rather than assumed
correct (see the [architecture](architecture.md#cryptography)).

A physical attacker with arbitrary hardware access is out of scope for the software design; Secure
Boot and TPM measures raise that bar separately (see [Updates and secure boot](updates.md)). One
consequence of that scoping is recorded plainly rather than implied: **the device identity key is
plaintext on the store medium.** There is no TPM, no secure element, and nowhere to keep a wrapping
key, so physical access to the store device is identity theft. Factory reset
[overwrites the key rather than marking it free](updates.md#factory-reset), which is what the
software can do about a medium that leaves the building.

**Consequence for verification.** Because the kernel and runtime are the trusted base, the project
does not test them — it assumes seL4, Microkit, and `rust-sel4` are correct — and instead
exhaustively tests and fuzzes all first-party logic: parsers, queues, ownership, policy, and state
machines. "Reject untrusted input safely; fail visibly on internal invariant violation" is the
dividing line those tests enforce; the project's
[engineering practices](../developers/engineering.md) describe the testing approach in detail.

## The ownership boundary

Onboarding rests on a **physical-access trust boundary**: trust in a management plane is established
by the administrator controlling physical and logical access to the management port while the
appliance is unowned. Whoever reaches an unprovisioned appliance becomes its owner — an attacker in
that position is indistinguishable from the intended administrator, and the design does not pretend
otherwise. There is no vendor-embedded anchor to fall back on, deliberately: it would make the
vendor a trust root for every appliance ever shipped.

The boundary has a precise **asymmetry**. The SPKI fingerprint on the console authenticates the
*appliance to the administrator* — the administrator cannot onboard the wrong box and cannot be
intercepted on the way to the right one. **Nothing authenticates the administrator to the
appliance**; physical access control is the property that stands in for it. Factory reset removes
all ownership and is the only ownership transfer.

Two rules defend the boundary's edges:

- **The onboarding endpoints are rate-limited with backoff and never permanently locked out.** A
  permanent lockout would be a remote bricking primitive — an attacker with transient access could
  destroy the owner's ability to ever onboard the box — which is a worse outcome than the brute-force
  the backoff already prices out.
- **Certificate validity is judged against the CMOS-derived clock, and the hardware is trusted at
  this point.** A recorded decision: the clock is unauthenticated, and an adversary positioned to
  set it — firmware, hypervisor, the board itself — already holds physical-class access the software
  design scopes out.

## The compromised management server

The management server is where administrators define and decide configuration, so a compromise of
it is a compromise of the configuration authority itself — no signature scheme changes that, because
any key the authority uses is a key the compromised authority holds. The design's answer is to sort
what such an attacker can do by whether it is *recoverable*:

**Most attacker actions are recoverable.** A hostile configuration pushed to the fleet, tampered
telemetry, forged audit records — all of it is undone by cleaning the server and pushing correct
configuration. Ugly, not fatal.

**Three actions are not remotely recoverable**, and each would irreversibly capture the fleet:
changing the **trust anchor**, which locks the real owner out permanently; changing the
**endpoint**, which redirects the fleet to the attacker; and **disabling recording**, which
destroys the evidence of everything else. Undoing any of them would need a physical visit to every
appliance.

**The control: the appliance refuses to change its trust anchor or its management endpoint over the
channel, ever.** Changing either requires factory reset and re-onboarding — the same physical
boundary that established ownership. This is strictly stronger than the alternative of a second,
offline configuration-signing key, because it cannot be defeated by stealing anything, and it needs
no second custody domain, no HSM, and no offline ceremony. The
[package contract](../contracts/configuration-package.md#members) makes the endpoint half structural:
a configuration document cannot even express an endpoint, so no pushed document can smuggle one. The
cost is CA rollover — an anchor that can never change remotely is an anchor whose rotation means
visiting every appliance — and that is deferred rather than solved, there being no fleet yet; it is
the one item this control is expected to force a revisit of.

**Recording stays under the management server's authority**, deliberately — what to record is a
configuration decision like any other. What bounds the damage is the **accepted residual**, stated
as such: after a management-server compromise, the networked copy of the evidence is
attacker-controlled, and the **on-appliance recording rings and console records remain evidence
that requires physical access to the box and cannot be scrubbed over the channel**. An attacker who
owns the server owns what the server was told; the box still holds what the box saw.

## Harvest now, decrypt later

The channel carries pcapng captures and connection histories — the customer's network history — so
an adversary recording the channel today and breaking its key exchange in a future decade obtains
that history retroactively. That threat is concrete for exactly this traffic, and it is why the
channel's key exchange is **hybrid X25519MLKEM768 from the start** rather than an upgrade for
later. Post-quantum *signatures* are a different matter with a different clock — an identity forged
in the future does not disclose the past — and stay out of scope; the
[certificate profile](../contracts/certificate-profile.md) keeps the algorithm a field so that
migration is re-issuance, not redesign.

## Isolation model

- **Least-privilege PDs.** Every component holds only the capabilities it needs. A compromise of
  one component cannot reach flows, memory, or keys it has no capability for.
- **Parser isolation.** Each protocol parser runs in its own PD so that a parser compromise is
  contained; faulting PDs are restartable.
- **CA signing key isolation.** The private CA key used for TLS interception lives in its own
  **sign-only** PD, ideally HSM/TPM-backed. It is never exposed to any other component; components
  can request signatures but cannot read the key.
- **Device identity key custody.** The [store domain](architecture.md#key-custody) owns the store
  device, generates the device keypair, holds it, signs with it, and never emits it. The TLS layer
  delegates its private-key operation to that domain, so the domain that faces the network never
  holds the key it authenticates with — and takes the certificate over that key from the same domain
  rather than issuing one, a certificate being public and the identity being that domain's to state.
- **Management-plane isolation.** The domain that terminates the channel — and, while unboarded, the
  onboarding server — runs isolated on a dedicated management interface. A full compromise of it
  must not be able to reach dataplane packet buffers, the interception CA key, or the device
  identity key.
- **Configuration validator isolation.** Parsing and validation of configuration input runs in an
  isolated, capability-minimal, restartable PD, so that an exploit attempt against the config
  mechanism cannot reach the dataplane or keys — and the channel does not change that: a document
  arriving over it crosses into the validator exactly as one arriving any other way.
- **DMA isolation.** The IOMMU (VT-d) is used to confine NIC DMA.
- **Denial-of-service resilience.** Because the terminating proxy commits per-connection state
  (TCP and TLS) at connection setup, it is a target for connection-flood and state-exhaustion
  attacks. The appliance resists these with standard measures such as SYN cookies, connection-rate
  limiting, and bounded flow tables with eviction.
- **Trusted time.** The management channel's certificate validity is judged against the CMOS-derived
  clock under the recorded decision [above](#the-ownership-boundary). TLS *interception* — validating
  upstream server certificates on behalf of protected clients — is a different question with a
  different adversary and still requires a genuinely trusted time source; that mechanism remains
  open (see [development status](../status.md)).
