# Deployment and high availability

**Architecture: x86_64 only.**

## Port roles

Interfaces are assigned **roles**, and the role — not a fixed port count — is the architectural
unit. Four roles exist:

- **Management port** — the appliance's only management-facing interface: while unboarded it serves
  the [onboarding server](management.md#onboarding), and once onboarded it carries the outbound
  [management channel](management.md#the-channel) and listens for nothing. It is isolated from the
  dataplane and carries no forwarded traffic.
- **Session-replication port** — the dedicated [HA link](#high-availability) carrying heartbeat and
  batched flow-state synchronization between the two nodes of a pair.
- **Dataplane ports** — the inspected-traffic ports, handled in **pairs**. The common labels
  "uplink" and "internal" describe a typical north-south deployment, but the role is semantically
  neutral: a pair may equally carry east-west traffic between two internal zones. A deployment has
  one or more dataplane pairs.
- **Mirror port** — an optional, egress-only port that emits a copy of selected traffic to an
  external capture/IDS system. It is **complementary to the on-box
  [recording sinks](recording.md#pcapng-as-the-internal-representation), not an alternative to
  them** — the recording design sets out what each buys and what it costs — and a deployment may
  want both.

## NIC configurations

The role model yields the supported hardware configurations:

| Configuration | NICs | Ports |
|---|---|---|
| **Single node** | 3 | management; one dataplane pair |
| **HA pair** | 4 | management; session-replication; one dataplane pair |
| **HA + redundant dataplane** | 6 | management; session-replication; two dataplane pairs |
| **HA appliance, full** | 7 | management; session-replication; two dataplane pairs; mirror |

The **4-NIC HA configuration is the primary Azure target**; the **7-NIC configuration is the
hardware-appliance build**, which populates every role and simply leaves ports unused when a site
needs fewer (no redundant pair, no mirror). A node without HA uses the 3-NIC configuration.

Because hardware topology is static (see [Configuration](configuration.md)), **each row is a
build-time image variant**: the number of NICs a system drives is fixed in its system description.
Which of those present ports a deployment actually uses, and in which role, is runtime
configuration — an unused port is administratively disabled, not built out.

## Targets and form factors

**Targets:**

- **QEMU** — development.
- **Proxmox** — virtual machine.
- **Azure** — virtual machine.
- **Bare-metal hardware** — the physical appliance.

**Form factors:**

- **Bare-metal appliance** — inline, with SFP+ 10 Gbit/s dataplane ports (see
  [Port roles](#port-roles)).
- **Virtual machine** — on Proxmox and Azure.
- **Cloud (Azure)** — deployed as a routed **Network Virtual Appliance (NVA) behind a Gateway Load
  Balancer**. The dataplane terminates the load balancer's **VXLAN tunnels** (internal and
  external), encapsulating and decapsulating that traffic.

## NIC drivers (all Rust)

- **virtio-net** — the first/foundational driver; covers QEMU, Proxmox, and development.
- **x86 10 Gbit/s NIC** — for the bare-metal appliance, using a register-programmable **SFP+** NIC
  of the Intel **ixgbe family (82599 / X520)**.
- **Azure** — **netvsc** as the baseline interface, and **MANA** (Microsoft Azure Network Adapter)
  for the high-performance path, which is required for Azure eventually.

Azure support is a substantial platform effort rather than a single NIC driver — see the
[development status](../status.md) page for the scope of that effort.

## High availability

- **Active/passive pair** with **session synchronization** for immediate failover.
- **Session state is synchronized in batches**, giving a millisecond-scale loss window on failover.
- **No TLS session synchronization.** L2–L4 flow/connection state is synchronized and those sessions
  survive failover; TLS-terminated / L7-proxied connections are **forced to reconnect** on
  failover. This is accepted as standard behavior.
- A **dedicated HA link** carries heartbeat and delta/batched state synchronization.
- The **HA state-sync component is its own isolated PD**.
- **Each node holds its own isolated signing capability** (see
  [Threat model and isolation](threat-model.md)). Sharing signing trust across the pair is required;
  its form (e.g. per-node intermediate CAs under a common trusted root) is still open (see
  [development status](../status.md)).
- **Configuration is applied in a staggered/canary order** across the pair (standby first, verified
  healthy, then active) — see [Configuration](configuration.md).
- Because hardware topology is static, a hardware change is an *image* change; **the HA pair is the
  mechanism for rolling image updates** without downtime (see
  [Configuration](configuration.md) and [Updates and secure boot](updates.md)).
- **Failover is mechanism-specific per environment**, because the takeover primitive differs:
  - **Routed, on-premises** — the pair shares a virtual IP and virtual MAC; the promoted node takes
    them over and announces the move with gratuitous ARP / unsolicited neighbour advertisements.
  - **Virtual wire, on-premises** — there is no address to take over, so failover is by **link
    state**: the standby holds its dataplane ports down and raises them on promotion, and loss of
    one port of a pair is propagated to the other so the neighbouring devices reconverge.
  - **Azure** — L2 takeover is impossible on the platform; failover is by withdrawing the node's
    Gateway Load Balancer health probe and letting the platform reprogram routing to the survivor.
- **Split-brain is arbitrated over the dedicated HA link.** The arbitration scheme (witness, quorum,
  or fencing) is still open (see [development status](../status.md)).

## Deploying the management server

The management server is deployed independently of every appliance target above, and its inventory
is deliberately complete in three pieces: **the Phoenix release, Postgres, and ClickHouse — nothing
else**. No Prometheus server, no collector, no agents, no message broker; Phoenix is the
[sole collector](management-server.md), and the appliances dial it. A deployment that can run those
three can run the management plane, and sizing it is a database question rather than a fleet
protocol one.
