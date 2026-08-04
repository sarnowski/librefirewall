# Introduction

**librefirewall is a high-performance, deeply inspecting firewall built for strong isolation.**

It is a defensive network security gateway for the operator's own infrastructure, from industrial
OT environments through corporate networks, data centers and cloud, up to web filtering — a
firewall that performs full deep packet inspection across ISO layers 2 through 7, including TLS
interception and inline content scanning.

It is a **two-component product**:

- **The appliance** (`datad/`) — the inline firewall itself, for x86_64 appliances and virtual
  machines. It runs on the **seL4 microkernel** with a **pure-Rust userspace**, decomposed into many
  small, least-privilege protection domains whose authority the kernel enforces at runtime. The code
  most exposed to hostile input — the parsers, the drivers, the proxies — is memory-safe and
  isolated, so compromising one component does not yield the flows, memory, or keys it holds no
  capability for. The target is 10 Gbit/s of sustained, fully inspected, inline throughput per
  dataplane port pair.
- **The management application** (`ctrld/`) — a central single pane of glass for many single and
  clustered appliances. **Appliances have no user interface of their own at all**: onboarding,
  configuration with version control and audit, and log and capture search all live here, and every
  appliance dials home to it over one persistent, mutually-authenticated connection.

## Who this book is for

This book is for the people who run firewalls — network engineers, firewall administrators,
security engineers — and for the people who build this one.

- **[Development status](status.md)** — what works today, what does not, and where the project is
  heading. librefirewall is in early development; read this first.
- **Reference** — the operator contract: the surfaces a running node answers through, and what its
  console records, metrics and recordings mean. Exact and complete; this is the appliance's
  interface definition.
- **Design** — how librefirewall is designed and why: the architecture, the threat model, and the
  decisions behind them. The design describes the settled target picture, which is deliberately
  larger than what exists today.
- **Contracts** — the exact formats the two components meet on: the onboarding package, the
  certificate profile, and the channel framing. Precise enough to implement either side against.
- **Development** — for contributors: how to build and test, the engineering practice the project
  holds itself to, and how a change is reviewed.

## License

librefirewall is free software, licensed under the **GNU Affero General Public License, version 3
or later (AGPL-3.0-or-later)**. It is distributed in the hope that it will be useful, but **without
any warranty**; without even the implied warranty of merchantability or fitness for a particular
purpose.
