# librefirewall

**A high-performance, deeply inspecting firewall built for strong isolation.**

librefirewall is a defensive network security gateway for x86_64 appliances and virtual machines:
full deep packet inspection across ISO layers 2 through 7, TLS interception, and inline content
scanning — built on the seL4 microkernel with a pure-Rust userspace, decomposed into
least-privilege protection domains whose authority the kernel enforces.

## Documentation

Everything lives in the **[documentation book](book/src/SUMMARY.md)** (`book/`, an
[mdBook](https://rust-lang.github.io/mdBook/); render it with `make book` or read the Markdown
directly):

- **Users** — network engineers, firewall administrators, security engineers — start at the
  [introduction](book/src/introduction.md) and the [development status](book/src/status.md), then
  the reference (the operator contract) and design parts.
- **Developers** — start at [building and testing](book/src/developers/building.md) and the
  [engineering practice](book/src/developers/engineering.md).
- **Agents** — read [AGENTS.md](AGENTS.md).

## Building

```sh
make image   # build the pinned OCI builder, then assemble the release A/B disk
make test    # fast host gate
make ci      # the complete gate, QEMU scenarios included
```

Every build and gate target requires rootless Podman and nothing else. Rendering the book with
`make book` is the one exception: mdbook runs on the host, because the book is a reading
convenience rather than a build input. See
[building and testing](book/src/developers/building.md).

## License

librefirewall is free software, licensed under the **GNU Affero General Public License, version 3
or later (AGPL-3.0-or-later)**. The full text is in [LICENSE.md](LICENSE.md).

Copyright (C) 2026 Tobias Sarnowski

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.
