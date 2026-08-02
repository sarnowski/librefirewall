# Building and testing

The supported developer and CI interface is GNU Make backed by rootless Podman. A pinned OCI
builder (Debian 13 by digest, a dated Debian snapshot, the Microkit SDK, `rust-sel4`, the project
Rust nightly, GRUB, OVMF, QEMU, and the coverage/lint/fuzz/SBOM tooling) provides every build
input. The downloads are sha256-pinned in `third-party/sources.lock`; each apt package is pinned to
an exact version inline in the Containerfile, next to the package name, against the snapshot that
file freezes. Nothing outside the builder is required beyond Podman itself.

From a clean checkout:

```sh
make image          # build the OCI builder, then assemble the release A/B disk + bundle
make test           # fast host gate: format, clippy, unit/property tests, coverage, lint, deps
make test-system    # boot the QEMU system scenarios; the ones with a reachable endpoint judge
                    #   metrics, logs and captures against each other and against the wire
make ci             # the complete gate (host gate + fuzz + release image + system + A/B scenarios)
```

The full command surface:

```sh
make image                # build the OCI builder, then `xtask image` — the RELEASE configuration
make image-debug          # assemble the debug kernel instead; an opt-in no gate reaches
make run                  # boot the image interactively in QEMU (debug kernel, for its diagnostics)
make test                 # fast host gate (format, clippy, tests, coverage floor, lint, dependency policy)
make coverage             # measure host-crate line coverage and print the per-crate summary
make bench                # run the performance benchmarks
make fuzz                 # run the seed smoke tests, build every fuzz target, exercise each briefly
make test-system          # boot the QEMU system scenarios on the release image
make test-ab              # boot the A/B state-machine scenarios on the release image
make ci                   # the complete gate: host gate, fuzz, release image, system and A/B
make release              # run CI, then keep `dist/` only if it proved what it holds
make verify-reproducible  # build the release payload twice in isolation and compare artifacts
make hooks                # install the pre-commit and pre-push git hooks
make book                 # render this book (requires mdbook on the host)
make clean                # remove generated output only
```

The `Makefile` is a thin, stable interface; the orchestration behind it lives in the Rust `xtask`
(`tools/xtask`), not in shell. `make image` works from a clean checkout: it enters or builds the
pinned environment, acquires and checksum-verifies the pinned inputs, builds every crate and
protection domain with locked dependencies, validates and assembles the Microkit system
description, produces the x86_64 Multiboot2 kernel and system image, packages only deployable
outputs into `dist/`, and emits checksums and an SBOM.

`make image` is the only network-enabled phase (the OCI build). Every target that runs a build or a
gate — `make clean` included — checks that the pinned builder image already exists and refuses with
an actionable message instead of quietly provisioning it, so no gate command can turn into an OCI
build. Project commands run with networking disabled, a read-only container filesystem, no Linux
capabilities, and only the workspace mounted writable. When the host exposes `/dev/kvm` it is
passed through for accelerated QEMU; the harness falls back to emulation otherwise, and which of
the two happened is printed and written into the run log, so a silent degradation to emulation
cannot pass for an accelerated run.

## Landing changes

Commits go straight to `trunk`; there are no long-lived branches, no remote feature branches, and
no pull requests. Install the git hooks once per checkout with `make hooks`:

- **pre-commit** runs `make test` — the fast host gate. It does not boot QEMU, so it stays fast.
- **pre-push** runs `make ci` — the complete gate.

Every commit that reaches `trunk` has therefore passed formatting, lints, tests, coverage,
dependency policy, the fuzz targets, release image assembly, and the QEMU system and A/B gates on
the release image — so `git bisect` is always meaningful. Do not bypass the hooks; a finding is
fixed, not skipped. Commit subjects follow Conventional Commits (`type(scope): description`), and
the message explains the intent, constraints, and semantic consequences of the change — the *why*
— not a narration of the file edits, which the diff already shows.

The gate verifies what a machine can check, and that is less than the practice the project holds
itself to: a green gate is necessary, never sufficient. What it checks mechanically:

| Check | Command |
|---|---|
| Formatting | `cargo fmt --all --check` |
| Lints, warnings denied — every host crate, and the protection domains for seL4 in **both** kernel configurations | `cargo clippy` over an explicit `-p` list, in `xtask test` |
| A `SAFETY` comment *present* on every `unsafe` block | `undocumented_unsafe_blocks = "deny"` |
| Per-file comment ratio and per-crate `unsafe` count never rise | `xtask test` (the budget ratchets) |
| Coverage floors (94% combined, 90% per library crate) | `cargo llvm-cov` in `xtask test` |
| Dependency, license and source policy | `cargo deny check bans licenses sources` |
| Fuzz targets build and their seed corpora replay; each also runs bounded where the sandbox lets an instrumented binary start | `xtask fuzz` |
| Boot, forwarding and A/B contracts | `xtask test-system`, `xtask test-ab` |

Two things that table must not be read as saying. The lint command is **not** a bare
`cargo clippy -- -D warnings`: `default-members = ["tools/xtask"]` makes that select `xtask` alone
and report clean without looking at a single library crate, which is why `xtask` names its packages
explicitly and fails the build when the list is incomplete. And the local gate runs offline, so
`cargo deny check advisories` is not in it — vulnerability scanning is a separate networked CI
stage (`azure-pipelines.yml`), so a local green is a dependency-policy pass and not an advisory
scan.

## Build profiles

Two profiles exist. There is no debug *binary*: the protection domains compile under the
`--release` Cargo profile in both, so first-party code is one compilation. What differs is the seL4
kernel build, which is why "debug" is better read as "release plus kernel diagnostics".

- `release` — the artifact. Every gate that boots anything boots this one, and it is what
  `make image` builds with no flag.
- `debug` — a diagnostic tool, not a test target. The kernel prints, so a fault reports itself
  instead of vanishing into an empty serial log. Reached three ways: `make run`, `make image-debug`,
  and automatically when an end-to-end scenario fails — the harness re-runs that one scenario on it
  and surfaces the result as evidence, never letting it change the verdict. The two-kernel-
  configuration Clippy pass is the only thing keeping this configuration buildable, so it is
  load-bearing rather than incidental.

**The shipped profile is the tested profile.** *Every* end-to-end scenario boots the release
configuration: `make ci` assembles it and holds that disk to the forwarding contract across the
system and A/B scenarios, and to the configuration transcript where a scenario states one. It was
not always so, and the reason it is now is worth keeping: the gate used to boot the debug
configuration and only `make release` touched the release one, which nothing ran on push; two
consecutive changes then shipped defects reachable only in release — a console that emitted
nothing, and a boot chain that loaded userland over the kernel's own page tables. A gate that boots
something other than the artifact says nothing about the artifact.

**Fail on release, diagnose on debug.** The release kernel is built without `CONFIG_PRINTING`, so a
boot that dies before the console domain claims the UART leaves an empty capture and a bare timeout
with no diagnosis in it. When a scenario fails, the harness therefore re-runs *that one scenario* —
never the others — on the debug kernel, and reports what happened beside the failure: a pass on
debug is reported as a divergence pointing at the kernel configuration and image layout, a failure
on both quotes the debug kernel's serial output, and a debug image that could not be assembled is
its own outcome. The re-run never changes the verdict, and its artifacts are written under separate
`-debug` names so they cannot overwrite the failing run's evidence.

Two more profiles are intended and do not exist — `benchmark` (PMU-enabled kernel and performance
instrumentation) and `smp-*` (multicore variants, to arrive with the multicore dataplane). Nothing
in `Cargo.toml`, `xtask`, or `systems/` wires them.

## Release artifacts

`make release` runs the complete acceptance gate and boots nothing of its own — `ci` already
assembles the release configuration into `dist/` and already holds that disk to both contracts a
booted appliance owes. What `make release` adds: if the gate did not prove the artifact, `dist/` is
emptied rather than left holding an unproven image that looks finished. That covers a failure
anywhere in the run, not a failed boot alone, because assembly populates `dist/` partway through
and an incomplete release is no more publishable than an unproven one.

The deployable artifact is `dist/librefirewall-qemu-x86_64.img`, the signed GPT A/B disk booted
through OVMF and GRUB. Alongside it, `dist/` carries five product-prefixed pieces of release
evidence and nothing else: the loose kernel and system images (the update input), a manifest
describing the target, pinned inputs and signing trust profile, an SPDX 2.3 SBOM (see
[Implementation status in detail](status-detail.md#engineering-foundations) for what it does and
does not cover), and a SHA-256 checksum file covering every other artifact. The Microkit
capability/memory report is deliberately **not** published: it is a full disclosure of the system's
authority topology, so it stays under `build/image/<config>/`.

Image builds generate a throwaway development signing key under `build/dev-keys/` (never committed;
removed by `make clean`); the manifest records `trust_profile: development` so a development-signed
image can never be mistaken for a production one.

All commands force Podman's `cgroupfs` manager. Override `PODMAN` only to select a compatible
Podman executable; Docker is not a supported build interface.

On a development machine behind a TLS-inspecting proxy, the build automatically detects an
installed inspection CA (a `*-dpi-ca.crt` under `/usr/local/share/ca-certificates/`) and provides
it as a Podman build secret. On another inspected network, or to select a specific certificate,
pass its path explicitly:

```sh
make image ENTERPRISE_CA_FILE=/path/to/enterprise-ca.pem
```

The CA reaches only the build steps that fetch dependencies, and the bundle each of them derives is
removed within that same step, so it does not persist into an image layer. TLS verification stays
enabled for every download. Never commit the certificate — or any other key material.

## Repository layout

Directories have fixed purposes; they grow as real functionality lands, and no empty placeholders
are created.

- `crates/` — portable `no_std` libraries holding the firewall and dataplane logic. This is where
  most code and almost all tests live.
- `pds/` — protection-domain binaries: thin adapters that map shared regions and drive a library
  crate's logic. Correctness logic belongs in a crate, not here, so it can be host-tested.
- `systems/` — the Microkit system description(s): the static capability topology. A capability
  change is a security change.
- `tools/` — the `xtask` build/test/packaging orchestrator and the QEMU harness.
- `fuzz/` — the persistent `cargo-fuzz` targets for the untrusted parsers, in their own workspace
  so the ASan/libFuzzer instrumentation never enters a protection-domain build. Criterion
  microbenchmarks are *not* a top-level directory: each lives in its crate's own `benches/`, beside
  the code it measures.
- `book/` — this book, plain Markdown under `book/src/`. Render it with `make book` (which runs
  [mdBook](https://rust-lang.github.io/mdBook/); install it with `cargo install mdbook`), or read
  the Markdown directly.
- `build/`, `third-party/`, `support/` — the pinned hermetic builder, pinned upstream inputs, and
  target specifications.
