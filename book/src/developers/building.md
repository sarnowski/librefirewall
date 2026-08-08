# Building and testing

The supported developer interface is GNU Make backed by rootless Podman. Each component builds and
tests inside its own pinned OCI builder. The appliance builder (Debian 13 by digest, a dated Debian
snapshot, the Microkit SDK, `rust-sel4`, the project Rust nightly, GRUB, OVMF, QEMU, and the
coverage/lint/fuzz/SBOM tooling) provides every `datad` build input; the BEAM builder (the
`hexpm/elixir` image by digest — Erlang/OTP, Elixir and Debian bookworm — plus Hex, rebar3, the
Phoenix generator, and the tailwind and esbuild standalone binaries) provides every `ctrld` one.
The downloads are sha256-pinned in `datad/third-party/sources.lock` and
`ctrld/third-party/sources.lock`; each apt package is pinned to an exact version inline in the
component's Containerfile, next to the package name, against the snapshot its lock file freezes.
Nothing outside the builders is required beyond Podman itself.

From a clean checkout:

```sh
make image          # build the appliance OCI builder, then assemble the release A/B disk + bundle
make ctrld-image    # build the BEAM OCI builder with its warmed offline caches, and pull the
                    #   two pinned databases the management server's gate runs against
make test           # both fast gates: the ctrld gate (lock, format, warning-free compile,
                    #   migrations and tests against real databases on an isolated network),
                    #   then the datad host gate (format, clippy, unit/property tests, coverage,
                    #   the budget ratchets, the system-description, reference-chapter and
                    #   configuration checks, and dependency policy)
make test-system    # boot the QEMU system scenarios; the ones with a reachable endpoint judge
                    #   metrics, logs and captures against each other and against the wire
make ci             # the complete gate (both fast gates + fuzz + release image + system + A/B
                    #   + the debug image the diagnostic re-run needs)
```

The full command surface:

```sh
make image                # build the appliance OCI builder, then `xtask image` — the RELEASE configuration
make image-debug          # assemble the debug kernel instead; an opt-in no gate reaches
make deps                 # resolve the appliance's Cargo manifests into datad/Cargo.lock, and nothing else
make run                  # boot the image interactively in QEMU (debug kernel, for its diagnostics)
make test                 # both fast gates: ctrld first (it is quick, so a finding there surfaces
                          #   before the datad gate spends its minutes), then the datad host gate
make coverage             # measure host-crate line coverage and print the per-crate summary
make bench                # run the performance benchmarks
make fuzz                 # run the seed smoke tests, build every fuzz target, exercise each briefly
make test-system          # boot the QEMU system scenarios on the release image
make test-ab              # boot the A/B state-machine scenarios on the release image
make ci                   # the complete gate: both fast gates, fuzz, release image, system and A/B,
                          #   then the debug image, assembled and never booted
make release              # run the full gate, then keep `datad/dist/` only if it proved what it holds
make verify-reproducible  # build the release payload twice in isolation and compare artifacts
make ctrld-image          # build the pinned BEAM builder and pull the two pinned databases
make ctrld-deps           # re-resolve the Hex dependency tree and rewrite mix.lock (networked)
make ctrld-test           # the ctrld offline gate on its own
make ctrld-server         # run the management server interactively for development
make ctrld-databases-down # stop the development databases `ctrld-server` brought up
make hooks                # install the pre-commit and pre-push git hooks
make book                 # render this book (requires mdbook on the host)
make clean                # remove generated output only
```

The `Makefile` is a thin, stable interface; the orchestration behind the `datad` targets lives in
the Rust `xtask` (`datad/tools/xtask`), and behind the `ctrld` targets in Mix, not in shell. The
containers mount the repository root and run inside their component directory. `make image` works
from a clean checkout: it enters or builds the pinned environment, acquires and checksum-verifies
the pinned inputs, builds every crate and protection domain with locked dependencies, validates
and assembles the Microkit system description, produces the x86_64 Multiboot2 kernel and system
image, packages only deployable outputs into `datad/dist/`, and emits checksums and an SBOM.

`make image`, `make deps`, `make ctrld-image` and `make ctrld-deps` are the only phases that fetch
from the network. Every target that runs a build or a gate — `make clean` included — checks that its
pinned builder image already exists and refuses with an actionable message instead of quietly
provisioning it, so no gate command can turn into an OCI build or a registry fetch. Project commands
run with networking disabled, a
read-only container filesystem, no Linux capabilities, and only the workspace mounted writable.
When the host exposes `/dev/kvm` it is passed through for accelerated QEMU; the harness falls back
to emulation otherwise, and which of the two happened is printed and written into the run log, so a
silent degradation to emulation cannot pass for an accelerated run.

Incremental compilation is disabled for every project command. A cache may accelerate a build and
must never decide one, and this one twice did: the compiler crashed on a stale incremental tree in
crates the change under test had not touched. A gate whose verdict depends on what a previous run
left behind is not a gate, so the runs depend on the sources and the pinned toolchain alone. Editing
a target specification is the same hazard in another form and is handled the same way — the build
records which specification each set of artifacts was compiled against, discards them when it
changes, and says so, because cargo does not fingerprint a custom target.

### Adding an appliance dependency

The gate is offline by construction: the builder image warms a Cargo cache from the committed
manifests and lockfile, and every gate target then runs with no network at all. A new dependency
therefore takes two provisioning steps before any gate can see it, and they must happen in this
order:

```sh
# 1. edit the crate's Cargo.toml
make deps      # resolve it into datad/Cargo.lock — the ONLY thing that writes that file
make image     # rebuild the builder so its offline cache holds the new crates, then assemble
make test      # and now the offline gate can compile against them
```

`make deps` runs the pinned builder's own Cargo with the network on and does nothing else: no
compilation, no artifact, only the lockfile (and the fuzz workspace's, which is resolved in the
same run). Running it against the pinned toolchain rather than the host's is what makes the
resolution the one the offline build replays. Skipping it and going straight to `make image` fails
with a lockfile that does not match the manifests; skipping `make image` afterwards fails with a
crate the offline cache does not hold.

Adding a dependency is also a policy decision, not only a resolution: `datad/deny.toml` bans the
crates that compile or link native code outright, denies build scripts by default with an explicit
allow-list, and denies two versions of one crate. A new build script needs an entry with a written
reason beside it, and a crate that would compile C is rejected rather than allow-listed.

**The protection-domain builds are not one invocation, and not two.** The dataplane domains are
compiled together for the softfloat target with `-Z build-std=core`; the three SIMD domains — the
hardware probe, the cryptography domain and the store domain — are compiled for the hardfloat,
SSE-enabled target with `-Z build-std=core,alloc`, **one invocation each**. The difference in the
standard-library set is deliberate and is the whole allocator story in one line: the cryptography
domain carries the appliance's only allocator, because a proven TLS implementation requires one, and
every other domain keeps having none.

One invocation per SIMD domain is a correctness requirement rather than tidiness. Cargo's resolver
unifies features across every package one invocation selects, so building the three together turns
on the `alloc` features of the shared cryptography dependency graph — the TLS stack asks for them —
in the store domain too, which carries no allocator and must not. Building each on its own is what
keeps a domain's feature set the set its own manifest asks for. Every invocation is in
`xtask::image`, and the linting in `xtask::host` mirrors them exactly — a domain linted with a
different standard-library set, or a different feature set, is a lint of a different binary.

**Editing a target specification invalidates what was built against it.** The two specifications
live in `datad/support/targets/`; cargo fingerprints the compiler, the profile, the features and
every source file it reads, and it does not fingerprint one of these. Left alone, an edited
specification is a build reported up to date that goes on linking object code compiled under the old
one. So every build that compiles for a seL4 target — both image configurations, every scenario disk
a QEMU run assembles, and the two-configuration Clippy pass — records the specification beside the
artifacts it produced and discards them when the two no longer agree, naming the lines that moved.
Editing a specification therefore costs one cold build of the target that changed, announced on the
build's own output rather than left to be wondered about; leaving them alone costs nothing.

## The management-server toolchain

`ctrld` follows the same discipline with BEAM-shaped mechanics. The builder image pins the
`hexpm/elixir` base by digest, resolves its apt packages against a dated Debian snapshot with the
exact version of each pinned inline next to its name, installs Hex, rebar3 (the published escript,
sha256-verified) and the Phoenix generator at pinned versions into an image path that is read-only
at run time, and fetches the tailwind and esbuild standalone binaries at pinned versions and
checksums into `/opt/assets` — those two are never downloaded by their libraries, whose own
downloaders would bypass the toolchain's TLS configuration. The offline dependency caches are
warmed during the image build from the committed manifests alone: `mix deps.get` fills the Hex
package cache inside the image, every git dependency in `mix.lock` is mirrored into the image and
rewritten to its mirror, and one throwaway compile of the dependency tree captures what any
dependency would otherwise fetch at compile time (the precompiled NIF tarball `lazy_html` uses).
A dependency change therefore means rebuilding the builder, exactly as it does for `datad`.

There are two invocation modes, because the offline discipline and the development experience pull
in opposite directions:

- **`make ctrld-test`** — the gate. It runs with the same container hardening as the datad gate,
  and holds the committed lockfile (`mix deps.get --check-locked`), formatting
  (`mix format --check-formatted`), a warning-free compile (`mix compile --warnings-as-errors`),
  the two schema migrations, and the test suite (`mix test`). The asset binaries are provisioned
  from the image: the provisioning step asks the project which versions it expects and refuses if
  the image does not carry them, so the pin and `config/config.exs` cannot drift apart silently.
- **`make ctrld-server`** — interactive development. It brings up the compose stack below and
  carries the host network, so the LiveView server is reachable and reaches both databases on
  localhost. It prints the URL to use; on a Cloud Developer Machine that is the machine's
  port-proxy origin for port 4000 — `https://<machine-uuid>-4000.proxy.code.gropyus.com/` — never
  a bare localhost address, which a browser-only machine cannot open. Dependencies still resolve
  offline from the image caches. `make ctrld-databases-down` stops the databases again.

### The gate needs real databases and stays offline

The management server's suite is worth nothing against fakes: Ecto has to meet Postgres and the
telemetry writer has to meet ClickHouse, or the tests prove only that this codebase agrees with
itself. That reads as a conflict with the offline discipline and is not one, once the property is
named precisely. **What must not exist is unpinned input — not sockets.**

So the gate brings both databases up as sibling containers, pinned by digest in
`ctrld/third-party/sources.lock` and pulled by `make ctrld-image`, on a Podman network created
`--internal`: it has no gateway, so there is no route off it, no name resolution, and nothing to
reach. The gate container joins that network and **checks the absence for itself before it runs
anything** — it refuses to start if its own routing table holds a default route — so the day
something makes that network routable, the gate fails instead of quietly acquiring the internet.
Both databases hold their state on tmpfs and are torn down with the run, whatever the outcome: a
gate that inherits state from the last run is a gate that can pass for the wrong reason.

**A database that is not there fails the run; it never shrinks it.** The suite creates and migrates
both schemas before its first test and refuses to start if either store does not answer, and it
refuses to start at all if any test tag is excluded — the failure a gate cannot afford is the one
that still prints no failures.

The development stack is the same two digests read from the same two lines: `ctrld/compose.yaml`
takes `ctrld/third-party/sources.lock` as its environment file, so the databases a developer works
against and the ones the gate runs against cannot drift apart. Unlike the gate's, its volumes are
named and survive a restart, and its key-encryption key and administrator password are generated
once into `ctrld/build/dev/` — untracked, because the development database holds CA material
sealed under the first of them and a key that has to survive a restart is a key that must not be
committed.

### Changing a dependency means rebuilding the builder

The offline caches are warmed from the committed manifests during the image build, so the manifests
and the image move together:

1. edit `ctrld/mix.exs`,
2. `make ctrld-deps` — networked, and the only thing that writes `ctrld/mix.lock`; the gate cannot
   produce a lockfile it is simultaneously checking,
3. `make ctrld-image` — re-warms the Hex cache, the git mirrors and the precompiled-NIF cache from
   the new manifests,
4. `make ctrld-test` — offline again, resolving everything from those caches.

Skipping step 3 fails at step 4 with a dependency the image does not carry, which is the intended
failure: the gate never fetches.

## Landing changes

Commits go straight to `trunk`; there are no long-lived branches, no remote feature branches, and
no pull requests. Install the git hooks once per worktree with `make hooks` — it points
`core.hooksPath` at `.githooks`, which git resolves relative to each worktree:

- **pre-commit** runs `make test` — both fast gates. It does not boot QEMU, so it stays fast.
- **pre-push** runs `make ci` — the complete gate.

The two hooks do not cover the same commits, and the difference is worth knowing before trusting a
bisect. Every commit reaching `trunk` has passed both fast gates — the ctrld gate, and the datad
host gate's formatting, lints, host tests and their coverage floors, the budget ratchets, the
system-description, reference-chapter and configuration-document checks, and dependency policy —
while the full gate runs once per push,
against the tip. A push carrying several commits therefore leaves the intermediate ones qualified
by pre-commit alone, so a bisect may land on a commit that was never booted. Do not bypass the
hooks; a finding is fixed, not skipped. Commit subjects follow Conventional Commits
(`type(scope): description`), and the message explains the intent, constraints, and semantic
consequences of the change — the *why* — not a narration of the file edits, which the diff already
shows.

The gate verifies what a machine can check, and that is less than the practice the project holds
itself to: a green gate is necessary, never sufficient. What it checks mechanically:

| Check | Command |
|---|---|
| Formatting, in both workspaces — the fuzz harnesses are their own, so one invocation never saw them | `cargo fmt --all --check` |
| Lints, warnings denied — every host crate, and the protection domains for seL4 in **both** kernel configurations | `cargo clippy` over an explicit `-p` list, in `xtask test` |
| A `SAFETY` comment *present* on every `unsafe` block | `undocumented_unsafe_blocks = "deny"` |
| Per-file comment ratio and per-crate `unsafe` count never rise, across `datad/crates/` and `datad/pds/` | `xtask test` (the budget ratchets) |
| Coverage floors (94% combined, 90% per library crate) | `cargo llvm-cov` in `xtask test` |
| Dependency, license and source policy | `cargo deny check bans licenses sources` |
| The system description agrees with the constants the domains compile against: every region's extent, cacheability and per-grant permissions, the **exact** set of domains that map it, both I/O-port windows against the constants the drivers form addresses from, every channel end's notify direction, the port→driver attribution, and that each of the 151 mappings is named by a `setvar_vaddr` | `xtask test` (`sysdesc::check`) |
| The shipped configuration document is one the appliance would accept: it goes through the same `config::load` the configuration domain runs at boot | `xtask test` (`image::check_configuration`) |
| The console and metrics reference chapters agree with the code, both directions: every `cause=` refusal token per domain, every `rejected=` reason, every metric family with its type, label-name set and publishing domains, and the counts those chapters state about themselves — plus the counts the status detail chapter states about the gate: how many system scenarios there are, how many reach the management port, and how many library crates carry the coverage floor | `xtask test` (`reference_contract`) |
| The fuzz targets the gate runs, and the harnesses the seed corpora replay through, are each exactly the set the fuzz manifest declares — both directions, so a declared target left off either list fails here rather than building under the sanitizer and never running | `xtask test`, `xtask fuzz` (the seed smoke tests) |
| Fuzz targets build and their seed corpora replay; each also runs bounded where the sandbox lets an instrumented binary start | `xtask fuzz` |
| Boot, forwarding and A/B contracts | `xtask test-system`, `xtask test-ab` |
| One boot on the emulator whatever the machine offers, judging the cryptography domain alone — because a defect that only appears under emulation is otherwise unobserved on a machine that has acceleration, and every machine this gate runs on does | `xtask test-system` (the `cryptography-under-emulation` scenario) |
| The management server's dependency lock, formatting, a warning-free compile, both schema migrations, and its whole suite against a real Postgres and a real ClickHouse | `make ctrld-test` |
| That the management server's gate is genuinely offline: its container refuses to run if it holds a default route | `make ctrld-test`, before anything else it does |

`sysdesc::check` is the **only** machine check of the capability topology. Because it names each
region's mapper set exactly, a grant that widens and a grant that vanishes are both findings there
and nowhere else — including the one shape the rest of it cannot see, a mapping no `setvar_vaddr`
names, which is authority granted to a domain with no line of code in it able to say where.

`reference_contract` is why the book's *content* is now gated without the book becoming a build
input: rendering is still a reading convenience, mdbook is still not pinned into the builder, and
no gate calls `make book` — but three chapters are read as data and held to the code, so the
operator's interface definition can no longer go stale with every stage green. Two of them are the
reference chapters; the third is the status detail, read for the counts it states about the gate,
because three of those had gone stale at once with every stage passing.

Four things that table must not be read as saying.

The lint command is **not** a bare `cargo clippy -- -D warnings`:
`default-members = ["tools/xtask"]` makes that select `xtask` alone and report clean without
looking at a single library crate, which is why `xtask` names its packages explicitly and fails the
build when the list is incomplete.

The gate runs offline, so `cargo deny check advisories` is not in it — vulnerability scanning is a
deliberate manual run (`cargo deny check advisories`, with the network available), and nothing runs
it automatically. A green gate is a dependency-policy pass and not an advisory scan.

The two ratchets do not reach as far as the two `unsafe` lint denials do. `unsafe_op_in_unsafe_fn`
and `undocumented_unsafe_blocks` are workspace lints and bind every member; the comment and
`unsafe` budgets measure the product trees, `datad/crates/` and `datad/pds/`, and neither
`datad/tools/` nor the separate `datad/fuzz/` workspace. For `xtask` and the fuzz harnesses the
discipline is review, not a gate.

And `reference_contract` sees less of its chapters than the row above may suggest. It compares
the parsed tables and the counts the chapters state about themselves — and deliberately not: prose
of any kind, a family's `HELP` text included; label *values*, because a shard's series carry what a
running node happens to publish rather than a closed set; `librefirewall_interface_info`'s label
names, which are byte literals in the exposition writer rather than a table; and which group a
token sits in, since a domain's tables are compared as one set per domain. In the status detail
chapter it reads a count only where the page states a number in front of the phrase it looks for:
a sentence that mentions the scenarios without counting them is prose and is left alone, so a
number deleted from one of several places while another keeps it passes. A check whose reach is
unstated invites confidence it has not earned, so those five gaps stay the reader's to close.

## Build profiles

Two profiles exist. There is no debug *binary*: the protection domains compile under the
`--release` Cargo profile in both, so first-party code is one compilation. What differs is the seL4
kernel build, which is why "debug" is better read as "release plus kernel diagnostics".

- `release` — the artifact. Every gate that boots anything boots this one, and it is what
  `make image` builds with no flag.
- `debug` — a diagnostic tool, not a test target. The kernel prints, so a fault reports itself
  instead of vanishing into an empty serial log. Reached three ways: `make run`, `make image-debug`,
  and automatically when an end-to-end scenario fails — the harness re-runs that one scenario on it
  and surfaces the result as evidence, never letting it change the verdict. That third way is why
  the configuration is load-bearing rather than incidental: when it cannot be assembled, every
  failing scenario reports that the re-run never reached a boot, and the diagnosis is gone exactly
  when it is wanted.

  Two different things stand behind it, and both are now in a gate. The two-configuration Clippy
  pass compiles this configuration's protection domains on every `make test`, which keeps the
  *compilation* from rotting; and `make ci` *assembles* the debug image — as a scenario disk under
  the build tree, never published over the release disk it just judged — and boots it not at all.
  Treating the first as standing in for the second is what once left `image-debug` broken with every
  gate green: the two steps compile into separate artifact directories, and neither noticed that a
  target specification had moved under them. Assembling it proves nothing about the appliance and
  everything about the diagnosis being available when a failure finally wants it.

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
in `datad/Cargo.toml`, `xtask`, or `datad/systems/` wires them.

## Release artifacts

`make release` runs the complete acceptance gate and boots nothing of its own — `ci` already
assembles the release configuration into `datad/dist/` and already holds that disk to both
contracts a booted appliance owes. What `make release` adds: if the gate did not prove the
artifact, `datad/dist/` is emptied rather than left holding an unproven image that looks finished.
That covers a failure anywhere in the run, not a failed boot alone, because assembly populates
`datad/dist/` partway through and an incomplete release is no more publishable than an unproven
one. Nothing publishes these artifacts automatically: a release is whatever a green `make release`
left in `datad/dist/`.

The deployable artifact is `datad/dist/librefirewall-qemu-x86_64.img`, the signed GPT A/B disk
booted through OVMF and GRUB. Alongside it, `datad/dist/` carries five product-prefixed pieces of
release evidence and nothing else: the loose kernel and system images (the update input), a
manifest describing the target, pinned inputs and signing trust profile, an SPDX 2.3 SBOM (see
[Implementation status in detail](status-detail.md#engineering-foundations) for what it does and
does not cover), and a SHA-256 checksum file covering every other artifact. The Microkit
capability/memory report is deliberately **not** published: it is a full disclosure of the system's
authority topology, so it stays under `datad/build/image/<config>/`.

Image builds generate a throwaway development signing key under `datad/build/dev-keys/` (never
committed; removed by `make clean`); the manifest records `trust_profile: development` so a
development-signed image can never be mistaken for a production one.

All commands force Podman's `cgroupfs` manager. Override `PODMAN` only to select a compatible
Podman executable; Docker is not a supported build interface.

On a development machine behind a TLS-inspecting proxy, both builder builds automatically detect an
installed inspection CA (a `*-dpi-ca.crt` under `/usr/local/share/ca-certificates/`) and provide
it as a Podman build secret. On another inspected network, or to select a specific certificate,
pass its path explicitly:

```sh
make image ENTERPRISE_CA_FILE=/path/to/enterprise-ca.pem
make ctrld-image ENTERPRISE_CA_FILE=/path/to/enterprise-ca.pem
```

The CA reaches only the build steps that fetch dependencies, and the bundle each of them derives is
removed within that same step, so it does not persist into an image layer. TLS verification stays
enabled for every download. Never commit the certificate — or any other key material.

## Repository layout

The repository holds a two-component product. `datad/` is the appliance: the Rust seL4/Microkit
system and its entire build. `ctrld/` is the management server: an Elixir/Phoenix application laid
out the way Phoenix projects are (`mix.exs`, `config/`, `lib/`, `test/`, `assets/`, `priv/`), with
its pinned builder under `ctrld/build/`, its pinned inputs in `ctrld/third-party/`, and the
development database stack in `ctrld/compose.yaml`. The book, `README.md`, and `LICENSE.md` stay at
the repository root and cover both components.

Inside `datad/`, directories have fixed purposes; they grow as real functionality lands, and no
empty placeholders are created.

- `datad/crates/` — portable `no_std` libraries holding the firewall and dataplane logic. This is
  where most code and almost all tests live.
- `datad/pds/` — protection-domain binaries: thin adapters that map shared regions and drive a
  library crate's logic. Correctness logic belongs in a crate, not here, so it can be host-tested.
- `datad/systems/` — the Microkit system description(s): the static capability topology. A
  capability change is a security change.
- `datad/tools/` — the `xtask` build/test/packaging orchestrator and the QEMU harness.
- `datad/fuzz/` — the persistent `cargo-fuzz` targets for the untrusted parsers, in their own
  workspace so the ASan/libFuzzer instrumentation never enters a protection-domain build. Criterion
  microbenchmarks are *not* a top-level directory: each lives in its crate's own `benches/`, beside
  the code it measures.
- `book/` — this book, plain Markdown under `book/src/`. Render it with `make book` (which runs
  [mdBook](https://rust-lang.github.io/mdBook/); install it with `cargo install mdbook`), or read
  the Markdown directly.
- `datad/build/`, `datad/third-party/`, `datad/support/` — the pinned hermetic builder, pinned
  upstream inputs, and target specifications.
