include datad/third-party/sources.lock
include ctrld/third-party/sources.lock

PODMAN ?= podman
BUILDER_IMAGE ?= localhost/librefirewall-builder:microkit-$(MICROKIT_VERSION)
CTRLD_BUILDER_IMAGE ?= localhost/librefirewall-ctrld-builder:elixir-$(ELIXIR_VERSION)
# Expose the KVM device to the sandbox for accelerated QEMU when the host has
# it; the harness falls back to emulation when it is absent.
KVM_FLAGS := $(if $(wildcard /dev/kvm),--device /dev/kvm --group-add keep-groups,)
CONTAINERFILE := datad/build/container/Containerfile
CONTAINER_IGNORE := datad/build/container/containerignore
CTRLD_CONTAINERFILE := ctrld/build/container/Containerfile
CTRLD_CONTAINER_IGNORE := ctrld/build/container/containerignore
ENTERPRISE_CA_FILE ?= $(firstword $(wildcard /usr/local/share/ca-certificates/*-dpi-ca.crt))

ifeq ($(strip $(ENTERPRISE_CA_FILE)),)
CA_SECRET :=
CA_MOUNT :=
else
CA_SECRET := --secret=id=enterprise_ca,src=$(abspath $(ENTERPRISE_CA_FILE))
# The run-time counterpart of CA_SECRET, for the two targets that fetch from
# the network outside an image build. It is a read-only bind mount rather than a
# layer: the inspection CA is never baked into an image, and a target that runs
# offline never sees it at all.
CA_MOUNT := --mount type=bind,src=$(abspath $(ENTERPRISE_CA_FILE)),dst=/etc/ssl/enterprise-ca.crt,ro=true
endif

COMPOSE ?= docker-compose
CTRLD_COMPOSE_FILE := ctrld/compose.yaml
CTRLD_COMPOSE_ENV := ctrld/third-party/sources.lock
CTRLD_COMPOSE_PROJECT := librefirewall-ctrld

.PHONY: image image-debug deps run test coverage bench fuzz verify-reproducible test-system test-ab ci release hooks book clean ctrld-image ctrld-deps ctrld-test ctrld-server ctrld-databases-down

# `image`, `deps` and `ctrld-image` are the provisioning targets and the only
# ones that fetch from the network. Every other target requires its builder
# image to already exist and refuses to build it, so no gate command can
# quietly turn into an OCI build or a registry fetch — and the offline
# guarantee is enforced here rather than asserted in prose. (`ctrld-server`
# carries the host network so a browser can reach it, but HEX_OFFLINE keeps
# its dependencies coming from the image caches like every other target.)
#
# `image` builds the RELEASE seL4 kernel configuration: the artifact a
# deployment gets, and the one every end-to-end scenario in `ci` boots.
image:
	$(provision_builder)
	$(call xtask,image)

# Resolve the appliance's Cargo manifests into datad/Cargo.lock, and nothing
# else. This is the ONLY writer of that lockfile and of the fuzz workspace's:
# every other target runs --network=none against the caches the builder image
# warmed, so a manifest that gained a dependency cannot resolve anywhere else.
#
# The cycle, after editing a Cargo.toml: `make deps` writes the lockfile,
# `make image` rebuilds the builder so its offline cache holds the new crates,
# and only then does any gate target see them.
#
# It runs the pinned builder's cargo rather than the host's, so the resolution
# is the one the offline build will replay. Nothing is compiled here and no
# artifact is produced — a fetch that also built would be a build outside the
# offline guarantee.
deps:
	$(require_builder)
	$(call deps_container,cargo fetch && cargo fetch --manifest-path fuzz/Cargo.toml)

# The debug kernel as an explicit opt-in, for hand inspection of a build
# nothing ships. No gate reaches it; `ci` boots the release image.
image-debug:
	$(require_builder)
	$(call xtask,image-debug)

# Interactive development, and the one place the debug kernel still earns its
# place: a human is reading the serial output as it happens.
run:
	$(require_builder)
	$(call xtask_interactive,run)

# The repository gate covers both components. The ctrld gate runs first: it is
# the fast half, so a finding there surfaces before the datad gate spends its
# minutes.
test: ctrld-test
	$(require_builder)
	$(call xtask,test)

coverage:
	$(require_builder)
	$(call xtask,coverage)

bench:
	$(require_builder)
	$(call xtask,bench)

fuzz:
	$(require_builder)
	$(call xtask,fuzz)

verify-reproducible:
	$(require_builder)
	$(call xtask,verify-reproducible)

test-system:
	$(require_builder)
	$(call xtask,test-system)

test-ab:
	$(require_builder)
	$(call xtask,test-ab)

ci: ctrld-test
	$(require_builder)
	$(call xtask,ci)

# Provision the pinned BEAM builder for ctrld and pull the two pinned
# database images — the second network-enabled phase, with the same CA-secret
# plumbing as `image`. The databases are pulled here rather than baked into
# the builder because they run as sibling containers, not as part of it; every
# later target requires them to be present already, exactly as it requires the
# builder.
ctrld-image:
	$(provision_ctrld_builder)
	$(pull_ctrld_databases)

# Re-resolve the Hex dependency tree and rewrite mix.lock. This is the one
# ctrld target besides `ctrld-image` that reaches the network, and it exists
# because the gate cannot produce a lockfile it is simultaneously checking:
# editing mix.exs means running this, then `make ctrld-image` to re-warm the
# offline caches from the new manifests, and only then `make ctrld-test`.
ctrld-deps:
	$(require_ctrld_builder)
	$(call ctrld_container,--network=host --env HEX_OFFLINE=0 $(CA_MOUNT),sh -c 'cp -r /opt/hex /tmp/hex; if [ -s /etc/ssl/enterprise-ca.crt ]; then cat /etc/ssl/certs/ca-certificates.crt /etc/ssl/enterprise-ca.crt > /tmp/ca-bundle.crt; export HEX_CACERTS_PATH=/tmp/ca-bundle.crt SSL_CERT_FILE=/tmp/ca-bundle.crt; fi; exec mix deps.get')

# The ctrld offline gate: dependency lock, formatting, a warning-free compile,
# the asset binaries provisioned from the image (never downloaded), the schema
# migrations, and the test suite.
#
# The gate needs real databases — Ecto against Postgres, the telemetry writer
# against ClickHouse — and it must stay offline. Those are not in tension once
# the property is named precisely: what must not exist is *unpinned input*, not
# sockets. So the databases are pinned by digest, pulled by `ctrld-image`, and
# run as sibling containers on a network created `--internal`, which has no
# gateway and therefore no route off itself. The gate container asserts that
# absence for itself before it runs anything, so the day the network stops
# being internal the gate fails rather than quietly gaining the internet.
#
# Both databases are torn down with the run, whatever the outcome, and both
# hold their state on tmpfs: a gate that inherits state from the last run is a
# gate that can pass for the wrong reason.
ctrld-test:
	$(require_ctrld_builder)
	$(require_ctrld_databases)
	$(ctrld_gate)

# Interactive development server. The compose stack carries the two databases
# on published loopback ports and the server container carries the host
# network, so the LiveView server is reachable — through the machine's
# port-proxy origin printed below, never a bare localhost address — and
# reaches both databases on localhost. HEX_OFFLINE still holds, so dependency
# bytes come from the image caches here too.
ctrld-server:
	$(require_ctrld_builder)
	$(require_ctrld_databases)
	$(ctrld_dev_secrets)
	$(ctrld_compose) up --detach --wait
	@echo "ctrld dev server (once booted): https://$$(hostname | sed 's/^vm-//')-4000.proxy.code.gropyus.com/"
	$(call ctrld_container,--network=host --interactive --tty $(CTRLD_DEV_ENV),sh -c 'cp -r /opt/hex /tmp/hex && mix deps.get --check-locked && ctrld-provision-assets && mix ecto.create --quiet && mix ecto.migrate && mix ctrld.clickhouse.migrate && exec mix phx.server')

# Stop the development databases. They are left running by `ctrld-server` so a
# restart of the server does not restart them; this is how they go away.
ctrld-databases-down:
	$(ctrld_compose) down

release:
	$(require_builder)
	$(call xtask,release)

# Point git at the tracked hooks: pre-commit runs the fast gate (`make test`),
# pre-push the full gate (`make ci`). Run once per worktree; git resolves the
# path per worktree, so this does not touch other checkouts.
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks path set to .githooks (pre-commit=make test, pre-push=make ci)"

# The documentation book renders on the host: mdbook is a reading convenience,
# not a build input, so it is neither pinned into the builder nor part of any
# gate. The source under book/src is plain Markdown either way.
book:
	mdbook build book

# xtask owns the list of generated directories (datad/tools/xtask host::clean), so
# the datad half runs in the container like every other command rather than
# restating that list here where the two would drift. ctrld has no orchestrator
# beyond Mix, so its two generated trees are named here.
clean:
	$(require_builder)
	$(call xtask,clean)
	rm -rf ctrld/deps ctrld/_build

# The build context is the appliance component, not the repository root: every
# COPY in the Containerfile and every pattern in the containerignore is
# context-relative, so they stay unchanged as the tree around them moves.
define provision_builder
$(PODMAN) --cgroup-manager=cgroupfs build \
	--file $(CONTAINERFILE) \
	--ignorefile $(CONTAINER_IGNORE) \
	--build-arg BASE_IMAGE=$(DEBIAN_IMAGE) \
	$(CA_SECRET) \
	--tag $(BUILDER_IMAGE) datad
endef

define require_builder
@$(PODMAN) image exists $(BUILDER_IMAGE) || { \
	echo "make: builder image $(BUILDER_IMAGE) is not present."; \
	echo "make: run 'make image' first — it is a network-enabled provisioning phase and builds the pinned builder."; \
	exit 1; \
}
endef

# The repository root is mounted, and the run starts in the appliance
# component below it: cargo then finds datad/Cargo.toml, the `xtask` alias in
# datad/.cargo/config.toml, and datad/rust-toolchain.toml, while the book at
# the repository root stays reachable one level up.
#
# Incremental compilation is off. A cache may accelerate a build and must never
# decide one, and this cache twice decided one: the compiler crashed on a stale
# incremental tree — twice, in crates the change under test did not touch — and
# a gate whose verdict depends on what a previous run left behind is not a gate.
# What it costs is compile time on a warm tree; what it buys is a run that
# depends on the sources and the pinned toolchain alone.
define container
$(PODMAN) --cgroup-manager=cgroupfs run --rm \
	--network=none \
	--read-only \
	--cap-drop=all \
	--security-opt=no-new-privileges \
	--userns=keep-id \
	--user $$(id -u):$$(id -g) \
	--env HOME=/tmp \
	--env CARGO_NET_OFFLINE=true \
	--env CARGO_INCREMENTAL=0 \
	--tmpfs /tmp:rw,nosuid,nodev \
	--mount type=bind,src=$(CURDIR),dst=/workspace,rw=true \
	--workdir /workspace/datad \
	$(KVM_FLAGS) \
	$(1) $(BUILDER_IMAGE) cargo xtask $(2)
endef

define xtask
	$(call container,, $(1))
endef

# The one appliance run with the network on, for `deps`. It keeps every other
# hardening property of `container` — read-only image filesystem, no
# capabilities, the invoking user's uid, only the repository writable — and
# differs in exactly two: the network is up, and the corporate TLS-inspection
# CA is folded into a bundle on the run's own tmpfs so crates.io is reachable
# from behind it. The bundle is built inside the container and dies with it,
# on the same reasoning as the image build's tmpfs mount: it cannot reach a
# layer or the repository however the command exits.
define deps_container
$(PODMAN) --cgroup-manager=cgroupfs run --rm \
	--read-only \
	--cap-drop=all \
	--security-opt=no-new-privileges \
	--userns=keep-id \
	--user $$(id -u):$$(id -g) \
	--env HOME=/tmp \
	--tmpfs /tmp:rw,nosuid,nodev \
	--mount type=bind,src=$(CURDIR),dst=/workspace,rw=true \
	$(CA_MOUNT) \
	--workdir /workspace/datad \
	$(BUILDER_IMAGE) sh -euc 'if [ -s /etc/ssl/enterprise-ca.crt ]; then cat /etc/ssl/certs/ca-certificates.crt /etc/ssl/enterprise-ca.crt > /tmp/ca-bundle.crt; export SSL_CERT_FILE=/tmp/ca-bundle.crt; fi; export CARGO_HOME=/tmp/cargo; cp -a /opt/rust/cargo /tmp/cargo; $(1)'
endef

define xtask_interactive
	$(call container,--interactive --tty, $(1))
endef

define provision_ctrld_builder
$(PODMAN) --cgroup-manager=cgroupfs build \
	--file $(CTRLD_CONTAINERFILE) \
	--ignorefile $(CTRLD_CONTAINER_IGNORE) \
	--build-arg BASE_IMAGE=$(ELIXIR_IMAGE) \
	$(CA_SECRET) \
	--tag $(CTRLD_BUILDER_IMAGE) ctrld
endef

define require_ctrld_builder
@$(PODMAN) image exists $(CTRLD_BUILDER_IMAGE) || { \
	echo "make: builder image $(CTRLD_BUILDER_IMAGE) is not present."; \
	echo "make: run 'make ctrld-image' first — it is a network-enabled provisioning phase and builds the pinned BEAM builder."; \
	exit 1; \
}
endef

define pull_ctrld_databases
$(PODMAN) pull $(POSTGRES_IMAGE)
$(PODMAN) pull $(CLICKHOUSE_IMAGE)
endef

define require_ctrld_databases
@for image in $(POSTGRES_IMAGE) $(CLICKHOUSE_IMAGE); do \
	$(PODMAN) image exists "$$image" || { \
		echo "make: database image $$image is not present."; \
		echo "make: run 'make ctrld-image' first — it is a network-enabled provisioning phase and pulls the pinned databases."; \
		exit 1; \
	}; \
done
endef

define ctrld_compose
$(COMPOSE) --project-name $(CTRLD_COMPOSE_PROJECT) --env-file $(CTRLD_COMPOSE_ENV) --file $(CTRLD_COMPOSE_FILE)
endef

# Development-only credentials, generated once into a gitignored directory
# rather than written into this file: the development stack keeps state across
# restarts, so its key-encryption key has to survive a restart too, and a key
# that survives is a key that must not be committed. The gate needs neither —
# it mints fresh ones per run for databases it throws away.
CTRLD_DEV_SECRETS := ctrld/build/dev
CTRLD_DEV_ENV = --env DATABASE_URL=ecto://ctrld:ctrld-development@127.0.0.1:5432/ctrld_dev \
	--env CLICKHOUSE_URL=http://127.0.0.1:8123 \
	--env CLICKHOUSE_USER=ctrld \
	--env CLICKHOUSE_PASSWORD=ctrld-development \
	--env CLICKHOUSE_DATABASE=ctrld_dev \
	--env CTRLD_KEY_ENCRYPTION_KEY=$$(cat $(CTRLD_DEV_SECRETS)/key-encryption-key) \
	--env CTRLD_CHANNEL_ENDPOINT=10.0.2.2:4433 \
	--env CTRLD_ADMIN_EMAIL=admin@librefirewall.invalid \
	--env CTRLD_ADMIN_PASSWORD=$$(cat $(CTRLD_DEV_SECRETS)/admin-password)
define ctrld_dev_secrets
@mkdir -p $(CTRLD_DEV_SECRETS)
@test -s $(CTRLD_DEV_SECRETS)/key-encryption-key || head -c 32 /dev/urandom | base64 -w0 > $(CTRLD_DEV_SECRETS)/key-encryption-key
@test -s $(CTRLD_DEV_SECRETS)/admin-password || head -c 18 /dev/urandom | base64 -w0 > $(CTRLD_DEV_SECRETS)/admin-password
@echo "ctrld development administrator: admin@librefirewall.invalid, password in $(CTRLD_DEV_SECRETS)/admin-password"
endef

# The offline gate, start to finish: an internal network, the two pinned
# databases on it, the gate container joined to it, and an unconditional
# teardown. Container names carry this shell's pid so two worktrees can gate at
# once without colliding, and the databases are addressed by the IP podman
# assigns them because this host has no aardvark-dns and a network alias would
# not resolve.
# How long a database is given to answer before the gate calls it a failure.
# Bounded, as every wait in this project is, and generous rather than tight: a
# gate sharing eight cores with an appliance build has watched ClickHouse take
# well over a minute to accept its first query, and a bound that expires under
# load is a red gate that says nothing about the change.
CTRLD_DATABASE_READY_SECONDS ?= 300

define ctrld_gate
@set -eu; \
run="ctrld-gate-$$$$"; \
net="$$run-net"; pg="$$run-postgres"; ch="$$run-clickhouse"; \
password=$$(head -c 18 /dev/urandom | base64 -w0 | tr -d '=+/'); \
cleanup() { \
	$(PODMAN) rm --force --ignore "$$pg" "$$ch" >/dev/null 2>&1 || true; \
	$(PODMAN) network rm --force "$$net" >/dev/null 2>&1 || true; \
}; \
trap cleanup EXIT INT TERM; \
echo "ctrld gate: internal network $$net — no gateway, so no route off it"; \
$(PODMAN) --cgroup-manager=cgroupfs network create --internal "$$net" >/dev/null; \
$(PODMAN) --cgroup-manager=cgroupfs run --detach --name "$$pg" --network "$$net" \
	--env POSTGRES_USER=ctrld --env POSTGRES_PASSWORD="$$password" --env POSTGRES_DB=ctrld_gate \
	--env PGDATA=/var/lib/postgresql/data/pgdata --tmpfs /var/lib/postgresql/data \
	$(POSTGRES_IMAGE) >/dev/null; \
$(PODMAN) --cgroup-manager=cgroupfs run --detach --name "$$ch" --network "$$net" \
	--env CLICKHOUSE_USER=ctrld --env CLICKHOUSE_PASSWORD="$$password" \
	--tmpfs /var/lib/clickhouse --ulimit nofile=262144:262144 \
	$(CLICKHOUSE_IMAGE) >/dev/null; \
for attempt in $$(seq 1 $(CTRLD_DATABASE_READY_SECONDS)); do \
	$(PODMAN) exec "$$pg" pg_isready -U ctrld -d ctrld_gate >/dev/null 2>&1 && break; sleep 1; \
done; \
$(PODMAN) exec "$$pg" pg_isready -U ctrld -d ctrld_gate >/dev/null 2>&1 || { \
	echo "ctrld gate: Postgres was still not ready after $(CTRLD_DATABASE_READY_SECONDS)s — the gate needs a database and does not skip its tests"; \
	$(PODMAN) logs "$$pg"; exit 1; }; \
for attempt in $$(seq 1 $(CTRLD_DATABASE_READY_SECONDS)); do \
	$(PODMAN) exec "$$ch" clickhouse-client --user ctrld --password "$$password" --query 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; \
done; \
$(PODMAN) exec "$$ch" clickhouse-client --user ctrld --password "$$password" --query 'SELECT 1' >/dev/null 2>&1 || { \
	echo "ctrld gate: ClickHouse was still not ready after $(CTRLD_DATABASE_READY_SECONDS)s — the gate needs a database and does not skip its tests"; \
	$(PODMAN) logs "$$ch"; exit 1; }; \
pgip=$$($(PODMAN) inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$$pg"); \
chip=$$($(PODMAN) inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$$ch"); \
echo "ctrld gate: Postgres at $$pgip:5432 and ClickHouse at $$chip:8123"; \
$(call ctrld_container,--network=$$net --env MIX_ENV=test --env DATABASE_URL=ecto://ctrld:$$password@$$pgip:5432/ctrld_gate --env CLICKHOUSE_URL=http://$$chip:8123 --env CLICKHOUSE_USER=ctrld --env CLICKHOUSE_PASSWORD=$$password --env CLICKHOUSE_DATABASE=ctrld_gate --env CTRLD_KEY_ENCRYPTION_KEY=$$(head -c 32 /dev/urandom | base64 -w0) --env CTRLD_CHANNEL_ENDPOINT=192.0.2.10:8443,sh -c 'if grep -qE "^[^[:space:]]+[[:space:]]+00000000[[:space:]]" /proc/net/route; then echo "ctrld gate: this container holds a default route so the gate network is not internal and the gate is not offline" >&2; exit 1; fi; cp -r /opt/hex /tmp/hex && mix deps.get --check-locked && mix format --check-formatted && mix compile --warnings-as-errors && ctrld-provision-assets && mix test')
endef

# The ctrld runs mirror the datad hardening: read-only image filesystem, no
# capabilities, the invoking user's uid, and only the repository mounted
# writable. $(1) carries the run mode — the gate passes --network=none, the
# development server the host network and a terminal. HEX_OFFLINE holds in
# both, so dependency bytes only ever come from the caches the image build
# warmed. HEX_HOME points into the tmpfs because Hex insists on persisting
# its registry cache; each command starts by copying the image's warmed
# cache there, which is what keeps that write off the read-only image.
define ctrld_container
$(PODMAN) --cgroup-manager=cgroupfs run --rm \
	--read-only \
	--cap-drop=all \
	--security-opt=no-new-privileges \
	--userns=keep-id \
	--user $$(id -u):$$(id -g) \
	--env HOME=/tmp \
	--env HEX_OFFLINE=1 \
	--env HEX_HOME=/tmp/hex \
	--tmpfs /tmp:rw,nosuid,nodev \
	--mount type=bind,src=$(CURDIR),dst=/workspace,rw=true \
	--workdir /workspace/ctrld \
	$(1) $(CTRLD_BUILDER_IMAGE) $(2)
endef
