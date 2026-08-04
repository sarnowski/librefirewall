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
else
CA_SECRET := --secret=id=enterprise_ca,src=$(abspath $(ENTERPRISE_CA_FILE))
endif

.PHONY: image image-debug run test coverage bench fuzz verify-reproducible test-system test-ab ci release hooks book clean ctrld-image ctrld-test ctrld-server

# `image` and `ctrld-image` provision the two pinned builders and are the only
# targets that fetch from the network. Every other target requires its image
# to already exist and refuses to build it, so no gate command can quietly
# turn into an OCI build — and the offline guarantee is enforced here rather
# than asserted in prose. (`ctrld-server` carries the host network so a
# browser can reach it, but HEX_OFFLINE keeps its dependencies coming from the
# image caches like every other target.)
#
# `image` builds the RELEASE seL4 kernel configuration: the artifact a
# deployment gets, and the one every end-to-end scenario in `ci` boots.
image:
	$(provision_builder)
	$(call xtask,image)

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

# Provision the pinned BEAM builder for ctrld — the second network-enabled
# phase, with the same CA-secret plumbing as `image`.
ctrld-image:
	$(provision_ctrld_builder)

# The ctrld offline gate: dependency lock, formatting, a warning-free compile,
# the asset binaries provisioned from the image (never downloaded), and the
# test suite — all with the network disabled, resolving everything from the
# caches warmed into the builder.
ctrld-test:
	$(require_ctrld_builder)
	$(call ctrld_container,--network=none --env MIX_ENV=test,sh -c 'cp -r /opt/hex /tmp/hex && mix deps.get --check-locked && mix format --check-formatted && mix compile --warnings-as-errors && ctrld-provision-assets && mix test')

# Interactive development server. It carries the host network so the LiveView
# server on localhost:4000 is reachable — through the machine's port-proxy
# origin printed below, never a bare localhost address — while HEX_OFFLINE
# keeps dependencies coming from the image caches.
ctrld-server:
	$(require_ctrld_builder)
	@echo "ctrld dev server (once booted): https://$$(hostname | sed 's/^vm-//')-4000.proxy.code.gropyus.com/"
	$(call ctrld_container,--network=host --interactive --tty,sh -c 'cp -r /opt/hex /tmp/hex && mix deps.get --check-locked && ctrld-provision-assets && exec mix phx.server')

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
	--tmpfs /tmp:rw,nosuid,nodev \
	--mount type=bind,src=$(CURDIR),dst=/workspace,rw=true \
	--workdir /workspace/datad \
	$(KVM_FLAGS) \
	$(1) $(BUILDER_IMAGE) cargo xtask $(2)
endef

define xtask
	$(call container,, $(1))
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
