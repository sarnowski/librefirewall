include third-party/sources.lock

PODMAN ?= podman
BUILDER_IMAGE ?= localhost/librefirewall-builder:microkit-$(MICROKIT_VERSION)
# Expose the KVM device to the sandbox for accelerated QEMU when the host has
# it; the harness falls back to emulation when it is absent.
KVM_FLAGS := $(if $(wildcard /dev/kvm),--device /dev/kvm --group-add keep-groups,)
CONTAINERFILE := build/container/Containerfile
CONTAINER_IGNORE := build/container/containerignore
ENTERPRISE_CA_FILE ?= $(firstword $(wildcard /usr/local/share/ca-certificates/*-dpi-ca.crt))

ifeq ($(strip $(ENTERPRISE_CA_FILE)),)
CA_SECRET :=
else
CA_SECRET := --secret=id=enterprise_ca,src=$(abspath $(ENTERPRISE_CA_FILE))
endif

.PHONY: image image-debug run test coverage bench fuzz verify-reproducible test-system test-ab ci release hooks book clean

# `image` provisions the pinned builder and is therefore the ONLY target that
# reaches the network. Every other target requires that image to already exist
# and refuses to build it, so no gate command can quietly turn into an OCI
# build — and the offline guarantee is enforced here rather than asserted in
# prose.
#
# It builds the RELEASE seL4 kernel configuration: the artifact a deployment
# gets, and the one every end-to-end scenario in `ci` boots.
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

test:
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

ci:
	$(require_builder)
	$(call xtask,ci)

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

# xtask owns the list of generated directories (tools/xtask host::clean), so
# clean runs in the container like every other command rather than restating
# that list here where the two would drift.
clean:
	$(require_builder)
	$(call xtask,clean)

define provision_builder
$(PODMAN) --cgroup-manager=cgroupfs build \
	--file $(CONTAINERFILE) \
	--ignorefile $(CONTAINER_IGNORE) \
	--build-arg BASE_IMAGE=$(DEBIAN_IMAGE) \
	$(CA_SECRET) \
	--tag $(BUILDER_IMAGE) .
endef

define require_builder
@$(PODMAN) image exists $(BUILDER_IMAGE) || { \
	echo "make: builder image $(BUILDER_IMAGE) is not present."; \
	echo "make: run 'make image' first — it is the only network-enabled phase and provisions the pinned builder."; \
	exit 1; \
}
endef

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
	$(KVM_FLAGS) \
	$(1) $(BUILDER_IMAGE) cargo xtask $(2)
endef

define xtask
	$(call container,, $(1))
endef

define xtask_interactive
	$(call container,--interactive --tty, $(1))
endef
