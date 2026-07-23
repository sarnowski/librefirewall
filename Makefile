include third-party/sources.lock

PODMAN ?= podman
BUILDER_IMAGE ?= localhost/librefirewall-builder:microkit-$(MICROKIT_VERSION)
# Expose the KVM device to the sandbox for accelerated QEMU when the host has
# it; the harness falls back to emulation when it is absent.
KVM_FLAGS := $(if $(wildcard /dev/kvm),--device /dev/kvm --group-add keep-groups,)
CONTAINERFILE := build/container/Containerfile
CONTAINER_IGNORE := build/container/containerignore
WRITABLE_DIRS := build dist sdk target
GROPYUS_CA_FILE ?= $(wildcard /usr/local/share/ca-certificates/gropyus-dpi-ca.crt)

ifeq ($(strip $(GROPYUS_CA_FILE)),)
CA_SECRET :=
else
CA_SECRET := --secret=id=gropyus_ca,src=$(abspath $(GROPYUS_CA_FILE))
endif

.PHONY: image run test test-system test-ab test-nic ci release clean builder prepare

image: builder prepare
	$(call xtask,image)

run: builder prepare
	$(call xtask_interactive,run)

test: builder prepare
	$(call xtask,test)

test-system: builder prepare
	$(call xtask,test-system)

test-ab: builder prepare
	$(call xtask,test-ab)

test-nic: builder prepare
	$(call xtask,test-nic)

ci: builder prepare
	$(call xtask,ci)

release: builder prepare
	$(call xtask,release)

clean:
	rm -rf build/bootstrap dist sdk target

builder:
	$(PODMAN) --cgroup-manager=cgroupfs build \
		--file $(CONTAINERFILE) \
		--ignorefile $(CONTAINER_IGNORE) \
		--build-arg BASE_IMAGE=$(DEBIAN_IMAGE) \
		$(CA_SECRET) \
		--tag $(BUILDER_IMAGE) .

prepare:
	mkdir -p $(WRITABLE_DIRS)

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
	$(1) $(BUILDER_IMAGE) cargo run --locked --package xtask -- $(2)
endef

define xtask
	$(call container,, $(1))
endef

define xtask_interactive
	$(call container,--interactive --tty, $(1))
endef
