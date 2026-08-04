# ctrld

The management server: the single pane of glass for a fleet of librefirewall appliances. It owns
appliance onboarding, configuration management, and telemetry; the appliance component lives in
`../datad/`.

Everything about this component — its design, its contracts with the appliance, and how to build,
test, and run it — is in the repository's documentation book under `../book/src/`: the design in
`design/management-server.md`, the wire contracts under `contracts/`, and the command surface
(`make ctrld-image`, `make ctrld-deps`, `make ctrld-test`, `make ctrld-server`) in
`developers/building.md`.

There is no Mix toolchain on the host; every command runs inside the pinned builder, from the
repository root.
