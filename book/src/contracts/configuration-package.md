# Configuration package

This page is the exact layout of the onboarding package — the one artifact the management server
produces and the appliance consumes during [onboarding](../design/management.md#onboarding). It binds
both components: the management server composes packages to this page, the appliance validates them
against it, and neither side carries a tolerance the other does not. The
[certificate profile](certificate-profile.md) specifies the certificates the package carries.

## The archive

The package is a plain, **uncompressed** tar archive in **ustar** format. Compression is
deliberately excluded: the contents are a few kilobytes of PEM and XML, so compression buys nothing,
and a decompressor would be a second parser on the untrusted input path with nothing to pay for
itself. The archive is uploaded whole, as the body of `POST /configuration.tar` on the onboarding
server.

**The package is not signed.** It is authenticated by the TLS session it travels in — the session
the administrator opened to the appliance's self-signed certificate after verifying its SPKI
fingerprint against the console, out of band. A signature would need an anchor the appliance already
trusts, and a factory-fresh appliance deliberately trusts nobody: the
[ownership model](../design/management.md#the-ownership-trust-model) is the trust mechanism, and the
package is what installs its result.

## Members

The archive carries **exactly four members**, each exactly once, each a regular file. Member order
is not significant. An unknown member name, a duplicate, or a missing member refuses the whole
package.

| Member | Content | Bound |
|---|---|---|
| `device-certificate.pem` | The CA-signed device certificate, one certificate, PEM | 16 KiB |
| `trust-anchor.pem` | The management CA certificate, one certificate, PEM | 16 KiB |
| `management-endpoint` | The channel endpoint, one textual line (below) | 32 bytes |
| `configuration.xml` | The appliance [configuration document](../design/configuration.md) | 64 KiB |

`management-endpoint` is one ASCII line of the form `<ipv4>:<port>`: a dotted-quad IPv4 address
literal in decimal, a colon, and a decimal port from 1 to 65535, optionally followed by a single
trailing line feed and nothing else. It is an address literal, never a name — DNS stays off the
untrusted path, so no resolver exists to be poisoned between an appliance and its management server.

The address is one a host can be dialled at: **the unspecified address, a loopback address, a
multicast or broadcast address, and the whole of the reserved top of the space are refused by
name.** Each of them names something other than a management server, and an appliance told to dial
one would spend its life reporting an unreachable next hop for a reason no operator could act on —
a package that cannot work is refused while an administrator is standing in front of the appliance,
which is the only moment at which it is cheap to fix.

**The endpoint is its own member, deliberately not an element of the configuration document.** The
configuration document is what later travels the channel, and the
[threat model](../design/threat-model.md#the-compromised-management-server) requires that a
configuration pushed over the channel can never change the endpoint. Keeping the endpoint out of the
document's schema makes that structural: a pushed document cannot even *express* an endpoint change,
which is stronger than any validation rule that would have to reject one.

The management port's **gateway** is in the document, and the two are not in tension. A gateway is a
routing fact — which station on this link carries traffic off it — and it changes with the site an
appliance is installed at, so it belongs with the rest of the addressing an operator maintains. An
endpoint is an ownership fact: which management server this appliance answers to. A pushed document
may move the appliance's traffic onto a different first hop, and the reachability that gives it is
the point; it may not change *who it is talking to*, and it cannot, because there is no attribute
for one.

`configuration.xml` is an ordinary configuration document, validated by the same reader and the same
rules as any other, and it may carry substantial inherited configuration — the management server
composes it so a freshly onboarded appliance comes up with the connectivity it needs to dial out.
Its 64 KiB bound is the document reader's own.

## Tar constraints

The reader accepts the narrowest tar that can carry four small files, and refuses everything else by
name:

- **ustar only.** The `ustar` magic and version are required in every header. GNU and PAX extensions
  — long-name entries, extended headers, global headers — are refused.
- **Regular files only.** The type flag must denote a regular file (`0` or the historical NUL). A
  link, symlink, directory, device node, or FIFO refuses the package; none of them has a meaning
  here.
- **Names are exact.** A member name is compared byte-for-byte against the four names above — no
  path prefix, no `./`, no name derived from the `prefix` field.
- **Bounded throughout.** The whole archive is bounded at **128 KiB**; each member at the bound in
  the table; the member count at exactly four. Every size field is parsed as bounded octal and
  checked against the bytes actually present, and each header's checksum must verify. The archive
  bound is the outer one a reader applies to bytes it has not yet parsed: the four member bounds
  together are smaller, so a well-formed package never approaches it, and a writer that composes one
  to this page can never produce one that exceeds it.
- **Every violation is a typed refusal** naming what was refused, and refusal installs nothing.

The tar reader is a new parser on an external-input path and is held to the standard for one: typed
errors, bounded work, no panicking construct, and a fuzz target.

## Validation and installation

The package is validated whole before anything is installed, and installation is all-or-nothing —
a package with one bad member changes nothing:

- `device-certificate.pem` must parse as one certificate whose public key equals the appliance's own
  — the keypair whose CSR the administrator carried to the management server. A certificate for any
  other key is somebody else's identity and is refused.
- `trust-anchor.pem` must parse as one CA certificate. The device certificate must chain to it,
  since the anchor is what the appliance will validate the channel against.
- `management-endpoint` must parse as above.
- `configuration.xml` must pass the configuration reader and every semantic rule, exactly as a
  document submitted any other way.

On success the appliance persists all four to its [store](../design/configuration.md#persistence),
prints the installed anchor's SPKI fingerprint and the endpoint on the console, closes the
onboarding server permanently, and dials out. From that moment the anchor and the endpoint are
[never changeable over the channel](../design/management.md#lifecycle-rules); replacing them is a
factory reset and a new package.
