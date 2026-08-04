# Certificate profile

This page is the exact profile of every certificate and certificate signing request the management
plane uses. It binds both components: the appliance generates keys, self-signed certificates and
CSRs to this page; the management server — which is the device-issuing CA — signs and issues to it;
and both ends validate against it. The [configuration package](configuration-package.md) is how the
issued artifacts reach the appliance.

## The algorithm is a field, never an assumption

Device identity is classical today, and the one rule that keeps it cheap to change is stated first:
**every consumer reads the signature and key algorithm out of the artifact it is looking at, and no
code path assumes one.** The certificate ecosystem has not moved to post-quantum signatures — chain
validators and the BEAM's own certificate handling validate classical chains only — so post-quantum
device identity is deliberately out of scope. Because the management server is the CA and holds
every issued certificate, moving the fleet to a post-quantum signature algorithm later is a
re-issuance campaign against this same profile with one row changed, not a redesign. (Post-quantum
*key exchange* is a separate concern and is in scope from the start — see the
[channel framing](channel-framing.md).)

Today's algorithm, everywhere: **ECDSA over P-256 with SHA-256** — for the device key, the CA key,
the channel endpoint's server certificate, and the onboarding certificate. It interoperates with any
CA tooling and with the BEAM's certificate handling natively.

## The device identifier

On first boot — and after every factory reset — the appliance generates a random **128-bit device
identifier** and renders it as **32 lowercase hexadecimal characters**. That string is the subject
common name of everything the appliance's identity appears in, and the only subject attribute: a
stable, meaningless name, carrying no serial number, no owner and no site, because the certificate
is an identity and not an inventory record.

## The artifacts

All four certificate kinds share: X.509 v3, ECDSA P-256 with SHA-256, a random 128-bit positive
serial number from the issuer's own generator, and a **validity of ten years** from issuance.
Ten years is deliberate: revocation is server-side, per-connection authorization in the management
application — there is no CRL and no OCSP on the appliance — so expiry is not the revocation
mechanism and a short lifetime would buy nothing but a fleet-wide re-issuance clock. The cost of the
matching non-remotable trust anchor — CA rollover means visiting every appliance — is recorded with
that decision in the [management design](../design/management.md#lifecycle-rules).

| Artifact | Subject | Issuer | Key usage | Extended key usage | Subject alternative name |
|---|---|---|---|---|---|
| Onboarding certificate | CN = device id | self-signed | digitalSignature | serverAuth | none |
| Device certificate | CN = device id | the management CA | digitalSignature | clientAuth | none |
| Channel endpoint certificate | CN = the endpoint IP as text | the management CA | digitalSignature | serverAuth | iPAddress = the endpoint IP |
| Management CA certificate | CN = a name the server chooses | self-signed | keyCertSign | none | none |

The CA certificate carries `basicConstraints` critical, `CA:true`, path length zero — it signs
end-entity certificates and nothing signs below it. The other three carry `basicConstraints`
critical, `CA:false`. The channel endpoint certificate's subject alternative name is the endpoint IP
address, because the appliance dials an address literal and validates the certificate against what
it dialed.

## The certificate signing request

The CSR the appliance serves at `GET /certificate.csr` is PKCS#10: subject CN = the device id, no
other subject attributes, signed with the device key. It requests no extensions, and **the CA honors
no requested extension** — everything in the issued certificate comes from this profile and from the
CA's own knowledge, so a CSR is a proof of key possession and a name, never a channel for reaching
into the certificate's contents.

## The SPKI fingerprint

The fingerprint that authenticates an appliance to its administrator is defined once and rendered
one way everywhere: **SHA-256 over the DER-encoded SubjectPublicKeyInfo** of the certificate's
public key, rendered as **64 lowercase hexadecimal characters with no separators**. The appliance
prints it on the console; the onboarding page and the management application display it; an
administrator compares two renderings of the same definition, character for character. A second
rendering — colons, upper case, a truncation — is a defect, because two fingerprints an
administrator must mentally normalise before comparing are two fingerprints that will be compared
carelessly.

The fingerprint is over the public key, not the certificate, deliberately: the self-signed
onboarding certificate and the CA-issued device certificate carry the same key, so the fingerprint
verified at first contact still names the appliance after issuance.

## Encodings

Every certificate travels as PEM with the `CERTIFICATE` label; the CSR as PEM with the
`CERTIFICATE REQUEST` label — one encapsulated structure per file, no leading or trailing content.
The [configuration package](configuration-package.md) bounds the files these travel in.
