# Cryptography profile

This page is two things an operator needs and a build can be held to: **what a processor must
provide** for this appliance to run at all, and **what the appliance proves about its own
cryptography every time it boots**. Both halves are read as data by the build — the feature table
against the target specification the cryptography domain is compiled with, the primitive table
against the vocabulary that domain reports in — so a page that drifts from the binary fails the gate
rather than misleading a purchase.

## The processor requirement

The appliance is compiled for the features below. They are **mandatory, not preferred**: a feature
enabled at compile time and absent from the part is an invalid-opcode fault on first use, not a slow
path. Every one of them has been universal on Intel and AMD server parts since roughly 2013.

| enabled target feature | why |
|---|---|
| `sse` | the base of the XMM register file everything below uses |
| `sse2` | integer XMM operations; the ChaCha20 backend and every AES helper are written against it |
| `sse3` | carried by the same parts and enabled with the rest of the tier |
| `ssse3` | byte shuffles, which the AES and GHASH backends use for endianness and state permutation |
| `sse4.1` | `pinsr`/`pextr` and blends, which the AES-GCM backend uses on partial blocks |
| `sse4.2` | carried by the same parts and enabled with the rest of the tier |
| `aes` | AES-NI. Without it AES-256-GCM falls to a software backend several times slower, and the throughput assertion below is what refuses to ship that quietly |
| `pclmulqdq` | carry-less multiply, which GHASH — the authentication half of AES-GCM — runs on |
| `adx` | multi-precision add-with-carry, for the big-integer arithmetic under the elliptic-curve work |
| `bmi2` | `mulx` and the bit-manipulation instructions the same arithmetic uses |

**What is deliberately not enabled, and why it is not a preference.** AVX and AVX2 would roughly
double ChaCha20 and SHA-2 throughput, and they are unavailable: the pinned kernel saves x87 and SSE
state per thread and not the wider vector state, so a protection domain executing an AVX instruction
holds a register the kernel will not preserve across a context switch. That is silent corruption of
a cipher's internals rather than a fault anyone would see. Enabling the tier means building the
kernel with a wider save area instead of consuming the pinned one, which is a change to the trusted
base and is out of scope here. The build asserts the absence: it disassembles the shipped protection
domains and fails if any of them names a wide vector register at all.

**SHA-NI is not enabled either, and here the reason is different and worth stating plainly.** The
product's position is that SHA-NI should be detected at runtime, because it arrived with AMD Zen 1
and Intel Ice Lake and enabling it at compile time would exclude Haswell- and Skylake-era parts
still in service. That position is not achieved on this image, and the cause is the same mechanism
that keeps AVX out: the adopted hash library detects the feature through a helper whose runtime
probe compiles to a constant `false` on a freestanding target, so the accelerated path is never
selected however capable the processor is. Making it selectable would mean making that probe run,
which would also make the AVX probes in the cipher libraries run — and those must not, for the
reason above. **SHA-256 therefore runs the portable implementation on this appliance**, at the cost
the table below reports, and no throughput figure on this page asserts otherwise.

## What the appliance proves at boot

The cryptography protection domain re-runs a committed corpus of published test vectors against the
code **as compiled for this target, on this processor**, before the node is of any use. A primitive
that disagrees with a published vector refuses the domain and names the row it disagreed with. Every
primitive below is proved on every boot; the counts are on the console and in the metrics.

| primitive | proven against | measured |
|---|---|---|
| `sha-256` | NIST CAVP SHAVS byte-oriented vectors, at the boundaries of the padding rule | yes |
| `hmac-sha-256` | NIST CAVP `HMAC.rsp` across the key lengths either side of the hash block, plus Wycheproof forgeries a verifier must refuse | no |
| `hkdf-sha-256` | Wycheproof, which carries RFC 5869's own appendix cases | no |
| `chacha20` | RFC 8439's keystream examples — the primitive the generator is built on | no |
| `chacha20-poly1305` | RFC 8439's worked example and Wycheproof, forgeries included | yes |
| `aes-256-gcm` | NIST CAVP `gcmEncryptExtIV256` and `gcmDecrypt256`, and Wycheproof, forgeries included | yes |
| `chacha20-drbg` | the generator's own output against an independent computation of the keystream it is defined as | no |

The corpus is a curated subset and not the whole published files, which run to megabytes: what is
kept is the adversarial shape of each — the boundary lengths where a padding or block loop changes
behaviour, the empty inputs, the keys either side of a hash block, and for everything that
authenticates, the forgeries a verifier must refuse.

**Why proving on the image and not only on the host.** A host test proves the source. It cannot
prove the instructions the source became on a different target with different features enabled,
running under a different kernel. The cryptography this appliance uses is adopted rather than
written here, and the whole basis for trusting an adopted library is that its correctness is
demonstrated on the artifact that ships.

## The accelerated backend, positively asserted

Correctness cannot tell an accelerated backend from a portable one — a software AES answers exactly
the same vectors. Three independent checks are what say the fast path is the one running, and all
three must hold:

1. **The processor was gated.** The domain reads `CPUID` before the first instruction from any gated
   set and refuses, naming the feature word, if a mandatory feature is missing. A node that reports
   ready has passed that gate.
2. **The instructions are in the binary.** The build disassembles the shipped protection domains and
   requires AES-NI and carry-less-multiply instructions to be present — and, as above, requires no
   wide-vector register to appear anywhere.
3. **It is fast enough that nothing else could be running.** The domain measures each primitive on
   the part and reports thousandths of a cycle per byte. AES-256-GCM is held below **4.0 cycles per
   byte**, derived as follows: the published accelerated figure is about one cycle per byte
   (2,957 MB/s for AES-256-GCM on a Xeon Gold 5412U), while the most optimistic published *portable*
   figure is 6.92 cycles per byte for bitsliced constant-time AES on a Core i7 — measured with SSSE3
   and carrying no GHASH, which without carry-less multiply is a table walk costing several cycles
   per byte more. Four sits four times above the accelerated figure and comfortably below the
   portable one, so it cannot be met by a fallback and cannot be missed by a slower accelerated part.

The other two measured primitives carry ceilings too, but those are **regression bounds and not
backend assertions**: SHA-256 runs the portable path for the reason given above, so a figure below
its ceiling says nothing about which backend answered.

**Measurements are asserted only on a run executing on real hardware.** Under emulation every guest
instruction is a host function call and the guest's cycle counter advances against emulated time, so
a figure taken there describes the emulator. Such a run reports its numbers in full and the verdict
says they were not asserted, rather than passing quietly.

## Where the numbers appear

| surface | what it carries |
|---|---|
| the console | one record per primitive with the vectors it proved, one per measured primitive with its cost, the `CPUID` feature words the part was accepted on, and a single ready or refused verdict |
| `librefirewall_crypto_proven` | 1 once every primitive answered every vector |
| `librefirewall_crypto_vectors_proven_total` | vectors answered, per primitive |
| `librefirewall_crypto_milli_cycles_per_byte` | measured cost, per primitive; 0 for a primitive that is not measured |

The exact console grammar is in [Console records](console.md) and the metric definitions in
[Prometheus metrics](metrics.md).

## Randomness

The node's deterministic random bit generator is seeded from **32 `RDRAND` draws — 2048 bits** for a
352-bit seed, each draw retried up to ten times as the vendor guidance prescribes, and every draw
checked against the shapes a broken generator produces: a word repeating the one before it, or a
word of all zeroes or all ones. Any of those refuses the domain rather than seeding it. All 2048
bits are folded into the seed with HKDF-SHA-256 rather than sliced, so one degraded draw among many
is diluted instead of placed directly into a key.

The generator itself is ChaCha20 in counter mode, rekeyed from its own output on every draw: the
first 32 bytes of each draw's keystream become the next key and are never emitted, so the state that
produced an output cannot be recovered from the state that follows it. Its output is therefore an
RFC 8439 keystream from byte 32 onward, which is what makes it provable against a published vector
rather than only against itself.

**No key material reaches any surface.** The seed, the generator's state and every value drawn from
it stay inside the domain that made them; the console and the metrics carry counts and costs and
nothing else.
