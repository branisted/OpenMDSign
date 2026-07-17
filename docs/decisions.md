# Design decisions

## Language & PKCS#11 binding: Go + github.com/miekg/pkcs11

**Choice:** Go 1.26 (pinned via `mise.toml`), with `github.com/miekg/pkcs11` as the
low-level Cryptoki binding for Phase 0.

**Why miekg/pkcs11 for Phase 0:** the recon harness needs the full low-level
surface — enumerating mechanisms with `C_GetMechanismInfo`, reading arbitrary
object attributes (`CKA_ID`, `CKA_VALUE`, `CKA_MODULUS_BITS`, `CKA_SIGN`), and
inspecting token flags. `miekg/pkcs11` exposes the C API almost verbatim, which
is exactly what recon wants. The higher-level `github.com/ThalesGroup/crypto11`
(a `crypto.Signer` wrapper over miekg) hides these details and is better suited
to Phase 2 signing; we defer adopting it until we know the signature profile.

**Maintenance check (2026-07-17):**
- `github.com/miekg/pkcs11`: latest tag **v1.1.2, released 2026-01-22** (prior
  v1.1.1 was 2022-01-05 — a long quiet period followed by a fresh 2026 release).
  ~337 commits, ~15 open issues. It is the de-facto standard Go PKCS#11 binding
  (used by crypto11, HashiCorp Vault, etc.). Verdict: healthy enough; low churn
  is expected for a thin, stable C binding.
- `github.com/spf13/cobra`: latest release **v1.10.2, 2025-12-04**; 27 releases,
  very active, 44k+ stars. Verdict: actively maintained, safe default CLI lib.
- `github.com/BurntSushi/toml` v1.4.0: standard, stable TOML library. Used for
  config parsing.

## Architecture: arm64 binary requires an arm64 PKCS#11 module

The host is macOS **arm64** (Darwin 25.5). `cgo`/`dlopen` loads a module of the
**same architecture** as the running binary. Of the vendor driver candidates:

| Module                   | Architectures         | Loadable by arm64 binary |
|--------------------------|-----------------------|--------------------------|
| `libeToken.dylib`        | x86_64 + arm64        | yes                      |
| `libcastle.1.0.0.dylib`  | x86_64 + arm64        | yes                      |
| `libbit4xpki.dylib`      | x86_64 + arm64        | yes                      |
| `libacos5pkcs11.dylib`   | x86_64 + **i386 only**| **no** (arch mismatch)   |

`libacos5pkcs11.dylib` has no arm64 slice, so an arm64 `openmdsign` cannot
`dlopen` it; it also is not in the vendor's driver list. To use it one would
need a Rosetta/x86_64 build of `openmdsign`. All three real driver candidates
are universal and load fine natively — confirmed by the Phase 0 smoke test (see
`docs/recon.md`).

`inspect` prints a `file`-based diagnostic on any load failure so an
architecture mismatch is self-explanatory.

## Pluggable `Signer` design

`internal/sign` defines a single `Signer` interface:

```go
type Signer interface {
    Profile() string
    Sign(ctx context.Context, tok TokenHandle, req Request) (Result, error)
}
```

No concrete implementation ships in Phase 0. The container profile
(XAdES / CAdES / PAdES) the target infrastructure expects is **unknown** until a
reference signature is dissected (see `docs/recon.md`). Keeping signing behind
an interface lets us implement whichever profile(s) the reference reveals — or
several — without reshaping the CLI. The interface deliberately forbids the
signer from performing its own login: PIN policy (exactly one attempt, no retry)
is owned entirely by the caller.

## PIN safety (cross-cutting, non-negotiable)

- A PIN, if supplied, drives **exactly one** `C_Login`. There is no retry loop
  anywhere in the codebase. On `CKR_PIN_INCORRECT` / `CKR_PIN_LOCKED` the tool
  aborts with a warning and a non-zero exit.
- A PIN is never passed to a `slog` call, an error string, or any serialized
  field. `--pin-stdin` is offered so the PIN stays out of shell history.

## Signature profile: RESOLVED by static analysis of the vendor code (2026-07-17)

The profile no longer has to wait for a runtime reference signature to be *named*
(though one is still needed to pin the exact sub-level — see recon.md §3). Static
inspection of the vendor jar
`moldsign2412unbundled/STISC/MoldSign/lib/PKCS11CardReader-2.0.jar` — class names
and UTF-8 constant-pool entries only; **no bytecode was disassembled to source and
no vendor binary is copied into this repo** — shows:

- **Arbitrary files → XAdES**, implemented on IAIK's `iaik.xml.crypto.xades`.
  `SignXAdESWorker` references `XAdES-T`, `XAdES-C`, `Detached`,
  `prepareSignInfoEnveloping`, `DataObjectFormat`, `QualifyingProperties`, digest
  `http://www.w3.org/2001/04/xmlenc#sha256`, and `SHA256withRSA`. So the target is
  **XAdES-T / XAdES-C, detached or enveloping, RSA + SHA-256.** No ASiC-specific
  strings appeared in the worker, so it may emit a standalone XAdES `.xml` rather
  than an ASiC-E zip — packaging must be confirmed against a real sample.
- **PDF files → PAdES**, via iText (`SignPDFWorker`, `sign-9.1.0.jar`).
- **No CAdES signer exists** — the CMS classes (`EncryptCMSAsymmetricWorker`,
  `DecryptCMSSymmetricWorker`, …) are for encryption only. Timestamping is a
  generic RFC 3161 client (`TSPTimeStampProcessor`).

**Consequence — this is the STOP condition below.** The primary file profile is
XAdES, so we do **not** hand-roll it in Go.

**Decision (2026-07-17, user-approved): Hybrid — Go front-end + Java EU DSS.**
- Go owns the CLI, PKCS#11/token access, X.509 parsing, config, and verify.
- **XAdES** signing is delegated to **EU DSS** (`eu.europa.esig.dss`, Java). The
  Go `Signer` for the XAdES profile shells out to a small DSS-based helper
  (bundled jar + JRE, or a locally running helper process). The token stays owned
  by Go: DSS must sign through a PKCS#11 `SignatureToken` OR Go computes the
  PKCS#11 signature and DSS assembles the XAdES around a pre-computed value —
  protocol TBD once the reference sample pins the level/packaging. PIN policy
  (one attempt, no retry) stays entirely on the Go side regardless.
- **PAdES** (PDF) stays pure-Go via `github.com/digitorus/pdfsign` +
  `github.com/digitorus/timestamp`. No Java on the PDF path.

Open sub-decisions, gated on the reference sample: exact XAdES level (T vs
C/LT/LTA), packaging (standalone `.xml` vs ASiC-E), and the Go↔DSS signing
protocol (DSS-holds-token vs Go-holds-token). Do not write the XAdES Signer until
these are known.

### Endpoints and trust anchors harvested (feed `internal/verify` + config)

- **TSA (RFC 3161):** `http://tsp.pki.gov.md/moldsign2/` (unauthenticated as observed).
- **Live issuing CA `mdtrustca`:** OCSP `http://mdtrustca.ocsp.pki.md`, CRL
  `http://pki.md/crl/mdtrustca.crl`, caIssuers `http://pki.md/cer/mdtrustca.cer`.
- **Trust set:** 19 anchors carved from `trusted.jks` inside the same jar and
  chain-verified with `openssl`. Two live self-signed roots — `mdtrustrootca`
  (exp 2040) and `mdtrustca` (exp 2045) — plus legacy `RootCA SIS 2` / `eMoldova`.
  Leaf CAs (MDQSign, MoldSign QCA 3A, …) verify against them. To be embedded as
  the built-in verify trust set (do **not** copy the vendor jks; re-fetch anchors
  from the public PKI URLs above for the repo).

## XAdES / ASiC-E caveat

If the reference signature turns out to be **XAdES inside an ASiC-E container**
(mimetype `application/vnd.etsi.asice+zip`), do **not** hand-roll XML
canonicalization (C14N) and XAdES qualifying properties — it is a notorious
source of subtle, non-interoperable bugs. In that case stop and evaluate driving
the mature **EU DSS** library (Java, `eu.europa.esig.dss`) or an equivalent,
rather than reimplementing XAdES from scratch. The vendor stack already bundles
IAIK XAdES/CMS/TSP jars, a strong hint the profile may be XAdES and/or CAdES.
Record the actual profile in `docs/recon.md` once known.

## Phase 2a: PAdES-B-T PDF signer — library validation & decisions (2026-07-18)

### `github.com/digitorus/pdfsign` validation (Step-1 gate)

Inspected the actually-installed source, not memory
(`pdfsign@v0.0.0-20260407063256-85ede6424a74`, dependency
`pkcs7@v0.0.0-20230818184609`, `timestamp@v0.0.0-20250524132541`).

**Maintenance:** healthy — the pinned `pdfsign` revision is from **April 2026**;
`timestamp` from **May 2025**. Pure Go, no JVM, MIT/BSD-licensed.

**Capability checklist (resolved API used):**

| Capability | Verdict | Resolved API |
|---|---|---|
| External `crypto.Signer` (token signs; no raw key) | **YES** | `sign.SignData.Signer crypto.Signer`, driven via `pkcs7.AddSignerChain`; `signAttributes` calls `signer.Sign(rand, SHA256(signedAttrs), crypto.SHA256)` |
| ESS `signingCertificateV2` (OID …16.2.47) | **YES** | `createSigningCertificateAttribute()` emits it for SHA-256 |
| RFC 3161 timestamp via configurable TSA | **YES** | `SignData.TSA.URL`; token embedded as unsigned attr OID …16.2.14 |
| SHA-256 / sha256WithRSAEncryption | **YES** | `SignData.DigestAlgorithm = crypto.SHA256` |
| `/SubFilter /ETSI.CAdES.detached` | **NO (hardcoded)** | upstream hardcodes `/adbe.pkcs7.detached` in `pdfsignature.go`; no config knob |
| Signed attrs == exactly {contentType, messageDigest, signingCertificateV2} | **NO** | upstream always injects legacy Adobe `adbe-revocationInfoArchival` (OID 1.2.840.113583.1.1.8), empty when no revocation |
| LTV `/DSS` document security store | **NO** | not implemented by pdfsign (it does the legacy CMS revocation attr, not the ETSI PDF-level `/DSS`) |

**Decision (STOP-flag resolved by minimal fork, not a non-conforming ship):**
Two of the required properties are not reachable through upstream configuration,
so per the Step-1 gate we did **not** ship a non-conforming signature. We took
the sanctioned *fork/patch* option: the `sign` subpackage is vendored verbatim
into `internal/pades/pdfsign/` (BSD-2-Clause `LICENSE` + `NOTICE.md` retained)
with exactly two patches, both marked `openmdsign FORK PATCH`:

1. `/SubFilter /adbe.pkcs7.detached` → `/ETSI.CAdES.detached`. The two names are
   both **19 bytes**, so the signed `/ByteRange` offsets are byte-identical; only
   the SubFilter name changes. (Post-processing the output was rejected because
   the SubFilter lives *inside* the signed ByteRange.)
2. Drop the always-injected `adbe-revocationInfoArchival` signed attribute, so the
   SignerInfo carries exactly contentType + messageDigest + signingCertificateV2.

All other upstream deps (`pkcs7`, `pdf`, `timestamp`, `revocation`, `verify`,
`filebuffer`, `x/crypto`, `x/text`) remain external module dependencies. To
re-sync with upstream: re-copy `sign/*.go`, re-apply the package rename and the
two `FORK PATCH` edits.

**`/DSS`-LTV: DEFERRED.** pdfsign cannot emit an ETSI `/DSS` store and the profile
lists it as best-effort. The signature is PAdES-**B-T** (timestamp inside the CMS),
not B-LT/B-LTA. Revisit if semnatura.md requires LTV material for acceptance.

### Token as `crypto.Signer` — `internal/token.Signer`

We did **not** adopt `crypto11`. Instead a thin `crypto.Signer` adapter sits over
the existing `internal/token` layer (`OpenSigner` / `Signer`):

- The `sign` command opens the module, and `(*Ctx).OpenSigner` opens a session and
  performs **exactly one** `C_Login` (same typed `*LoginError` path as `sign-raw`;
  on failure it aborts with the lockout warning, **no retry**), then locates the
  key + certificate by CKA_ID (or auto-selects the single CKA_SIGN key). The PIN
  is dropped the instant login returns and is never stored on the Signer.
- `Public()` returns the certificate's public key; `Certificate()` the leaf.
- `Sign(rand, digest, opts)` requires SHA-256, builds the PKCS#1 v1.5 DigestInfo
  via the shared `token.DigestInfoSHA256` (factored out of `sign_raw.go`), and
  raw-signs it with `CKM_RSA_PKCS`, returning a standard RSASSA-PKCS1-v1_5
  signature — exactly what `pkcs7.signAttributes` expects.
- The login/session lifetime spans the whole sign; the command defers
  `signer.Close()` (C_Logout + CloseSession). The Signer itself NEVER logs in.

### `sign` command & pluggable profile

`internal/sign` was reshaped around an already-authenticated `crypto.Signer`
(login stays with the caller). `internal/sign/pades` implements the `Signer`
interface for PDFs; the profile is selected by extension (`auto`) or `--profile`,
with a clear "XAdES not yet implemented — Phase 2b" error for non-PDF input so
XAdES can slot in later. Privacy: the PIN never reaches a log; only the input
basename (never a local absolute path) is used, and it is not written into
signature metadata.
