# openmdsign

`openmdsign` is an open-source macOS command-line tool for signing files with a
hardware **PKCS#11** token (smartcard / USB crypto token). Its goal is
**interoperability** with the electronic-signature ecosystem already used in
Moldova, so that holders of a hardware token can create and inspect signatures
from a scriptable, open CLI on macOS.

> **Status: Phase 0 — recon harness.** The only command today is
> `openmdsign inspect`, which is entirely **read-only**. No signing is
> implemented yet (see the roadmap below).

## Legal / interoperability statement

- openmdsign is an **independent, unofficial** project. It is **not affiliated
  with, endorsed by, or connected to** any government authority, certification
  service provider, or the proprietary vendor middleware it interoperates with.
- Any reverse engineering involved is undertaken **solely for interoperability**
  — understanding on-the-wire and on-disk formats so an independent tool can
  produce/read compatible output — which is the purpose for which such analysis
  is generally permitted.
- openmdsign talks to the vendor PKCS#11 driver **only through the standard
  PKCS#11 (Cryptoki) C interface**. It does **not** bundle, copy, redistribute,
  or disassemble any proprietary library. You must supply the path to a driver
  that is already installed on your machine.
- openmdsign does **not** claim that its output is a legally **"qualified"**
  electronic signature. Whether a signature has any particular legal status
  depends on certificates, policies, and infrastructure outside this tool.

## Requirements

- macOS (developed and tested on Apple Silicon / arm64).
- A hardware PKCS#11 token and its **vendor PKCS#11 driver** (`.dylib`) installed
  locally. The driver architecture must match the `openmdsign` binary (an arm64
  binary needs an arm64 or universal driver).
- Build toolchain: Go (pinned via [`mise`](https://mise.jdx.dev/)) and Apple
  `clang` (needed because the PKCS#11 binding uses cgo).

## Install / build

```sh
# Go is pinned in mise.toml (Go 1.26.x).
mise install
mise exec -- go build -o bin/openmdsign ./cmd/openmdsign
# or, with mise shims on PATH:  go build -o bin/openmdsign ./cmd/openmdsign
```

> **Module path note:** the Go module is `github.com/branistedev/openmdsign`.
> It is trivially renameable — change the `module` line in `go.mod` and the
> import paths under `internal/` if you fork it elsewhere.

## Usage: `inspect`

`inspect` loads a PKCS#11 module and reports, read-only: the library info
(`C_GetInfo`), all slots and tokens, the supported mechanisms (highlighting the
signing-relevant ones), and public objects (certificates and public keys). Each
certificate is parsed (subject/issuer, validity, key usage, AIA/OCSP/CRL URLs,
certificate policies, and ETSI qualified-certificate `qcStatements`) and its DER
is exported.

```sh
# Read-only, no PIN — lists library, slots, mechanisms, certs, public keys.
openmdsign inspect --module /path/to/vendor/libeToken.dylib

# Machine-readable output:
openmdsign inspect --module /path/to/driver.dylib --json

# Optionally also list PRIVATE key objects (requires the token PIN).
# Prefer --pin-stdin so the PIN never enters your shell history:
printf '%s' "$PIN" | openmdsign inspect --module /path/to/driver.dylib --pin-stdin
```

Certificate DER files are written to `./inspect-out/cert-<CKA_ID>.der`
(override with `--out`).

### PIN safety (important)

If you supply a PIN, openmdsign performs **exactly one** login attempt and
**never retries**. Hardware tokens typically **lock after ~3 failed attempts**,
after which a PUK is needed. If login fails, openmdsign aborts and tells you not
to retry blindly — verify the correct PIN and the remaining-attempts count on
the physical device first. A PIN is never written to logs or error messages.

### Configuration

Precedence is **flags > config file > defaults**. openmdsign reads
`./openmdsign.toml` automatically if present, or `--config <path>`. See
[`configs/openmdsign.example.toml`](configs/openmdsign.example.toml) for all
keys (`module`, `slot`, `token_label`, `key_id`, `ca_chain`, `ocsp_url`,
`tsa_url`).

## Roadmap

- **Phase 0 (this release):** `inspect` recon harness — read-only token/cert
  discovery, plus documented steps to capture and dissect a reference signature.
- **Phase 1:** determine the exact signature profile (XAdES / CAdES / PAdES)
  from a reference signature (see [`docs/recon.md`](docs/recon.md)).
- **Phase 2:** implement signing behind the `internal/sign.Signer` interface for
  the confirmed profile(s), including timestamping (RFC 3161) and revocation
  material where required.
- **Later:** verification, batch signing, and packaging.

## Project layout

```
cmd/openmdsign/     CLI (cobra commands: root, inspect)
internal/token/     PKCS#11 access (miekg/pkcs11): slots, mechanisms, objects, single-attempt login
internal/x509util/  X.509 parsing/printing incl. AIA, CRLDP, policies, ETSI qcStatements
internal/sign/      Signer interface stub only (no implementation in Phase 0)
internal/config/    TOML config with flags>file>defaults precedence
configs/            Example configuration
docs/               recon.md (reference-signature procedure), decisions.md
```

## Recon and design notes

- [`docs/recon.md`](docs/recon.md) — vendor PKCS#11 module facts, the smoke-test
  results, and the exact commands to capture/dissect a reference signature.
- [`docs/decisions.md`](docs/decisions.md) — dependency choices and maintenance
  checks, the arm64/driver architecture constraint, the pluggable-`Signer`
  design, and the XAdES caveat.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
