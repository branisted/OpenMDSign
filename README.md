# openmdsign

`openmdsign` is an open-source macOS tool for signing documents with a hardware
**PKCS#11** token (smartcard / USB crypto token), built for **interoperability**
with the electronic-signature ecosystem used in Moldova (MoldSign / STISC). It
ships two front-ends over one signing core:

- **`openmdsign`** — a scriptable CLI: inspect a token, sign a PDF or file, and
  verify signatures, entirely from the terminal.
- **`openmdsignd`** — a local HTTPS daemon that speaks the same browser⇄daemon
  protocol the official middleware uses, so the government web portals can drive
  your token through this tool instead.

Both produce standard AdES signatures that validate on the official verifiers:
**PAdES-B-T** for PDFs and **XAdES-T** for arbitrary files.

> **Status.** Document signing works end-to-end and is validated on real
> infrastructure (PAdES via the msign.gov.md verifier; XAdES in the MoldSign
> desktop app; msign document signing confirmed in-browser through the daemon).
> The mpass.gov.md **login** flow is implemented but its in-browser acceptance is
> not yet confirmed on hardware. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Legal / interoperability statement

- openmdsign is an **independent, unofficial** project. It is **not affiliated
  with, endorsed by, or connected to** any government authority, certification
  service provider, or the proprietary vendor middleware it interoperates with.
- Any reverse engineering involved is undertaken **solely for interoperability**.
- openmdsign talks to the vendor PKCS#11 driver **only through the standard
  PKCS#11 (Cryptoki) C interface**. It does **not** bundle, copy, redistribute,
  or disassemble any proprietary library, cert store, or binary. You supply the
  path to a driver already installed on your machine.
- openmdsign does **not** claim its output is a legally **"qualified"** electronic
  signature. Legal status depends on certificates, policies, and infrastructure
  outside this tool.

## Requirements

- macOS (developed and tested on Apple Silicon / arm64).
- A hardware PKCS#11 token and its **vendor PKCS#11 driver** (`.dylib`) installed
  locally, of matching architecture (an arm64 binary needs an arm64/universal driver).
- Toolchain, pinned via [`mise`](https://mise.jdx.dev/) (`mise.toml`):
  - **Go 1.26** + Apple `clang` (the PKCS#11 binding uses cgo) — for everything.
  - **Java 21 + Maven** — only for **XAdES** signing/verification, which delegates
    to a bundled [EU DSS](https://github.com/esig/dss) helper. PAdES is pure Go.

## Build

```sh
mise install            # provisions Go, Java, Maven at the pinned versions
make build              # -> bin/openmdsign, bin/openmdsignd
make jar                # -> java/dss-helper/target/dss-helper.jar (needed for XAdES)
make test               # go vet + unit tests
make release GOOS=darwin GOARCH=arm64   # -> dist/openmdsign-<ver>-darwin-arm64.tar.gz
```

The XAdES path needs the helper jar at runtime; point to it with `--dss-helper`
or `$OPENMDSIGN_DSS_HELPER` (default `java/dss-helper/target/dss-helper.jar`).

> The Go module is `github.com/branistedev/openmdsign`; rename the `module` line
> in `go.mod` and the `internal/` imports if you fork it elsewhere.

## CLI: `openmdsign`

### inspect — read-only token/cert discovery
```sh
openmdsign inspect --module /path/to/driver.dylib          # library, slots, mechanisms, certs
openmdsign inspect --module /path/to/driver.dylib --json
```

### sign — produce an AdES signature
PDF → **PAdES-B-T**; any other file → **XAdES-T** (detached by default). A PIN is
required; prefer `--pin-stdin` so it stays out of shell history.
```sh
# PAdES (PDF). --chain embeds the issuer chain (issuing CA + root) in the CMS.
printf '%s' "$PIN" | openmdsign sign --module /path/to/driver.dylib \
    --file contract.pdf --level t --chain moldsign-chain.pem --pin-stdin

# XAdES (any file), detached -> writes contract.docx.xades next to your file.
printf '%s' "$PIN" | openmdsign sign --module /path/to/driver.dylib \
    --file contract.docx --profile xades --level t \
    --dss-helper java/dss-helper/target/dss-helper.jar --pin-stdin
```
For detached XAdES, keep the signature (`<name>.xades`) next to the original —
the signature references `file:/<name>`, so verifiers need the original beside it.

### verify — validate a signature offline
Checks the cryptographic signature, the certificate chain against embedded STISC
trust anchors, and the RFC 3161 timestamp. No portal or vendor app required.
```sh
openmdsign verify --file contract.signed.pdf                 # PAdES
openmdsign verify --file contract.docx.xades --original contract.docx   # detached XAdES
openmdsign verify --file contract.signed.pdf --check-revocation --json  # + online OCSP/CRL
```

### sign-raw — crypto proof-of-life
Signs a SHA-256 digest on the token and verifies it against the certificate.

## Daemon: `openmdsignd`

`openmdsignd` serves the browser⇄daemon protocol on `https://localhost.cts.md:18443`
(a public name that resolves to `127.0.0.1`) so the government portals can drive
your token. Signing pops a **native confirmation dialog** naming the requesting
site and taking your PIN — no website can sign silently (strict CORS allowlist +
per-operation confirmation).

```sh
# One-time: create a per-machine self-signed leaf cert for localhost.cts.md and
# trust it in your login keychain (asks for your password once; TLS-only, loopback-only).
openmdsignd trust install
openmdsignd trust status            # -> trusted: yes

# Run on demand (foreground; stop with Ctrl-C). No background service is installed.
openmdsignd serve --module /path/to/driver.dylib \
    --chain moldsign-chain.pem \
    --dss-helper java/dss-helper/target/dss-helper.jar
```
Then open `msign.gov.md` in Chrome/Safari and sign as usual. Remove the trust
anchor any time with `openmdsignd trust uninstall`.

## PIN safety (important)

A PIN drives **exactly one** login attempt and is **never retried** — hardware
tokens typically **lock after ~3 failures** (PUK required to recover). On failure
openmdsign aborts and tells you not to retry blindly. A PIN is never written to
logs, errors, or any file.

## Configuration

Precedence is **flags > config file > defaults**. `./openmdsign.toml` is read
automatically if present (or `--config <path>`). See
[`configs/openmdsign.example.toml`](configs/openmdsign.example.toml) for all keys,
including the `[daemon]` table.

## Project layout

```
cmd/openmdsign/     CLI (inspect, sign-raw, sign, verify)
cmd/openmdsignd/    local HTTPS daemon (serve, trust)
internal/token/     PKCS#11 access + single-login crypto.Signer (one PIN attempt, no retry)
internal/sign/      Signer interface + pades/ (pure Go) and xades/ (EU DSS helper)
internal/verify/    offline PAdES/XAdES verification + embedded STISC trust anchors
internal/server/    daemon: routing, strict CORS, /certificates, signer + confirm gate, TLS trust
internal/x509util/  X.509 parsing incl. AIA, CRLDP, policies, ETSI qcStatements
java/dss-helper/    EU DSS (Java) helper for XAdES, two-step external signing
docs/               ROADMAP, PROTOCOL, profile-spec, decisions, recon
```

## Documentation

- [`docs/ROADMAP.md`](docs/ROADMAP.md) — status, progress, and what's left.
- [`docs/profile-spec.md`](docs/profile-spec.md) — exact PAdES/XAdES container structures.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the browser⇄daemon localhost contract.
- [`docs/decisions.md`](docs/decisions.md) — architecture & library decisions.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
