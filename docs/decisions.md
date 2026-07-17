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

## XAdES / ASiC-E caveat

If the reference signature turns out to be **XAdES inside an ASiC-E container**
(mimetype `application/vnd.etsi.asice+zip`), do **not** hand-roll XML
canonicalization (C14N) and XAdES qualifying properties — it is a notorious
source of subtle, non-interoperable bugs. In that case stop and evaluate driving
the mature **EU DSS** library (Java, `eu.europa.esig.dss`) or an equivalent,
rather than reimplementing XAdES from scratch. The vendor stack already bundles
IAIK XAdES/CMS/TSP jars, a strong hint the profile may be XAdES and/or CAdES.
Record the actual profile in `docs/recon.md` once known.
