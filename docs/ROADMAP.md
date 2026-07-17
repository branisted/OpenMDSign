# OpenMDSign — unified roadmap (single source of truth)

One project, **one core, two front-ends.** This file is the single place both the
CLI and the daemon workstreams are planned and tracked from. Updated as phases land.

```
                         ┌───────────────────────────┐
   cmd/openmdsign  ─────▶│                           │
   (CLI front-end)       │   SHARED CORE (libs)      │
                         │  internal/token           │◀── PKCS#11, single-login
   cmd/openmdsignd ─────▶│  internal/sign/{pades,    │    crypto.Signer (one PIN try)
   (daemon front-end)    │    xades}                 │
                         │  internal/x509util        │
                         │  internal/verify (TODO)   │
                         └───────────────────────────┘
```

Both front-ends call the **same** signers and the **same** token layer. The daemon
is not a separate project — it is a second consumer of the core.

---

## Status at a glance

| Track | Phase | State |
|---|---|---|
| Core/CLI | P0 `inspect` recon | ✅ done, hardware-validated |
| Core/CLI | P1 `sign-raw` proof-of-life | ✅ done, hardware-validated |
| Core/CLI | **P2a PAdES-B-T signer** | ✅ **done — semnatura.md returns VALID** |
| Core/CLI | P2b XAdES-T signer (EU DSS) | ✅ **done — builds; sw-key integration PASS; awaiting real-token semnatura.md check** |
| Core/CLI | P3 `verify` + trust anchors | ▫ todo |
| Core/CLI | P4 LTV / XAdES-C, `/DSS` store | ▫ todo (optional) |
| Core/CLI | P5 packaging (brew, notarized dmg) | ▫ todo |
| Daemon | A protocol freeze (`PROTOCOL.md`) | ✅ done |
| Daemon | B skeleton: HTTPS loopback + 3 routes + CORS + `/certificates` | ✅ done, merged |
| Daemon | C wire signers + sync PIN/confirm gate | ⏳ **now unblocked (both signers exist)** |
| Daemon | D TLS trust gate (`localhost.cts.md`) | ▫ todo — has a STOP decision |
| Daemon | E install/packaging (DNS/hosts, launchd) | ▫ todo |

---

## Critical path & sequencing

1. **P2b (XAdES-T signer)** is the linchpin — the daemon's sign route (Phase C)
   needs both signers. Do it next.
2. Daemon **Phase B** (transport + routing + cert enumeration) is independent of the
   signers and can proceed in parallel with P2b.
3. Daemon **Phase C** joins them: once P2b lands and Phase B stands, wire the signers
   behind `POST /sign/data` with the synchronous PIN + per-operation confirmation.
4. **Phase D** (TLS trust) and **P3 verify** can follow in either order.

### XAdES has TWO digest variants — the signer must be parameterized
- **Document** XAdES-T (from sample dissection): **SHA-256**, detached or enveloping.
- **Auth** XAdES-T (from `PROTOCOL.md`, mpass.gov.md): **SHA-1**, over a pre-hashed
  20-byte challenge, `contentType: Text`.
Do **not** read the digest from the request's `algorithm` field (it lied — said
SHA-1 on a PDF job that emitted SHA-256). Drive digest from `signFormat` + profile.

---

## Open STOP decisions (human-owned)

| # | Decision | Where | Default lean |
|---|---|---|---|
| 1 | `localhost.cts.md:18443` TLS trust model | `PROTOCOL.md §2` | Option 2 — ship our own cert for `localhost.cts.md`, install a one-off local root at setup |
| 2 | CORS allowlist scope (reflect-any vs gov allowlist) | `PROTOCOL.md §3` | Strict gov allowlist regardless of vendor behavior |
| 3 | XAdES-C legacy *references* vs DSS baseline-LT *values* | `profile-spec.md §1` | Target T first; only do -C if a consumer demands the legacy form |

---

## File-ownership boundaries (avoid cross-track churn)

- **Core (shared — coordinate before reshaping):** `internal/token`,
  `internal/sign/sign.go` (Signer interface), `internal/x509util`, `go.mod`.
- **CLI track:** `cmd/openmdsign`, `internal/sign/pades`, `internal/sign/xades`,
  `internal/verify`.
- **Daemon track:** `cmd/openmdsignd`, `internal/server/*`, daemon TLS/trust code.
- **Docs:** `profile-spec.md` (crypto profiles), `PROTOCOL.md` (browser⇄daemon),
  `decisions.md` (rationale), this file (plan/status).

---

## Reference docs
- `docs/profile-spec.md` — PAdES/XAdES container structure (from real samples).
- `docs/PROTOCOL.md` — the localhost browser⇄daemon REST contract.
- `docs/decisions.md` — architecture & library decisions with rationale.
- `docs/recon.md` — token/PKCS#11 recon + reference-capture procedure.

## Non-negotiables (both tracks)
- PKCS#11 PIN: **exactly one** `C_Login`, never retried; never logged/serialized.
- No vendor binaries, STISC certs, or personal data in the repo.
- No "qualified signature" legal claim — technically-valid AdES only.
- Acceptance for any signer = round-trips as VALID through semnatura.md.
