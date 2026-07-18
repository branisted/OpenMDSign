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
| Core/CLI | **P2a PAdES-B-T signer** | ✅ **done — VALID via msign.gov.md/#/verify/upload** |
| Core/CLI | P2b XAdES-T signer (EU DSS) | ✅ **done — VALID in MoldSign app (detached, XAdES-T, cert+TSA+timestamp shown)** |
| Core/CLI | P3 `verify` + trust anchors | ✅ done — our PAdES VALID; our XAdES chain-trusted (VALID with --check-revocation) |
| Core/CLI | P4 LTV / XAdES-C, `/DSS` store | ▫ todo (optional — long-term validation) |
| Core/CLI | ~~P5 packaging (brew, notarized dmg)~~ | ✗ dropped — GitHub-repo-only, bins only |
| Daemon | msign document signing in-browser | ✅ **works end-to-end (user-confirmed)** |
| Daemon | mpass auth (XAdES SHA-1 challenge) | ▫ todo — currently 501 stub; needs real challenge capture |
| Daemon | A protocol freeze (`PROTOCOL.md`) | ✅ done |
| Daemon | B skeleton: HTTPS loopback + 3 routes + CORS + `/certificates` | ✅ done, merged |
| Daemon | C wire signers + sync PIN/confirm gate | ✅ done, merged (PAdES/XAdES doc signing + native PIN/confirm; auth-challenge stubbed) |
| Daemon | D TLS trust gate (`localhost.cts.md`) | ✅ done — trusted self-signed leaf + `openmdsignd trust install/uninstall/status` |
| Daemon | ~~E launchd auto-start / installer~~ | ✗ dropped — run `openmdsignd serve` standalone on demand; no launchd. Just ship the bins + `trust install`. |

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
| 1 | `localhost.cts.md:18443` TLS trust model | `PROTOCOL.md §2` | ✅ **DECIDED (2026-07-18): trusted self-signed LEAF** — per-machine self-signed cert for CN/SAN=localhost.cts.md, added as a trusted SSL anchor in the login keychain via `openmdsignd trust install`. Loopback-only ⇒ minimal blast radius; no CA that can sign other names. DNS→127.0.0.1 already works. |
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

## Where signatures get validated (acceptance surfaces)
- **PAdES / PDF** → `https://msign.gov.md/#/verify/upload` (PDF-only web verifier).
- **XAdES / XML** → the **MoldSign desktop app** validation feature. It keys off the
  **`.xades` extension** (a `.xml` suffix is rejected); for **detached**, the original
  document must sit next to the `.xades` file so the `file:/<name>` reference resolves.
- `https://semnatura.md/certificate/verify` → only checks **certificate status** by
  IDNP/serial; it does **not** validate signature files.

## Non-negotiables (both tracks)
- PKCS#11 PIN: **exactly one** `C_Login`, never retried; never logged/serialized.
- No vendor binaries, STISC certs, or personal data in the repo.
- No "qualified signature" legal claim — technically-valid AdES only.
- Acceptance for any signer = round-trips as VALID through semnatura.md.
