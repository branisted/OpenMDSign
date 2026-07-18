# Embedded STISC trust anchors

These PEM files are the **public** certificate-authority certificates of the
Moldovan PKI operated by STISC (Serviciul Tehnologia Informaţiei şi Securitate
Cibernetică). They are embedded via `go:embed` (see `anchors.go`) and used by
`openmdsign verify` to build and validate certificate chains for
MoldSign-family PAdES/XAdES signatures **offline**.

## Provenance & policy

Every certificate here was fetched from a **public** PKI distribution URL — the
same endpoints any relying party uses to obtain the CA chain. **None** of these
come from the proprietary vendor keystore (`trusted.jks` /
`moldsign2412unbundled`), and none contain personal data: they are CA certs, not
end-entity certificates.

Re-verify any file with:

```sh
openssl x509 -in <file>.pem -noout -fingerprint -sha256 -subject -issuer
```

## Included anchors

| File | Role | Source URL | SHA-256 fingerprint |
|---|---|---|---|
| `mdtrustrootca.pem` | Root (self-signed, 2020) | `http://www.pki.sis.md/cert/mdtrustrootca.cer` | `EB:8A:03:21:9C:32:17:FB:9C:03:87:13:74:5F:96:21:0C:20:B8:29:40:38:92:A0:77:4B:07:08:3E:AF:04:E9` |
| `mdtrustca.pem` | Root (self-signed, 2025) — current signing hierarchy | `http://pki.md/cer/mdtrustca.cer` | `21:1A:8A:9C:C9:2D:E6:91:6B:AB:20:24:FC:EA:41:08:E7:2D:4A:CF:CA:0F:B8:ED:D2:94:B9:98:E4:E9:9C:06` |
| `mdqsign.pem` | Issuing CA (leaf CA, issued by `mdtrustca`) | `http://pki.md/cert/mdqsign.crt` | `BA:55:D9:4B:F9:1C:0E:D0:32:DC:2C:DD:EE:ED:DF:70:81:0F:F6:41:F5:8C:50:E7:DF:F2:E1:A1:FF:A0:67:BF` |

### Subjects / issuers

- **mdtrustrootca** — `CN=mdtrustrootca, OU=RootCA, O=SIS RM 1006601000439, L=Chișinău, ST=Republica Moldova, C=MD` (self-signed). A distinct, older root; not part of the 2025 signing chain but retained as a public anchor for older material.
- **mdtrustca** — `CN=mdtrustca, O=IP Serviciul Tehnologia Informației şi Securitate Cibernetică, organizationIdentifier=NTRMD-1003600096694, L=Chișinău, C=MD` (self-signed root, valid 2025–2045). This is the trust anchor for the **current** signing hierarchy.
- **MDQSign** — `CN=MDQSign, O=IP Serviciul Tehnologia Informației şi Securitate Cibernetică, organizationIdentifier=NTRMD-1003600096694, L=Chișinău, C=MD`, **issued by `mdtrustca`** (valid 2025–2035). This is the intermediate/issuing CA that signs qualified end-entity certificates. The signing leaf on the token chains `leaf → MDQSign → mdtrustca`. The TSA `MDQTSA` chains under `mdtrustca` as well.

`Pools()` in `anchors.go` treats the two self-signed certs (`mdtrustca`,
`mdtrustrootca`) as x509 verification **roots** and `MDQSign` as an
**intermediate** (it is also seeded because a XAdES signature embeds only the
leaf, so the issuing CA must be supplied from here to complete the path).

## URLs that were probed but not reachable / not bundled

The following were probed to try to also bundle a dedicated TSA CA and the
legacy roots, but returned nothing (HTTP failure / 404) at the guessed public
paths, so they are **not** included:

- `http://pki.md/cert/mdqtsa.crt`, `http://pki.md/cer/mdqtsa.cer`,
  `http://www.pki.sis.md/cert/mdtsa.cer` — no dedicated TSA-CA cert found. Not
  needed in practice: `MDQTSA` chains under `mdtrustca` (bundled above), and the
  RFC 3161 timestamp token embeds the TSA certificate chain anyway.
- Legacy roots `RootCA SIS 2` / `eMoldova` — no public download URL located.
  Not part of the current MoldSign signing hierarchy.

The three bundled anchors (`mdtrustrootca` + `mdtrustca` + `mdqsign`) cover the
current MoldSign signing hierarchy (signer leaf, issuing CA, root) and the
`MDQTSA` timestamp path.
