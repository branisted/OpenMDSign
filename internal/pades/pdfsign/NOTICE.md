# Vendored fork of github.com/digitorus/pdfsign `sign` package

Source: `github.com/digitorus/pdfsign@v0.0.0-20260407063256-85ede6424a74`,
subpackage `sign/` (BSD-2-Clause, see `LICENSE`).

This is a **minimal fork**, copied verbatim except for the package clause
(`package sign` -> `package pdfsign`) and two patches in `pdfsignature.go`,
both required to match the MoldSign PAdES-B-T profile (`docs/profile-spec.md` §2)
which upstream cannot produce as-is:

1. **`/SubFilter`** — upstream hardcodes `/adbe.pkcs7.detached`; the profile
   requires `/ETSI.CAdES.detached`. The two names are both 19 bytes, so the
   signed `/ByteRange` offsets are identical; only the SubFilter name changes.
   There is no configuration knob upstream, hence the fork.

2. **Signed attributes** — upstream always injects the legacy Adobe
   `adbe-revocationInfoArchival` signed attribute (OID 1.2.840.113583.1.1.8,
   empty when no revocation data is fetched). The reference profile's SignerInfo
   carries exactly `contentType` + `messageDigest` + `signingCertificateV2`, so
   the extra attribute is removed.

Everything else — the incremental-update PDF writer, xref/trailer handling,
ESS `signingCertificateV2` construction (OID 1.2.840.113549.1.9.16.2.47), the
RFC 3161 `signatureTimeStampToken` unsigned attribute (OID
1.2.840.113549.1.9.16.2.14) and TSA client — is upstream's, unchanged.

Upstream dependencies (`digitorus/pkcs7`, `digitorus/pdf`, `digitorus/timestamp`,
`digitorus/pdfsign/revocation`, `digitorus/pdfsign/verify`, `mattetti/filebuffer`,
`golang.org/x/crypto`, `golang.org/x/text`) remain external module dependencies.

To re-sync with upstream: re-copy `sign/*.go`, re-apply the package rename and
the two `FORK PATCH` edits (search for `openmdsign FORK PATCH`).
