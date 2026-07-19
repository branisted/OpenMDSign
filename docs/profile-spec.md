# MoldSign signature profile spec (from reference-sample dissection, 2026-07-18)

Derived by dissecting reference signatures produced by the official app across
all offered formats. **No personal data is reproduced here** (the samples embed
the signer's certificate, name, IDNP and local file paths; those live only in the
git-ignored `signed-samples/` and are never committed or echoed).

Two independent families, matching the vendor code:
- **Arbitrary files → standalone XAdES** (ETSI TS 101 903 v1.3.2). **Not ASiC-E.**
- **PDF → PAdES-B-T** (ETSI, CAdES-based CMS embedded in the PDF).

Both: RSA + SHA-256 throughout. Levels offered by the app: XAdES-BES / -T / -C,
and PAdES-T. Signature type: detached or embedded (enveloping) for XAdES; PAdES
is always embedded.

---

## 1. XAdES (arbitrary files)

Standalone XML whose root is `ds:Signature`. Namespaces:
- `ds` = `http://www.w3.org/2000/09/xmldsig#`
- `xades` = `http://uri.etsi.org/01903/v1.3.2#`
- EncapsulatedTimeStamp encoding attr = `http://uri.etsi.org/01903/v1.2.2#DER`

Algorithms (all levels):
- SignatureMethod: `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`
- DigestMethod (every digest): `http://www.w3.org/2001/04/xmlenc#sha256`
- CanonicalizationMethod:
  - **detached** → `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` (C14N 1.0, no comments)
  - **embedded** → same URI **`#WithComments`** (vendor quirk; detached does NOT use WithComments)

### SignedInfo — two References
1. **SignedProperties ref** — `Type="http://uri.etsi.org/01903#SignedProperties"`,
   `URI="#SignedProperties-<uuid>"`, SHA-256, no transforms.
2. **Signed-file ref** — SHA-256, no transforms:
   - **detached**: `URI="file:/<basename>"` (e.g. `file:/test.txt`). Digest is over
     the **raw file bytes**. The verifier must resolve a sibling file of that
     basename. No Transforms element.
   - **embedded**: `URI="#FileObject-<uuid>"` pointing to a trailing
     `<ds:Object Encoding="UTF-8" Id="FileObject-<uuid>">` whose text is the
     **base64** of the file bytes. There is **no base64 Transform** — the digest is
     the same-document reference (C14N of the Object element). (Confirmed: text
     files and PDFs are both base64-in-Object despite the `Encoding="UTF-8"` label.)

### KeyInfo
`ds:X509Data > ds:X509Certificate` — the **signer certificate only** (no chain).

### SignedProperties (referenced by ref #1)
- `SignedSignatureProperties`:
  - `SigningTime`
  - `SigningCertificate` (**XAdES v1 form, NOT SigningCertificateV2**) →
    `Cert { CertDigest{sha256, DigestValue}, IssuerSerial{X509IssuerName, X509SerialNumber} }`
- `SignedDataObjectProperties`:
  - `DataObjectFormat ObjectReference="#<signed-file-ref-id>"` with child
    `Description` and `MimeType`.
  - ⚠️ In the vendor output `Description` contains the signer's **full local file
    path** (personal data). **Our implementation must not do this** — set
    `Description` to the bare filename or make it empty/configurable.

### Level deltas (unsigned properties)
`xades:UnsignedProperties > xades:UnsignedSignatureProperties`:
- **XAdES-BES**: none (no UnsignedProperties element).
- **XAdES-T**: `SignatureTimeStamp { CanonicalizationMethod(c14n), EncapsulatedTimeStamp }`
  — an RFC 3161 token (DER, base64) over the C14N'd `ds:SignatureValue`.
  TSA: `http://tsp.pki.gov.md/moldsign2/`.
- **XAdES-C** (adds, on top of T):
  - `CompleteCertificateRefs > CertRefs > Cert×2` — the CA chain (issuing CA +
    root) by `CertDigest`(sha256) + `IssuerSerial`.
  - `CompleteRevocationRefs`:
    - `CRLRefs > CRLRef×2` → `http://pki.md/crl/mdqsign.crl`, `http://pki.md/crl/mdtrustca.crl`
      (each with DigestAlgAndValue + CRLIdentifier{Issuer, IssueTime, Number}).
    - `OCSPRefs > OCSPRef×1` → `http://mdqsign.ocsp.pki.md`
      (OCSPIdentifier{ResponderID/ByName, ProducedAt} + DigestAlgAndValue).
  - NB: XAdES-C is the legacy **references** form. Modern DSS baseline emits the
    **values** form (XAdES-LT). If a consumer strictly requires -C, that is a
    structural mismatch to resolve with DSS's legacy API.

### 1.1 mpass authentication XAdES-T — SHA-1 enveloping (interop-required)

The mpass.gov.md login flow (`POST /sign/data`, PROTOCOL.md §5/§6) is the **same
XAdES pipeline** with three deltas, dissected from the captured `auth.xades`:

- **SHA-1 everywhere** (interop-mandated by the government auth protocol; NOT a
  general default — documents stay SHA-256): SignatureMethod `rsa-sha1`
  (`http://www.w3.org/2000/09/xmldsig#rsa-sha1`), every DigestMethod `sha1`
  (`http://www.w3.org/2000/09/xmldsig#sha1`) — SignedProperties ref, file ref,
  and `SigningCertificate/CertDigest`.
- **Enveloping**: `data` is a ~20-byte SHA-1 pre-hash challenge, base64-wrapped
  into a trailing `<ds:Object … Id="FileObject-…">` referenced by
  `URI="#FileObject-…"`. C14N of SignedInfo is `…#WithComments` (as for document
  enveloping).
- Same as document XAdES otherwise: `SigningCertificate` v1 (not V2),
  `SigningTime`, `SignedDataObjectProperties/DataObjectFormat`, and **-T**
  `SignatureTimeStamp/EncapsulatedTimeStamp`. The **timestamp request digest stays
  SHA-256** (independent of the signature digest; MDQTSA rejects SHA-1 and SHA-512
  requests) and the timestamped SignatureValue is canonicalized with plain C14N.

**Daemon routing heuristic** (`internal/server/tokensigner.go`, driven by
`signFormat`+`contentType`, NEVER the request `algorithm` hint): `XAdES-T` +
`contentType:"Text"` + `data ≤ 64 bytes` + not a `%PDF-` header ⇒ the mpass auth
challenge → XAdES-T **enveloping SHA-1**. Any larger/PDF `XAdES-T` payload ⇒
document XAdES-T **detached SHA-256**. The confirmation dialog is flagged
`IsAuth` so it tells the user this authorizes a LOGIN to the requesting Origin.

**Known divergences from the vendor `auth.xades`** (our signer delegates to EU
DSS; the vendor rolled its own XAdES). Semantically all central items match
(algorithms, C14N, SigningCertificate v1, SignatureTimeStamp), but DSS's
enveloping mode differs in reference construction — flagged here because a real
mpass round-trip (hardware-gated) is the only way to confirm acceptance:

- **File reference transform** (semantic): DSS adds a `base64` `<ds:Transform>` so
  the digest is over the decoded raw bytes; the vendor uses **no transform** (the
  digest is SHA-1 of the C14N'd `ds:Object` element). Different digest inputs.
- **SignedProperties reference transform** (semantic-ish): DSS adds an `exc-c14n`
  transform; the vendor reference carries none.
- **`ds:Object` `Encoding="UTF-8"`** (cosmetic): present in the vendor output,
  absent from DSS's enveloping object.
- **Reference `Id` naming** (cosmetic): DSS emits `r-id-…`; the vendor uses
  `SignedProperties-Reference-…` / `SignedFile-Reference-…`.
- **`DataObjectFormat/Description`** (intentional): the vendor leaks the signer's
  local file path here; we **omit Description entirely** (anti-leak, by design).

---

## 2. PAdES (PDF)

- Signature dict: `/Filter /Adobe.PPKLite`, `/SubFilter /ETSI.CAdES.detached`.
- Single `/ByteRange` covering the whole document; CMS in `/Contents`.
- `/DSS` Document Security Store present (LTV validation material: certs/OCSP/CRL).
- No `/DocTimeStamp` object → this is PAdES-**B-T**, not LTA (the timestamp lives
  inside the CMS, not as a separate document timestamp).

### CMS (SignedData) — SHA-256, sha256WithRSAEncryption
Signer `SignerInfo`:
- **Signed attributes**: `contentType` (pkcs7-data), `messageDigest`,
  **`signingCertificateV2`** (ESS, OID 1.2.840.113549.1.9.16.2.47).
  No `signingTime` signed attr, no signature-policy (not EPES).
- **Unsigned attributes**: `signatureTimeStampToken`
  (OID 1.2.840.113549.1.9.16.2.14) — a full RFC 3161 token (`id-smime-ct-TSTInfo`)
  from `http://tsp.pki.gov.md/moldsign2/`. The TSA's own SignerInfo carries
  `signingTime` + `signingCertificate`.
- Embedded certificates: signer chain **and** TSA chain.

Note the asymmetry: XAdES uses the old `SigningCertificate`; PAdES CMS uses
`signingCertificateV2`.

---

## 3. Implementation mapping

| Target | Library | Token handling |
|---|---|---|
| PAdES-B-T (PDF) | `github.com/digitorus/pdfsign` + `digitorus/timestamp` (pure Go) | Go `crypto.Signer` via crypto11 — token stays in Go, no JVM |
| XAdES-BES/T/C (files) | EU DSS (Java) helper | **Two-step external signing**: DSS returns data-to-be-sign; Go signs on-token; DSS assembles. PIN never leaves Go. |

### TSA verification (2026-07-18)

The TSA `http://tsp.pki.gov.md/moldsign2/` was probed with a standard RFC 3161
SHA-256 query (`openssl ts -query`): **HTTP 200, `Status: Granted`**,
`application/timestamp-reply`, signed by **`CN=MDQTSA`**, policy OID
`1.2.498.3.32.5`, accuracy 60s. **Unauthenticated, plain HTTP** — no credentials
needed for the `-T` path at runtime.

**Acceptance for every target:** round-trips as VALID through semnatura.md.