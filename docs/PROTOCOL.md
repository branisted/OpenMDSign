# PROTOCOL.md — the browser ⇄ MoldSign Server localhost contract

> **Status: FROZEN (v1) — 2026-07-18.** Reverse-engineered from live captures on a
> Windows 10 host (`DESKTOP-L31D4KK`) running the official **MoldSign Server 2.4.12**
> against `msign.gov.md` (document sign) and `mpass.gov.md` (authentication).
> Source artifacts: `scripts/recon-windows.ps1` output + `sign.har` / `login.har`
> (kept out of the repo — they embed a real qualified certificate and personal
> data). Do not edit without a fresh capture.

The official server is a cross-platform **Java** app (`ClientCardServer-2.0.jar`,
Grizzly HTTP + Jersey JAX-RS). The protocol below is emitted by that jar and is
therefore **identical on Windows and macOS** — this spec drives both builds.

---

## 1. Process & listeners

```
MoldSignServer.exe  -jar ...\lib\ClientCardServer-2.0.jar     (pid owns both ports)
```
Binds **loopback only** — two listeners:

| URL                        | Used by page? | Notes                                   |
|----------------------------|---------------|-----------------------------------------|
| `http://127.0.0.1:18480`   | no (in caps)  | plain HTTP; answered probes, page never used it |
| `https://127.0.0.1:18443`  | **yes**       | the live channel; all flows go here     |

Discovery is **not** a port scan and **not** a native-messaging host (registry had
none referencing MoldSign). It is a **fixed hostname + fixed port**.

---

## 2. Transport, discovery & TLS  — the load-bearing finding

The page connects to a **fixed absolute URL**:

```
https://localhost.cts.md:18443
```

`localhost.cts.md` is a **public DNS name that resolves to `127.0.0.1`**. The daemon
serves TLS on `:18443` with a **real, publicly-trusted DV certificate**:

```
Subject : CN=localhost.cts.md
Issuer  : CN=Certum DV TLS G2 R39 CA, O=Asseco Data Systems S.A., C=PL
Valid   : ... to 2027-02-16
```

So the browser makes an ordinary, fully-trusted `https://` request that happens to
land on loopback — **no local CA is installed** (the Windows trust store had no
MoldSign/localhost anchor). The cert + private key ship inside the app bundle.

> ### ⛔ STOP / decide — this is the hardest interop gate for `openmdsignd`
> The government pages are hardcoded to `https://localhost.cts.md:18443`. To be
> detected *identically*, our daemon must answer **on that exact name with a cert
> the browser trusts**. We cannot get Certum to reissue `localhost.cts.md` to us.
> Options, in order of fidelity vs. cleanliness:
> 1. **Reuse the vendor's shipped cert+key** — highest fidelity, but redistributing
>    a third party's TLS key is legally/ethically out of bounds. Rejected.
> 2. **Local trust anchor** — generate our own cert for `localhost.cts.md`, install
>    a one-off root into the user's trust store at setup (the model the agent brief
>    anticipated). Works, but requires `localhost.cts.md → 127.0.0.1` resolution
>    (public DNS already provides it) and a trust-store write.
> 3. **Ask whether the page will accept a different host/port** — not viable; the
>    origin/URL is fixed by the government front-end, out of our control.
> Recommendation: **option 2**. Record the DNS dependency (`localhost.cts.md` must
> resolve to loopback) and the trust-store provisioning step as install-time work.

---

## 3. Origin / CORS handling

Every response carries:

```
Access-Control-Allow-Origin:   <the caller's Origin, echoed>
Access-Control-Allow-Methods:  GET, POST, OPTIONS
Access-Control-Allow-Headers:  Origin, x-requested-with, content-type, accept, error, Location
Access-Control-Expose-Headers: Origin, x-requested-with, content-type, accept, error, Location
Access-Control-Max-Age:        3600
```

Preflight `OPTIONS` → `200`. Observed origins that were accepted and echoed:
`https://msign.gov.md` (sign) and `https://mpass.gov.md` (auth).

> **Security note / unconfirmed:** with only two samples we cannot tell whether the
> official daemon restricts `Allow-Origin` to a government allowlist or **reflects
> any Origin**. If it reflects unconditionally, *any* website could drive the token
> — a signing-oracle risk. Re-probe with a non-gov Origin to settle this. Our
> reimplementation **must enforce a strict allowlist** regardless (brief requirement).

---

## 4. Message flows

Both document-sign and authentication use the **same three-call REST sequence**.
JSON in, JSON out.

### 4.1 Enumerate certificates
```
GET /certificates?private_only=true
→ 200  application/json
{"certificateModel":[{
   "certificateId":"379ee7b7446a43c3e125eb2a139c7bcbb0d9ab1e",
   "label":"Nume Prenume...", "providerId":"eToken.dll-0",
   "policy":"1.2.498.3.32.1.1", "certificateName":"...(1.2.498.3.32.1.1)",
   "subjectDN":"C=MD,...,CN=Nume Prenume",
   "issuerDN":"...CN=MDQSign,...",
   "authority":false, "trusted":true, "verified":0,
   "privateKeyPresent":true, "certificateBase64":"MIIH..."
}]}
```
`providerId` = `<pkcs11-module>.dll-<slotIndex>` (here a SafeNet **eToken**).

### 4.2 Submit a signing job
```
POST /sign/data           content-type: application/json
{
  "algorithm":     "SHA-1",             // client hint — see §5 caveat
  "certificate":   { ...the chosen certificateModel object, verbatim... },
  "signatureType": "Embedded",
  "signFormat":    "PAdES-T" | "XAdES-T",
  "contentType":   "Pdf" | "Text",
  "data":          "<base64>"           // full document (PDF) OR pre-hashed challenge
}
→ 201 Created   Content-Length: 0
  Location: https://localhost.cts.md:18443/sign/data/PKCS11/<uuid>/<format>
```
The **PIN prompt, user confirmation and token signature happen synchronously**
inside this call — the `201` + `Location` come back only once the signed artifact
is ready. `<format>` in the Location is `pdf` (PAdES) or `XAdES`.

### 4.3 Fetch the result
```
GET /sign/data/PKCS11/<uuid>/<format>
→ 200  application/json
{"base64File":"<base64 of the finished signed container>"}
```
The page then posts `base64File` onward to the msign/mpass back-end (the outer
`ReturnUrl`/`RelayState` flow, out of scope here).

---

## 5. The two signature profiles (dissected from the captured outputs)

### Document signing — `signFormat: PAdES-T`  (msign.gov.md, a PDF)
- Output: a **PDF**, one signature, `/SubFilter /ETSI.CAdES.detached`.
- CMS digest **SHA-256** (`sha256` + `sha256WithRSAEncryption`).
- Signed attrs: contentType, messageDigest, **signingCertificateV2**
  (`1.2.840.113549.1.9.16.2.47`).
- **-T**: unsigned attr **`id-smime-aa-timeStampToken`** (RFC 3161) embedded.
- Full chain embedded: leaf → `MDQSign` → `mdtrustca` (self-signed root).

### Authentication — `signFormat: XAdES-T`  (mpass.gov.md, a challenge)
- Output: a **standalone `<ds:Signature>` XML** — **NOT** an ASiC-E zip.
  *(Resolves the open packaging question in `docs/decisions.md`.)*
- SignatureMethod **`rsa-sha1`**, DigestMethod **`sha1`**, C14N
  `xml-c14n-20010315#WithComments`.
- `xades:SignedProperties` → **SigningCertificate** (v1, *not* V2) + `SigningTime`
  (`2026-07-18T01:02:10+03:00`). No `SignaturePolicyIdentifier`.
- **-T**: `UnsignedProperties` → `SignatureTimeStamp` / `EncapsulatedTimeStamp`
  (RFC 3161). TSA = **MDQTSA** (pki.md), TST policy `1.2.498.3.32.5`, TST hash sha256.
- `data` sent was a 20-byte value (a SHA-1 digest of the mpass challenge),
  `contentType: Text`.

> **CAVEAT — do not trust the request `algorithm` field.** Both requests carried
> `"algorithm":"SHA-1"`, yet the **PAdES output is SHA-256** while the **XAdES
> output is SHA-1**. The field appears to describe how the *page* hashed `data`,
> not the container's internal digest. Drive the container digest from `signFormat`
> + profile rules, not from `algorithm`.

---

## 6. Corrections this capture forces on earlier docs
- **Auth is not a distinct challenge-response API.** It is the same `/sign/data`
  endpoint; only `Origin`, `signFormat` (XAdES-T) and `contentType` (Text) differ,
  with `data` = the pre-hashed challenge.
- **XAdES packaging = standalone `.xml`**, not ASiC-E. (`decisions.md` open item.)
- **XAdES digest = SHA-1** in the observed auth flow — contradicts the SHA-256 guess
  from static string analysis. (PAdES = SHA-256.) The static `sha256` strings may
  belong to a different XAdES path; only the mpass auth flow was captured.
- **Both profiles are -T** (timestamped) — consistent with the hybrid signer plan.

---

## 7. Implications for `openmdsignd` (feed Phase B)
- **Transport:** HTTPS on loopback, must answer for `localhost.cts.md:18443`
  (see §2 STOP gate) — plus optionally the `:18480` HTTP listener.
- **Router:** three routes — `GET /certificates`, `POST /sign/data`,
  `GET /sign/data/PKCS11/{uuid}/{format}` — Grizzly-compatible CORS headers per §3.
- **Signer:** PAdES-T (SHA-256, pure-Go path already chosen) and XAdES-T
  (standalone .xml, SHA-1, via EU DSS per the hybrid decision).
- **Token:** provider string `<module>.dll-<slot>`; live token here is a SafeNet
  eToken; all Windows vendor PKCS#11 DLLs are **x86 (32-bit)** → a Windows daemon
  loading them must be a **386 build** (or ship 64-bit vendor drivers).
- **Confirmation gate:** the synchronous `201` is exactly where our native PIN +
  per-operation confirmation dialog belongs.

---

## 8. Still to confirm (does not block Phase B start)
1. CORS allowlist scope — reflect-any vs gov-allowlist (§3). Re-probe with a
   non-gov Origin.
2. A **document XAdES** sample (msign signing a non-PDF) to see whether document
   XAdES uses SHA-256 while auth XAdES uses SHA-1.
3. Error/negative paths: no token present, user cancels, wrong PIN — response
   shapes the page expects.
4. Exact `localhost.cts.md` DNS record (public A → 127.0.0.1) and whether the
   installer also writes a hosts entry as a fallback.
