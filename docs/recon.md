# Recon notes

This document captures (1) established facts about the vendor PKCS#11 modules,
(2) the observed behavior of `openmdsign inspect` against each of them, and
(3) the exact procedure to capture and dissect a **reference signature** made by
the official vendor application, so we can determine the signature profile
(XAdES / CAdES / PAdES) before writing any signing code.

---

## 1. Vendor PKCS#11 module facts (established)

The proprietary vendor app is unpacked under `moldsign2412unbundled/` (this
directory is git-ignored and must never be committed, modified, or
redistributed). Its PKCS#11 drivers live in:

```
moldsign2412unbundled/STISC/MoldSign/native_lib/
```

Driver candidates listed in the vendor's `PKCS11.properties` / driver_lib config:

| Module                  | Exports `C_GetFunctionList` | Architectures             | In driver list |
|-------------------------|-----------------------------|---------------------------|----------------|
| `libcastle.1.0.0.dylib` | yes                         | universal x86_64 + arm64  | yes            |
| `libbit4xpki.dylib`     | yes                         | universal x86_64 + arm64  | yes            |
| `libeToken.dylib`       | yes                         | universal x86_64 + arm64  | yes            |
| `libacos5pkcs11.dylib`  | yes                         | x86_64 + **i386 only**    | no             |

Which module is "live" depends on the **physical token** plugged in, which is
why the module path is configuration, never hardcoded. `libacos5pkcs11.dylib`
lacks an arm64 slice and is not a listed driver, so an arm64 `openmdsign` binary
cannot load it (see `docs/decisions.md`).

The vendor Java stack bundles `iaik_xades`, `iaik_cms`, `iaik_tsp`, and iText
signing jars — a hint that the profile is likely XAdES and/or CAdES, possibly
PAdES for PDFs. **Unconfirmed** until a reference signature is dissected.

---

## 2. `openmdsign inspect` smoke-test results (2026-07-17, macOS arm64, no token plugged)

Command form:

```
./bin/openmdsign inspect --module moldsign2412unbundled/STISC/MoldSign/native_lib/<module>
```

All three real drivers loaded successfully and exited **0** with no token
present (graceful degradation), confirming cgo/`dlopen` works natively on arm64.
No PIN was ever passed.

| Module                  | C_GetInfo manufacturer / description        | Cryptoki | Lib ver | Slots reported (empty) |
|-------------------------|---------------------------------------------|----------|---------|------------------------|
| `libeToken.dylib`       | SafeNet, Inc. / "SafeNet eToken PKCS#11"    | 2.20     | 10.9    | 8 slots (0-7), `CKF_REMOVABLE_DEVICE`, `CKF_HW_SLOT` |
| `libcastle.1.0.0.dylib` | Feitian Technologies / "EnterSafe PKCS#11 Library." | 2.40 | 1.20 | 1 slot ("ES SLOT 1"), EnterSafe |
| `libbit4xpki.dylib`     | Bit4id / "bit4id PKCS#11"                    | 3.0      | 1.4     | 0 slots (prints "no slots" note) |

`libacos5pkcs11.dylib` fails to load on arm64 as expected; `inspect` prints a
`file` diagnostic showing it is `x86_64 + i386` only.

**Next step (requires hardware):** plug in the physical token, re-run `inspect`
(optionally with `--pin-stdin` to also list private keys), and record the token
label, mechanism list (especially whether `CKM_SHA256_RSA_PKCS` is present vs
only raw `CKM_RSA_PKCS`), and the certificate details (issuer chain, qcStatements,
AIA/OCSP/CRL URLs). Exported certs land in `./inspect-out/cert-<CKA_ID>.der`.

---

## 3. Capturing a reference signature with the official app

Goal: produce reference signatures over trivial inputs so we can reverse the
container format for interoperability.

### 3a. Create tiny test inputs

```sh
printf 'openmdsign reference test %s\n' "$(date -u +%FT%TZ)" > /tmp/ref.txt
# A minimal 1-page PDF (any small PDF works):
cp /path/to/any/small.pdf /tmp/ref.pdf
```

### 3b. Sign both with the official MoldSign application

- Launch the official app, sign `/tmp/ref.txt` and `/tmp/ref.pdf`.
- Note **where the output lands** (same folder as input, a chosen output dir, or
  a temp path). Record the exact output filenames and extensions.
- If the app offers signature-format options (e.g. "CAdES / XAdES / PAdES",
  "detached / enveloping / enveloped", "with timestamp"), record which defaults
  were used.

### 3c. Identify the container type

```sh
file <output>                      # first guess: Zip, PDF, PKCS7/DER, or XML
```

**ASiC-E (→ XAdES)** — a Zip whose first entry is an uncompressed `mimetype`:
```sh
unzip -l <output>                  # look for META-INF/signatures*.xml
unzip -p <output> mimetype; echo   # expect: application/vnd.etsi.asice+zip
```

**PAdES** — a PDF with an embedded signature dictionary:
```sh
grep -a -c ByteRange <output.pdf>  # >0 means an embedded PKCS#7 signature
grep -a -o '/SubFilter[^ ]*' <output.pdf>   # ETSI.CAdES.detached => PAdES-BES
```

**CAdES** — a standalone `.p7s` (detached) or `.p7m` (enveloping) DER/PEM blob:
```sh
file <output.p7s>                  # "data" / DER; confirm with openssl below
```

### 3d. Dissect

**CMS / CAdES (.p7s / .p7m):**
```sh
openssl pkcs7 -inform DER -in <f.p7s> -print -noout
openssl asn1parse -inform DER -in <f.p7s> -i          # full ASN.1 tree
openssl cms   -inform DER -in <f.p7s> -cmsout -print  # richer CMS view
# List certificates embedded in the CMS:
openssl pkcs7 -inform DER -in <f.p7s> -print_certs -noout
```

**PAdES (PDF):** extract the hex `/Contents` blob, then parse it as CMS.
```sh
# Extract the first /Contents<...> hex string into raw DER:
python3 - <<'PY'
import re
data = open('/tmp/ref.pdf','rb').read()
m = re.search(rb'/Contents\s*<([0-9A-Fa-f]+)>', data)
raw = bytes.fromhex(m.group(1).decode())
# PDF pads /Contents with trailing 00s to a fixed length; strip trailing zeros.
open('/tmp/ref_contents.der','wb').write(raw.rstrip(b'\x00'))
print('wrote', len(raw), 'bytes')
PY
openssl asn1parse -inform DER -in /tmp/ref_contents.der -i
openssl cms -inform DER -in /tmp/ref_contents.der -cmsout -print
```

**XAdES / ASiC-E (XML):**
```sh
unzip -o <output> -d /tmp/asice_ref
xmllint --format /tmp/asice_ref/META-INF/signatures*.xml | less
# Note: <ds:Signature>, <xades:SignedProperties>, <xades:SigningCertificateV2>,
#       <xades:SignaturePolicyIdentifier>, and any <xades:...Timestamp> elements.
```

### 3e. What to paste back (the deliverable of this recon)

For each reference signature, report:

1. **Container type**: CAdES (.p7s/.p7m) / PAdES (PDF) / XAdES (ASiC-E).
2. **Detached vs enveloping/enveloped** (does the container embed the data?).
3. **Digest and signature algorithms** (e.g. SHA-256, RSA PKCS#1 v1.5 vs PSS).
4. **Signed (authenticated) attribute OIDs present**, especially:
   - content-type `1.2.840.113549.1.9.3`
   - message-digest `1.2.840.113549.1.9.4`
   - signing-time `1.2.840.113549.1.9.5`
   - ESS signing-certificate-v2 `1.2.840.113549.1.9.16.2.47`
   - signature-policy-identifier `1.2.840.113549.1.9.16.2.15`
5. **Timestamp presence** — unsigned attr signature-time-stamp-token
   `1.2.840.113549.1.9.16.2.14` (RFC 3161 TST). Note the TSA URL if visible.
6. The **certificate chain** embedded (leaf + intermediates), and whether an OCSP
   response / CRL is stapled into the container (for -LT / -LTA levels).

With the above we can pick the profile and wire a concrete `internal/sign`
implementation (see the XAdES caveat in `docs/decisions.md`).
