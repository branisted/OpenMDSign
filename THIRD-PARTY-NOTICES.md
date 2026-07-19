# Third-party notices

openmdsign itself is licensed under the **Apache License 2.0** (see [`LICENSE`](LICENSE)).
This file covers third-party components redistributed in **built release
artifacts** (`make release`), which are **not** all Apache-2.0.

The most important item is **EU DSS, which is LGPL-2.1** — see the dedicated
section below for the obligations that come with it.

---

## 1. EU DSS — LGPL-2.1 (bundled in `dss-helper.jar`)

`dss-helper.jar` is a shaded ("fat") jar built by `make jar`. It **embeds the
class files** of the European Commission's Digital Signature Service (DSS),
which is licensed under the **GNU Lesser General Public License, version 2.1**.

| | |
|---|---|
| Component | `eu.europa.ec.joinup.sd-dss:dss-*` and `specs-*`, version **6.4** |
| License | **LGPL-2.1** ([`licenses/LGPL-2.1.txt`](licenses/LGPL-2.1.txt)) |
| Upstream | https://github.com/esig/dss |
| Source for this version | https://github.com/esig/dss/releases/tag/6.4 |

Bundled DSS modules: `dss-alert`, `dss-crl-parser`, `dss-crl-parser-x509crl`,
`dss-detailed-report-jaxb`, `dss-diagnostic-jaxb`, `dss-document`,
`dss-enumerations`, `dss-i18n`, `dss-jaxb-common`, `dss-jaxb-parsers`,
`dss-model`, `dss-policy-jaxb`, `dss-service`, `dss-simple-certificate-report-jaxb`,
`dss-simple-report-jaxb`, `dss-spi`, `dss-utils`, `dss-utils-apache-commons`,
`dss-validation`, `dss-xades`, `dss-xml-common`, `dss-xml-utils`,
`specs-trusted-list`, `specs-trusted-list-v211`, `specs-validation-report`,
`specs-xades`, `specs-xmldsig`.

### Obligations when you redistribute a release artifact

**Written offer for source (LGPL-2.1 §6).** The complete corresponding source
for DSS 6.4 is publicly available at the release URL above. openmdsign applies
**no modifications** to DSS — it is consumed as an unmodified Maven artifact,
so upstream's published source *is* the corresponding source.

**Relinking (LGPL-2.1 §6).** Because the jar is shaded, DSS classes are copied
into `dss-helper.jar` rather than linked at runtime. To rebuild the helper
against a different version of DSS, change `<dss.version>` in
[`java/dss-helper/pom.xml`](java/dss-helper/pom.xml) and run `make jar`; the
helper's own source is in this repository under `java/dss-helper/`. This
satisfies the user's right to modify the library and relink.

**Reverse engineering for debugging is permitted** for the LGPL portions,
notwithstanding any contrary language elsewhere.

> **Note on separation.** The Go binaries (`openmdsign`, `openmdsignd`) do not
> link DSS. They invoke `dss-helper.jar` as a **separate process** over a
> command-line/stdio boundary. The Apache-2.0 Go code and the LGPL Java helper
> are therefore separate works; only the jar carries LGPL obligations.

---

## 2. Other components bundled in `dss-helper.jar`

| Component | Version | License |
|---|---|---|
| `org.bouncycastle:bcprov-jdk18on`, `bcpkix-jdk18on`, `bcutil-jdk18on` | 1.83 | Bouncy Castle License (MIT-style) |
| `org.apache.santuario:xmlsec` | 3.0.6 | Apache-2.0 |
| `org.apache.httpcomponents.client5:httpclient5` | 5.5.2 | Apache-2.0 |
| `org.apache.httpcomponents.core5:httpcore5`, `httpcore5-h2` | 5.3.6 | Apache-2.0 |
| `org.apache.commons:commons-lang3` | 3.20.0 | Apache-2.0 |
| `org.apache.commons:commons-collections4` | 4.5.0 | Apache-2.0 |
| `commons-io:commons-io` | 2.21.0 | Apache-2.0 |
| `commons-codec:commons-codec` | 1.18.0 | Apache-2.0 |
| `com.fasterxml.jackson.core:jackson-core`, `jackson-databind`, `jackson-annotations` | 2.18.2 | Apache-2.0 |
| `com.fasterxml.woodstox:woodstox-core` | 6.5.1 | Apache-2.0 |
| `org.codehaus.woodstox:stax2-api` | 4.2.1 | BSD-2-Clause |
| `org.glassfish.jaxb:jaxb-runtime`, `jaxb-core`, `txw2` | 3.0.2 | EDL-1.0 (BSD-3-Clause) |
| `jakarta.xml.bind:jakarta.xml.bind-api` | 3.0.1 | EDL-1.0 (BSD-3-Clause) |
| `com.sun.activation:jakarta.activation` | 2.0.1 | EDL-1.0 (BSD-3-Clause) |
| `com.sun.istack:istack-commons-runtime` | 4.0.1 | EDL-1.0 (BSD-3-Clause) |
| `org.slf4j:slf4j-api` | 2.0.17 | MIT |

Regenerate this list with:

```sh
cd java/dss-helper && mvn dependency:list -DincludeScope=runtime
```

---

## 3. Components compiled into the Go binaries

| Module | License |
|---|---|
| `github.com/digitorus/pdfsign` | BSD-2-Clause |
| `github.com/digitorus/timestamp` | BSD-2-Clause |
| `github.com/digitorus/pdf` | BSD-3-Clause |
| `github.com/digitorus/pkcs7` | MIT |
| `github.com/beevik/etree` | BSD-2-Clause |
| `github.com/miekg/pkcs11` | BSD-3-Clause |
| `github.com/BurntSushi/toml` | MIT |
| `github.com/mattetti/filebuffer` | MIT |
| `github.com/russellhaering/goxmldsig` | Apache-2.0 |
| `github.com/spf13/cobra` | Apache-2.0 |
| `golang.org/x/crypto`, `golang.org/x/text` | BSD-3-Clause |

### Vendored source

[`internal/pades/pdfsign/`](internal/pades/pdfsign/) is a **modified** minimal
fork of the `sign/` package of `github.com/digitorus/pdfsign` (BSD-2-Clause).
Upstream's license is retained at
[`internal/pades/pdfsign/LICENSE`](internal/pades/pdfsign/LICENSE), and the two
functional changes are documented in
[`internal/pades/pdfsign/NOTICE.md`](internal/pades/pdfsign/NOTICE.md).

---

## 4. Not redistributed

openmdsign does **not** bundle, copy, or redistribute any vendor PKCS#11 driver,
keystore, or proprietary middleware binary. Those are installed separately by
the user; see "Obtaining the PKCS#11 driver" in [`README.md`](README.md).

The embedded trust anchors in [`internal/verify/anchors/`](internal/verify/anchors/)
are **public** CA certificates fetched from public PKI distribution URLs, with
provenance and SHA-256 fingerprints documented in that directory's `README.md`.
The same applies to `moldsign-chain.pem` (issuing CA + root, both `CA:TRUE`).
