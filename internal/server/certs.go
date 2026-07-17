package server

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"path/filepath"

	"github.com/branistedev/openmdsign/internal/token"
)

// TokenCertificate is one raw certificate discovered on a PKCS#11 token, plus
// the placement metadata needed to build the PROTOCOL.md §4.1 shape. It is the
// hardware-agnostic currency between a CertProvider and the /certificates
// handler: the real token-backed provider and the test fake both speak it, so
// the handler needs no hardware.
type TokenCertificate struct {
	// DER is the raw certificate (CKA_VALUE of a CKO_CERTIFICATE object).
	DER []byte
	// CKAIDHex is the certificate's CKA_ID in hex — becomes certificateId.
	CKAIDHex string
	// Label is the CKA_LABEL of the certificate object.
	Label string
	// SlotIndex is the certificate's slot position; feeds providerId.
	SlotIndex int
	// PrivateKeyPresent reports whether a matching private key is present. On a
	// token this is inferred without a login (see tokenCertProvider).
	PrivateKeyPresent bool
}

// CertProvider enumerates the certificates available for signing WITHOUT a PIN
// or login (PROTOCOL.md §4.1: certificate objects are public objects). This is
// the seam that lets the /certificates route run against real hardware in
// production and against an injected fake in tests.
//
// Implementations:
//   - tokenCertProvider (this file) — the production path, backed by
//     internal/token; loads the vendor PKCS#11 module and reads public cert
//     objects. No C_Login, so no PIN ever touches this route.
//   - a test fake — returns a canned []TokenCertificate so httptest coverage
//     needs no token. See certs_test.go.
type CertProvider interface {
	// Certificates returns every certificate object visible without login. A
	// missing/absent token is NOT an error: return an empty slice so the route
	// answers 200 with an empty certificateModel list (PROTOCOL.md §4.1).
	Certificates(ctx context.Context) ([]TokenCertificate, error)
}

// tokenCertProvider is the production CertProvider backed by internal/token. It
// depends on the shared core through its exported API only (token.Load /
// (*Ctx).Inspect with no PIN) — it never reshapes the token layer.
type tokenCertProvider struct {
	modulePath string
}

// NewTokenCertProvider returns a CertProvider that enumerates public cert
// objects from the vendor PKCS#11 module at modulePath. No login is performed.
func NewTokenCertProvider(modulePath string) CertProvider {
	return &tokenCertProvider{modulePath: modulePath}
}

// Certificates loads the module, runs a read-only inspection (HasPIN=false, so
// EXACTLY zero logins), and maps every CKO_CERTIFICATE object to a
// TokenCertificate. privateKeyPresent is inferred from a public-key object with
// a matching CKA_ID, which is enumerable without a login (private-key objects
// usually are not). An absent/empty module path yields an empty list.
func (p *tokenCertProvider) Certificates(ctx context.Context) ([]TokenCertificate, error) {
	if p.modulePath == "" {
		// No module configured: behave like "no token" and return empty.
		return nil, nil
	}
	c, err := token.Load(p.modulePath)
	if err != nil {
		return nil, fmt.Errorf("load PKCS#11 module: %w", err)
	}
	defer c.Close()

	// HasPIN=false ⇒ no C_Login anywhere; only public objects are read.
	rep, err := c.Inspect(token.Options{})
	if err != nil {
		return nil, fmt.Errorf("inspect token: %w", err)
	}

	var out []TokenCertificate
	for slotIdx, slot := range rep.Slots {
		// Collect the CKA_IDs of public keys present in this slot; a matching
		// public key is our login-free proxy for "a key pair lives here".
		pubIDs := map[string]bool{}
		for _, o := range slot.Objects {
			if o.Class == "CKO_PUBLIC_KEY" && o.IDHex != "" {
				pubIDs[o.IDHex] = true
			}
		}
		for _, o := range slot.Objects {
			if len(o.CertDER) == 0 {
				continue
			}
			out = append(out, TokenCertificate{
				DER:               o.CertDER,
				CKAIDHex:          o.IDHex,
				Label:             o.Label,
				SlotIndex:         slotIdx,
				PrivateKeyPresent: o.IDHex != "" && pubIDs[o.IDHex],
			})
		}
	}
	return out, nil
}

// CertificateModel is the JSON object the page expects for each certificate
// (PROTOCOL.md §4.1). Field names and casing match the captured wire format
// exactly — do not rename.
type CertificateModel struct {
	CertificateID     string `json:"certificateId"`
	Label             string `json:"label"`
	ProviderID        string `json:"providerId"`
	Policy            string `json:"policy"`
	CertificateName   string `json:"certificateName"`
	SubjectDN         string `json:"subjectDN"`
	IssuerDN          string `json:"issuerDN"`
	Authority         bool   `json:"authority"`
	Trusted           bool   `json:"trusted"`
	Verified          int    `json:"verified"`
	PrivateKeyPresent bool   `json:"privateKeyPresent"`
	CertificateBase64 string `json:"certificateBase64"`
}

// certificatesResponse is the §4.1 envelope: {"certificateModel":[ ... ]}.
type certificatesResponse struct {
	CertificateModel []CertificateModel `json:"certificateModel"`
}

// providerID builds the PROTOCOL.md §4.1 providerId of the form
// `<pkcs11-module-basename>-<slotIndex>`. On Windows the vendor emitted
// `eToken.dll-0`; on macOS the module is a `.dylib`, so the basename carries the
// `.dylib` extension (e.g. `libeToken.dylib-0`). An empty module path yields a
// stable placeholder so the field is never blank.
func providerID(modulePath string, slotIndex int) string {
	base := filepath.Base(modulePath)
	if modulePath == "" || base == "." || base == "/" {
		base = "pkcs11"
	}
	return fmt.Sprintf("%s-%d", base, slotIndex)
}

// toCertificateModel maps a raw TokenCertificate to the §4.1 wire shape, parsing
// the DER for the DN / policy / authority fields. A cert that fails to parse is
// still surfaced with its raw fields so the page at least sees it.
func toCertificateModel(modulePath string, tc TokenCertificate) CertificateModel {
	m := CertificateModel{
		CertificateID:     tc.CKAIDHex,
		Label:             tc.Label,
		ProviderID:        providerID(modulePath, tc.SlotIndex),
		PrivateKeyPresent: tc.PrivateKeyPresent,
		CertificateBase64: base64.StdEncoding.EncodeToString(tc.DER),
		// verified: the capture showed 0. We do not run a chain/OCSP validation
		// in the skeleton, so we report the observed neutral value.
		Verified: 0,
		// trusted: the real trust decision (chain to mdtrustca + revocation) is
		// later work; the skeleton reports true to match the captured shape and
		// avoid a false "untrusted" flag on a genuine cert. Documented deviation.
		Trusted: true,
	}

	cert, err := x509.ParseCertificate(tc.DER)
	if err != nil {
		return m
	}
	m.SubjectDN = cert.Subject.String()
	m.IssuerDN = cert.Issuer.String()
	m.Authority = cert.IsCA
	if len(cert.PolicyIdentifiers) > 0 {
		m.Policy = cert.PolicyIdentifiers[0].String()
	} else if len(cert.Policies) > 0 {
		m.Policy = cert.Policies[0].String()
	}
	// certificateName in the capture read like "<name>(<policy oid>)". We build
	// a best-effort rendering from the subject CN + policy; the exact vendor
	// string is not fully specified. Documented as best-effort.
	name := cert.Subject.CommonName
	if name == "" {
		name = tc.Label
	}
	if m.Policy != "" {
		m.CertificateName = fmt.Sprintf("%s (%s)", name, m.Policy)
	} else {
		m.CertificateName = name
	}
	return m
}
