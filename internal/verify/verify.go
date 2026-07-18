// Package verify implements offline verification of the AdES signatures the
// project (and the MoldSign vendor) produces: PAdES-B-T (embedded CMS in a PDF)
// and standalone XAdES. Certificate chains are validated against the public
// STISC trust anchors embedded in internal/verify/anchors.
//
// PAdES is verified in pure Go (github.com/digitorus/pkcs7 for the CMS,
// github.com/digitorus/pdf for the ByteRange, github.com/digitorus/timestamp
// for the RFC 3161 token). XAdES is delegated to the EU DSS Java helper, which
// this package seeds with the same embedded anchors so DSS returns a real
// indication instead of NO_CERTIFICATE_CHAIN_FOUND.
package verify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/branistedev/openmdsign/internal/verify/anchors"
)

// Overall is the top-level verdict.
type Overall string

const (
	// Valid: the signature is cryptographically valid and the certificate
	// chain terminates at an embedded (trusted) STISC anchor.
	Valid Overall = "VALID"
	// Invalid: the signature does not verify (bad crypto, tampered content,
	// or a definitively rejected chain).
	Invalid Overall = "INVALID"
	// Indeterminate: verification could not be completed to a definitive
	// answer (e.g. no revocation data offline, or a DSS INDETERMINATE result).
	Indeterminate Overall = "INDETERMINATE"
)

// Result is the machine- and human-friendly verification outcome.
type Result struct {
	Profile       string         `json:"profile"` // "pades" | "xades"
	Overall       Overall        `json:"overall"`
	Reason        string         `json:"reason,omitempty"`
	Signer        SignerInfo     `json:"signer"`
	Timestamp     *TimestampInfo `json:"timestamp,omitempty"`
	Chain         ChainInfo      `json:"chain"`
	Indication    string         `json:"indication,omitempty"`     // DSS (XAdES)
	SubIndication string         `json:"sub_indication,omitempty"` // DSS (XAdES)
	Warnings      []string       `json:"warnings,omitempty"`
}

// SignerInfo describes the signing certificate and the signature over it.
type SignerInfo struct {
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	IDNP           string `json:"idnp,omitempty"` // subject serialNumber (personal number) if present
	SigningTime    string `json:"signing_time,omitempty"`
	SignatureValid *bool  `json:"signature_valid,omitempty"` // CMS crypto validity (PAdES)
}

// TimestampInfo describes an RFC 3161 signature timestamp.
type TimestampInfo struct {
	Time          string `json:"time"`
	TSA           string `json:"tsa,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	Valid         *bool  `json:"valid,omitempty"`
}

// ChainInfo reports the certificate-chain trust decision.
type ChainInfo struct {
	Status string `json:"status"`           // "trusted" | "untrusted" | "indeterminate"
	Anchor string `json:"anchor,omitempty"` // subject of the anchor the chain reached
	Detail string `json:"detail,omitempty"`
}

// Options configures a verification run.
type Options struct {
	// Profile is "auto", "pades", or "xades".
	Profile string
	// OriginalPath is the detached original document (XAdES detached).
	OriginalPath string
	// CheckRevocation enables online OCSP/CRL checks (needs network).
	CheckRevocation bool
	// ExtraAnchorsPEM is an optional additional PEM bundle of trust anchors.
	ExtraAnchorsPEM []byte
	// JavaPath and JarPath locate the EU DSS helper (XAdES only).
	JavaPath string
	JarPath  string
	// FilePath is the path of the signed file (used to resolve a sibling
	// detached original when OriginalPath is empty).
	FilePath string
}

// Run verifies the signed file at opts.FilePath and returns a Result. It
// autodetects (or applies the requested) profile and dispatches to the PAdES or
// XAdES verifier. Errors returned here are operational (unreadable file,
// undetectable profile, helper failure); a completed verification with a
// negative verdict is a *Result with Overall != Valid, not an error.
func Run(ctx context.Context, opts Options) (*Result, error) {
	data, err := os.ReadFile(opts.FilePath)
	if err != nil {
		return nil, fmt.Errorf("read --file %q: %w", opts.FilePath, err)
	}
	profile, err := resolveProfile(opts.Profile, data)
	if err != nil {
		return nil, err
	}
	switch profile {
	case "pades":
		return verifyPAdES(bytes.NewReader(data), int64(len(data)), opts)
	case "xades":
		return verifyXAdES(ctx, data, opts)
	default:
		return nil, fmt.Errorf("internal: unhandled profile %q", profile)
	}
}

// DetectProfile returns "pades", "xades", or "" (unknown) from the file bytes.
// %PDF -> PAdES; an XML document containing a ds:Signature root -> XAdES.
func DetectProfile(data []byte) string {
	trimmed := bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // strip UTF-8 BOM
	trimmed = bytes.TrimLeft(trimmed, " \t\r\n")
	if bytes.HasPrefix(trimmed, []byte("%PDF")) {
		return "pades"
	}
	// XAdES: an XML document whose signature is a W3C XML-DSig ds:Signature.
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<")) {
		if bytes.Contains(data, []byte("Signature")) &&
			bytes.Contains(data, []byte("http://www.w3.org/2000/09/xmldsig#")) {
			return "xades"
		}
	}
	return ""
}

// resolveProfile applies the requested profile or autodetects it.
func resolveProfile(requested string, data []byte) (string, error) {
	switch requested {
	case "pades", "xades":
		return requested, nil
	case "", "auto":
		p := DetectProfile(data)
		if p == "" {
			return "", fmt.Errorf("could not autodetect profile: not a PDF (%%PDF) and no XML-DSig ds:Signature found; pass --profile pades|xades")
		}
		return p, nil
	default:
		return "", fmt.Errorf("invalid profile %q: expected auto|pades|xades", requested)
	}
}

// trustAnchors loads the embedded anchors plus any extra PEM the caller passed.
func trustAnchors(extraPEM []byte) ([]anchors.Anchor, error) {
	list, err := anchors.Load()
	if err != nil {
		return nil, err
	}
	rest := extraPEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("--anchors: parse certificate: %w", err)
		}
		list = append(list, anchors.Anchor{
			File:        "extra",
			Certificate: cert,
			SelfSigned:  cert.Subject.String() == cert.Issuer.String(),
		})
	}
	return list, nil
}
