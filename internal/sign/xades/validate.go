package xades

import (
	"context"
)

// ValidateInput drives a DSS validation of an existing XAdES signature.
type ValidateInput struct {
	// XML is the XAdES document bytes.
	XML []byte
	// DetachedContent is the original signed document for a detached XAdES
	// (nil for enveloping/enveloped signatures).
	DetachedContent []byte
	// DetachedName is the basename the file:/<name> reference resolves to.
	DetachedName string
	// Anchors is the trust-anchor set (DER certificates) seeded into DSS's
	// CertificateVerifier so a chain can terminate at a trusted root instead
	// of yielding NO_CERTIFICATE_CHAIN_FOUND.
	Anchors [][]byte
	// CheckRevocation, when true, wires online OCSP/CRL sources into DSS.
	CheckRevocation bool
	// JavaPath and JarPath locate the DSS helper (empty => resolved from env).
	JavaPath string
	JarPath  string
}

// ValidationResult is the DSS validation outcome (from the simple report).
type ValidationResult struct {
	SignatureID         string
	Indication          string
	SubIndication       string
	SignedBy            string
	SigningTime         string
	TimestampTime       string
	TimestampProducedBy string
}

// validateReq is the JSON request for the helper's "validate" op.
type validateReq struct {
	Op              string   `json:"op"`
	XMLB64          string   `json:"xmlB64"`
	DetachedFileB64 string   `json:"detachedFileB64,omitempty"`
	DetachedName    string   `json:"detachedName,omitempty"`
	AnchorsB64      []string `json:"anchorsB64,omitempty"`
	CheckRevocation bool     `json:"checkRevocation"`
}

// Validate runs the EU DSS validator against an existing XAdES signature,
// seeding it with the given trust anchors. It reuses the same long-running
// stdio helper as the signing path.
func Validate(ctx context.Context, in ValidateInput) (*ValidationResult, error) {
	h, err := startHelper(ctx, in.JavaPath, in.JarPath)
	if err != nil {
		return nil, err
	}
	defer h.close()

	req := validateReq{
		Op:              "validate",
		XMLB64:          b64encode(in.XML),
		DetachedName:    in.DetachedName,
		CheckRevocation: in.CheckRevocation,
	}
	if in.DetachedContent != nil {
		req.DetachedFileB64 = b64encode(in.DetachedContent)
	}
	for _, der := range in.Anchors {
		req.AnchorsB64 = append(req.AnchorsB64, b64encode(der))
	}

	r, err := h.call(req)
	if err != nil {
		return nil, err
	}
	return &ValidationResult{
		SignatureID:         r.SignatureID,
		Indication:          r.Indication,
		SubIndication:       r.SubIndication,
		SignedBy:            r.SignedBy,
		SigningTime:         r.SigningTime,
		TimestampTime:       r.TimestampTime,
		TimestampProducedBy: r.TimestampProducedBy,
	}, nil
}
