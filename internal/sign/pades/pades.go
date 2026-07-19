// Package pades implements the PAdES-B-T PDF signer profile for openmdsign.
//
// It produces a PDF signature matching docs/profile-spec.md §2:
//
//   - signature dict /Filter /Adobe.PPKLite, /SubFilter /ETSI.CAdES.detached
//   - a single /ByteRange over the whole document, CMS in /Contents
//   - CMS SignedData: SHA-256 / sha256WithRSAEncryption
//   - signed attrs: contentType + messageDigest + signingCertificateV2 (ESS)
//   - unsigned attr (level t): RFC 3161 signatureTimeStampToken from the TSA
//
// It never performs a C_Login: it drives an already-authenticated crypto.Signer
// (typically internal/token.Signer over the hardware token). The heavy lifting
// -- the incremental-update PDF writer and CMS assembly -- is a minimal fork of
// github.com/digitorus/pdfsign (see internal/pades/pdfsign/NOTICE.md).
package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/digitorus/pdf"

	"github.com/branisted/openmdsign/internal/pades/pdfsign"
	"github.com/branisted/openmdsign/internal/sign"
)

// Profile is the profile name produced by this Signer.
const Profile = "PAdES"

// Signer implements sign.Signer for the PAdES-B-T PDF profile.
type Signer struct{}

// New returns a PAdES Signer.
func New() *Signer { return &Signer{} }

// Profile returns the container profile name.
func (*Signer) Profile() string { return Profile }

// Sign produces a PAdES-B-T (or -B if level b) signature over req.InputPDF and
// writes it to req.OutputPath. It never logs in: req.Signer must already be
// authenticated. For level t it calls req.TSAURL for an RFC 3161 timestamp.
func (*Signer) Sign(_ context.Context, req sign.Request) (sign.Result, error) {
	if req.Certificate == nil {
		return sign.Result{}, fmt.Errorf("pades: signing certificate is required")
	}
	if req.Signer == nil {
		return sign.Result{}, fmt.Errorf("pades: authenticated crypto.Signer is required")
	}
	if len(req.InputPDF) == 0 {
		return sign.Result{}, fmt.Errorf("pades: empty input PDF")
	}

	// Reject non-PDF input cleanly (the pdf reader would otherwise fail with an
	// opaque error). A PDF must begin with the %PDF- header.
	if !looksLikePDF(req.InputPDF) {
		return sign.Result{}, fmt.Errorf("pades: input does not look like a PDF (missing %%PDF- header)")
	}

	rdr, err := pdf.NewReader(bytes.NewReader(req.InputPDF), int64(len(req.InputPDF)))
	if err != nil {
		return sign.Result{}, fmt.Errorf("pades: parse input PDF: %w", err)
	}

	// Build the CMS certificate set: leaf first, then the supplied issuer chain.
	chain := make([]*x509.Certificate, 0, 1+len(req.Chain))
	chain = append(chain, req.Certificate)
	chain = append(chain, req.Chain...)

	timestamp := req.Level == sign.LevelT
	tsa := pdfsign.TSA{}
	if timestamp {
		if req.TSAURL == "" {
			return sign.Result{}, fmt.Errorf("pades: level t requires a TSA URL")
		}
		tsa.URL = req.TSAURL
	}

	signData := pdfsign.SignData{
		Signature: pdfsign.SignDataSignature{
			// ApprovalSignature is a plain document (recipient) signature: no
			// DocMDP/UR transform, which matches a detached PAdES-B-T signature.
			CertType: pdfsign.ApprovalSignature,
		},
		Signer:            req.Signer,
		DigestAlgorithm:   crypto.SHA256,
		Certificate:       req.Certificate,
		CertificateChains: [][]*x509.Certificate{chain},
		TSA:               tsa,
	}

	var out bytes.Buffer
	if err := pdfsign.Sign(bytes.NewReader(req.InputPDF), &out, rdr, int64(len(req.InputPDF)), signData); err != nil {
		return sign.Result{}, fmt.Errorf("pades: sign PDF: %w", err)
	}

	if err := writeOutput(req.OutputPath, out.Bytes()); err != nil {
		return sign.Result{}, err
	}

	return sign.Result{
		OutputPath:       req.OutputPath,
		Profile:          Profile,
		Level:            req.Level,
		TimestampApplied: timestamp,
		Bytes:            out.Len(),
	}, nil
}

// looksLikePDF reports whether b starts with a %PDF- header (optionally after a
// small leading BOM/whitespace, which some PDFs carry).
func looksLikePDF(b []byte) bool {
	const header = "%PDF-"
	limit := 1024
	if len(b) < limit {
		limit = len(b)
	}
	return bytes.Contains(b[:limit], []byte(header))
}
