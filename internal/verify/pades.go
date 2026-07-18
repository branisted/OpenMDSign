package verify

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"github.com/branistedev/openmdsign/internal/verify/anchors"
)

// oidSignatureTimeStampToken is the CMS unsigned attribute carrying the RFC 3161
// signature timestamp (id-aa-signatureTimeStampToken).
var oidSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// verifyPAdES verifies a PAdES-B-T signature over a PDF read from r (size
// bytes). It parses the embedded CMS, checks the signature over the /ByteRange,
// builds the certificate chain to the embedded anchors, and verifies the
// RFC 3161 signature timestamp.
func verifyPAdES(r io.ReaderAt, size int64, opts Options) (*Result, error) {
	anchorList, err := trustAnchors(opts.ExtraAnchorsPEM)
	if err != nil {
		return nil, err
	}

	p7, byteRange, err := extractPDFSignature(r, size)
	if err != nil {
		return nil, err
	}
	p7.Content = byteRange

	res := &Result{Profile: "pades"}

	// 1. Cryptographic validity of the CMS over the ByteRange (no trust yet).
	sigValid := p7.Verify() == nil
	res.Signer.SignatureValid = &sigValid

	leaf := p7.GetOnlySigner()
	if leaf == nil {
		return nil, fmt.Errorf("pades: no signer certificate in the CMS")
	}
	res.Signer.Subject = leaf.Subject.String()
	res.Signer.Issuer = leaf.Issuer.String()
	res.Signer.SerialNumber = formatSerial(leaf)
	res.Signer.IDNP = leaf.Subject.SerialNumber

	// 2. Signature timestamp (RFC 3161) from the unsigned attributes.
	ts, tsErr := extractTimestamp(p7)
	verifyTime := time.Now()
	if ts != nil {
		verifyTime = ts.timestamp.Time
		res.Timestamp = &TimestampInfo{
			Time:          ts.timestamp.Time.UTC().Format(time.RFC3339),
			TSA:           ts.tsaName,
			HashAlgorithm: ts.timestamp.HashAlgorithm.String(),
			Valid:         &ts.hashMatch,
		}
		res.Signer.SigningTime = ts.timestamp.Time.UTC().Format(time.RFC3339)
	} else if tsErr != nil {
		res.Warnings = append(res.Warnings, "timestamp: "+tsErr.Error())
	}

	// 3. Certificate chain to the embedded STISC anchors, at timestamp time.
	roots, intermediates := anchors.Pools(anchorList)
	for _, c := range p7.Certificates {
		intermediates.AddCert(c)
	}
	chains, chainErr := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   verifyTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if chainErr == nil && len(chains) > 0 {
		anchor := chains[0][len(chains[0])-1]
		res.Chain = ChainInfo{Status: "trusted", Anchor: anchor.Subject.String()}
	} else {
		res.Chain = ChainInfo{Status: "indeterminate"}
		if chainErr != nil {
			res.Chain.Detail = chainErr.Error()
		}
	}

	// 4. Optional revocation (OCSP/CRL, needs network).
	revoked := false
	if opts.CheckRevocation {
		rr := checkRevocation(leaf, append([]*x509.Certificate{}, p7.Certificates...), anchorList)
		if rr.detail != "" {
			res.Warnings = append(res.Warnings, "revocation: "+rr.detail)
		}
		revoked = rr.revoked
	}

	// 5. Overall verdict.
	switch {
	case !sigValid:
		res.Overall = Invalid
		res.Reason = "CMS signature does not verify over the document ByteRange"
	case revoked:
		res.Overall = Invalid
		res.Reason = "signer certificate is revoked"
	case res.Chain.Status == "trusted":
		res.Overall = Valid
	default:
		res.Overall = Indeterminate
		res.Reason = "signature is cryptographically valid but the certificate chain did not terminate at a trusted STISC anchor"
	}
	if ts != nil && !ts.hashMatch {
		res.Warnings = append(res.Warnings, "timestamp hash does not match the signature value")
	}
	return res, nil
}

// extractPDFSignature locates the Adobe.PPKLite signature in the PDF, returning
// the parsed CMS and the concatenated /ByteRange content it signs.
func extractPDFSignature(r io.ReaderAt, size int64) (p7 *pkcs7.PKCS7, content []byte, err error) {
	// The digitorus/pdf reader panics on some malformed/tampered inputs;
	// convert that into an ordinary error so verification reports INVALID
	// rather than crashing the process.
	defer func() {
		if rec := recover(); rec != nil {
			p7, content, err = nil, nil, fmt.Errorf("pades: malformed PDF: %v", rec)
		}
	}()
	rdr, err := pdf.NewReader(r, size)
	if err != nil {
		return nil, nil, fmt.Errorf("pades: open PDF: %w", err)
	}
	if rdr.Trailer().Key("Root").Key("AcroForm").Key("SigFlags").IsNull() {
		return nil, nil, fmt.Errorf("pades: no digital signature in document (no AcroForm SigFlags)")
	}
	for _, x := range rdr.Xref() {
		v := rdr.Resolve(x.Ptr(), x.Ptr())
		if v.Key("Filter").Name() != "Adobe.PPKLite" {
			continue
		}
		contents := v.Key("Contents").RawString()
		if contents == "" {
			continue
		}
		parsed, perr := pkcs7.Parse([]byte(contents))
		if perr != nil {
			return nil, nil, fmt.Errorf("pades: parse CMS from /Contents: %w", perr)
		}
		var body []byte
		br := v.Key("ByteRange")
		for i := 0; i+1 < br.Len(); i += 2 {
			off := br.Index(i).Int64()
			length := br.Index(i + 1).Int64()
			seg, rerr := io.ReadAll(io.NewSectionReader(r, off, length))
			if rerr != nil {
				return nil, nil, fmt.Errorf("pades: read ByteRange segment: %w", rerr)
			}
			body = append(body, seg...)
		}
		if len(body) == 0 {
			return nil, nil, fmt.Errorf("pades: empty /ByteRange")
		}
		return parsed, body, nil
	}
	return nil, nil, fmt.Errorf("pades: no Adobe.PPKLite signature dictionary found")
}

type tsResult struct {
	timestamp *timestamp.Timestamp
	tsaName   string
	hashMatch bool
}

// extractTimestamp pulls and validates the RFC 3161 signature timestamp from
// the CMS unsigned attributes.
func extractTimestamp(p7 *pkcs7.PKCS7) (*tsResult, error) {
	for _, s := range p7.Signers {
		for _, attr := range s.UnauthenticatedAttributes {
			if !attr.Type.Equal(oidSignatureTimeStampToken) {
				continue
			}
			ts, err := timestamp.Parse(attr.Value.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse RFC 3161 token: %w", err)
			}
			h := ts.HashAlgorithm.New()
			h.Write(s.EncryptedDigest)
			match := bytes.Equal(h.Sum(nil), ts.HashedMessage)
			return &tsResult{timestamp: ts, tsaName: tsaName(ts), hashMatch: match}, nil
		}
	}
	return nil, nil
}

// tsaName picks a human-readable TSA name from the timestamp token's certs,
// preferring the certificate that carries the TimeStamping EKU.
func tsaName(ts *timestamp.Timestamp) string {
	for _, c := range ts.Certificates {
		for _, eku := range c.ExtKeyUsage {
			if eku == x509.ExtKeyUsageTimeStamping {
				return c.Subject.String()
			}
		}
	}
	if len(ts.Certificates) > 0 {
		return ts.Certificates[0].Subject.String()
	}
	return ""
}

func formatSerial(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return ""
	}
	return c.SerialNumber.Text(16)
}
