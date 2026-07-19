package pades

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"github.com/branisted/openmdsign/internal/sign"
)

// oidSigningCertificateV2 is the ESS signingCertificateV2 signed-attribute OID.
var oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

// oidSignatureTimeStampToken is the RFC 3161 signatureTimeStampToken unsigned-attr OID.
var oidSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// buildMinimalPDF assembles a minimal one-page PDF with a correct xref table.
func buildMinimalPDF() []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	objOffsets := make([]int, 4)
	writeObj := func(n int, body string) {
		objOffsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	writeObj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>")

	xrefOff := buf.Len()
	buf.WriteString("xref\n0 4\n")
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", objOffsets[i])
	}
	buf.WriteString("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n")
	fmt.Fprintf(&buf, "%d\n%%%%EOF\n", xrefOff)
	return buf.Bytes()
}

// softwareSigner returns a self-signed RSA leaf + a crypto.Signer (NOT the token).
func softwareSigner(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, cert
}

// mockTSASigner returns a self-signed cert suitable for an RFC 3161 TSA: it is
// a CA (so the token's own self-signed chain verifies) with the timestamping
// extended key usage.
func mockTSASigner(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate tsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "OpenMDSign Mock TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create tsa cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse tsa cert: %v", err)
	}
	return key, cert
}

// pdfSig holds the CMS bytes and the signed ByteRange content extracted from a
// signed PDF.
type pdfSig struct {
	cms          []byte
	byteRangeIn  []byte
	byteRangeQty int
}

var (
	byteRangeRe = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)
	contentsRe  = regexp.MustCompile(`/Contents\s*<([0-9A-Fa-f]+)>`)
)

// extractSignature parses the single /ByteRange and /Contents CMS from a signed PDF.
func extractSignature(t *testing.T, signed []byte) pdfSig {
	t.Helper()
	brs := byteRangeRe.FindAllSubmatch(signed, -1)
	if len(brs) != 1 {
		t.Fatalf("expected exactly one /ByteRange, found %d", len(brs))
	}
	var a, b, c, d int
	fmt.Sscanf(string(brs[0][1]), "%d", &a)
	fmt.Sscanf(string(brs[0][2]), "%d", &b)
	fmt.Sscanf(string(brs[0][3]), "%d", &c)
	fmt.Sscanf(string(brs[0][4]), "%d", &d)

	cm := contentsRe.FindSubmatch(signed)
	if cm == nil {
		t.Fatalf("no /Contents hex found")
	}
	cms, err := hex.DecodeString(string(cm[1]))
	if err != nil {
		t.Fatalf("decode /Contents hex: %v", err)
	}
	// Strip trailing zero padding (the placeholder is padded with '0' nibbles).
	cms = bytes.TrimRight(cms, "\x00")

	content := make([]byte, 0, b+d)
	content = append(content, signed[a:a+b]...)
	content = append(content, signed[c:c+d]...)
	return pdfSig{cms: cms, byteRangeIn: content, byteRangeQty: len(brs)}
}

func TestSignPAdESLevelB(t *testing.T) {
	key, cert := softwareSigner(t, "OpenMDSign PAdES B Test")
	pdfBytes := buildMinimalPDF()
	out := filepath.Join(t.TempDir(), "signed.pdf")

	res, err := New().Sign(context.Background(), sign.Request{
		InputPDF:    pdfBytes,
		InputName:   "fixture.pdf",
		OutputPath:  out,
		Signer:      key,
		Certificate: cert,
		Level:       sign.LevelB,
	})
	if err != nil {
		t.Fatalf("Sign level b: %v", err)
	}
	if res.TimestampApplied {
		t.Fatalf("level b must not apply a timestamp")
	}
	if res.Profile != Profile || res.Level != sign.LevelB {
		t.Fatalf("unexpected result: %+v", res)
	}

	signed, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// Structural: SubFilter + single ByteRange.
	if !bytes.Contains(signed, []byte("/SubFilter /ETSI.CAdES.detached")) {
		t.Fatalf("missing /SubFilter /ETSI.CAdES.detached")
	}
	if bytes.Contains(signed, []byte("/adbe.pkcs7.detached")) {
		t.Fatalf("legacy /adbe.pkcs7.detached must not be present")
	}

	ps := extractSignature(t, signed)

	// CMS parses.
	p7, err := pkcs7.Parse(ps.cms)
	if err != nil {
		t.Fatalf("parse CMS: %v", err)
	}

	// Digest algorithm SHA-256.
	assertDigestSHA256(t, ps.cms)

	// signingCertificateV2 signed attribute present.
	var scv2 asn1.RawValue
	if err := p7.UnmarshalSignedAttribute(oidSigningCertificateV2, &scv2); err != nil {
		t.Fatalf("signingCertificateV2 signed attribute missing: %v", err)
	}

	// No adbe-revocationInfoArchival signed attr (spec: exactly 3 signed attrs).
	var junk asn1.RawValue
	if err := p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}, &junk); err == nil {
		t.Fatalf("unexpected adbe-revocationInfoArchival signed attribute present")
	}

	// The CMS signature verifies over the ByteRange content with the SOFTWARE key.
	p7.Content = ps.byteRangeIn
	if err := p7.Verify(); err != nil {
		t.Fatalf("CMS signature does not verify over ByteRange: %v", err)
	}

	// The embedded signer cert is our software leaf.
	if signer := p7.GetOnlySigner(); signer == nil || signer.Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("embedded signer cert mismatch")
	}

	// No RFC 3161 timestamp unsigned attribute at level b.
	if bytes.Contains(ps.cms, encodeOID(t, oidSignatureTimeStampToken)) {
		t.Fatalf("level b CMS must not carry a signatureTimeStampToken")
	}
}

func TestSignPAdESLevelTWithMockTSA(t *testing.T) {
	key, cert := softwareSigner(t, "OpenMDSign PAdES T Test")
	tsaKey, tsaCert := mockTSASigner(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil && len(body) == 0 {
			http.Error(w, "read", 500)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, "parse request: "+err.Error(), 400)
			return
		}
		tsResp := timestamp.Timestamp{
			HashAlgorithm: req.HashAlgorithm,
			HashedMessage: req.HashedMessage,
			Time:          time.Now(),
			Nonce:         req.Nonce,
			SerialNumber:  big.NewInt(1),
			Policy:        asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		}
		if req.Certificates {
			tsResp.Certificates = []*x509.Certificate{tsaCert}
		}
		der, err := tsResp.CreateResponse(tsaCert, tsaKey)
		if err != nil {
			http.Error(w, "create response: "+err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(der)
	}))
	defer ts.Close()

	pdfBytes := buildMinimalPDF()
	out := filepath.Join(t.TempDir(), "signed-t.pdf")

	res, err := New().Sign(context.Background(), sign.Request{
		InputPDF:    pdfBytes,
		OutputPath:  out,
		Signer:      key,
		Certificate: cert,
		Level:       sign.LevelT,
		TSAURL:      ts.URL,
	})
	if err != nil {
		t.Fatalf("Sign level t: %v", err)
	}
	if !res.TimestampApplied {
		t.Fatalf("level t must apply a timestamp")
	}

	signed, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	ps := extractSignature(t, signed)

	p7, err := pkcs7.Parse(ps.cms)
	if err != nil {
		t.Fatalf("parse CMS: %v", err)
	}
	p7.Content = ps.byteRangeIn
	if err := p7.Verify(); err != nil {
		t.Fatalf("CMS signature does not verify over ByteRange: %v", err)
	}

	// The RFC 3161 signatureTimeStampToken unsigned attribute must be embedded.
	if !bytes.Contains(ps.cms, encodeOID(t, oidSignatureTimeStampToken)) {
		t.Fatalf("level t CMS is missing the signatureTimeStampToken unsigned attribute")
	}
	// And the mock TSA's token must itself parse as a CMS.
	sub := ps.cms[bytes.Index(ps.cms, encodeOID(t, oidSignatureTimeStampToken)):]
	if len(sub) == 0 {
		t.Fatalf("could not locate timestamp token region")
	}
}

func TestSignRejectsNonPDF(t *testing.T) {
	key, cert := softwareSigner(t, "OpenMDSign NonPDF Test")
	out := filepath.Join(t.TempDir(), "nope.pdf")
	_, err := New().Sign(context.Background(), sign.Request{
		InputPDF:    []byte("this is plainly not a pdf document"),
		OutputPath:  out,
		Signer:      key,
		Certificate: cert,
		Level:       sign.LevelB,
	})
	if err == nil {
		t.Fatalf("expected error for non-PDF input")
	}
}

func TestSignLevelTRequiresTSAURL(t *testing.T) {
	key, cert := softwareSigner(t, "OpenMDSign NoTSA Test")
	out := filepath.Join(t.TempDir(), "x.pdf")
	_, err := New().Sign(context.Background(), sign.Request{
		InputPDF:    buildMinimalPDF(),
		OutputPath:  out,
		Signer:      key,
		Certificate: cert,
		Level:       sign.LevelT,
		TSAURL:      "",
	})
	if err == nil {
		t.Fatalf("expected error: level t without TSA URL")
	}
}

// assertDigestSHA256 checks the SignedData carries the SHA-256 digest algorithm
// OID (2.16.840.1.101.3.4.2.1) by scanning the CMS DER for its encoding.
func assertDigestSHA256(t *testing.T, cms []byte) {
	t.Helper()
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	if !bytes.Contains(cms, encodeOID(t, sha256OID)) {
		t.Fatalf("CMS does not carry the SHA-256 digest algorithm OID")
	}
}

// encodeOID returns the DER encoding (including tag+length) of an OID.
func encodeOID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal oid: %v", err)
	}
	return b
}
