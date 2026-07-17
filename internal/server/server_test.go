package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeCertProvider is the injected test double for CertProvider: it lets the
// /certificates route run with zero hardware. This is exactly how the real
// token-backed provider will be swapped for a fake — via WithCertProvider.
type fakeCertProvider struct {
	certs []TokenCertificate
	err   error
}

func (f fakeCertProvider) Certificates(context.Context) ([]TokenCertificate, error) {
	return f.certs, f.err
}

// makeTestCertDER builds a throwaway self-signed cert so the mapping code has a
// real DER to parse (subject/issuer/policy), without any token.
func makeTestCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	policyOID, err := x509.OIDFromInts([]uint64{1, 2, 498, 3, 32, 1, 1})
	if err != nil {
		t.Fatalf("oid: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Country: []string{"MD"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		Policies:     []x509.OID{policyOID},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	return der
}

func newTestServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	cfg := Config{
		HTTPSAddr:     "127.0.0.1:18443",
		Hostname:      "localhost.cts.md",
		CORSAllowlist: []string{"https://msign.gov.md", "https://mpass.gov.md"},
		ModulePath:    "/opt/vendor/libeToken.dylib",
	}
	return New(cfg, opts...)
}

// --- CORS -------------------------------------------------------------------

func TestCORSAllowedOriginEchoed(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}))
	req := httptest.NewRequest(http.MethodGet, "/certificates", nil)
	req.Header.Set("Origin", "https://msign.gov.md")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://msign.gov.md" {
		t.Fatalf("ACAO = %q, want the echoed gov origin", got)
	}
	// The constant CORS headers must always be present.
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
		t.Fatalf("Allow-Methods = %q", got)
	}
	if got := rr.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(got, "Location") {
		t.Fatalf("Expose-Headers = %q, want to include Location", got)
	}
	if got := rr.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Fatalf("Max-Age = %q", got)
	}
}

func TestCORSDeniedOriginNoACAO(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}))
	req := httptest.NewRequest(http.MethodGet, "/certificates", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO = %q, want empty for a non-allowlisted origin (no reflect-any)", got)
	}
	// Other CORS headers are still emitted per §3.
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
		t.Fatalf("Allow-Methods = %q", got)
	}
}

func TestCORSPreflightOptions(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}))
	req := httptest.NewRequest(http.MethodOptions, "/sign/data", nil)
	req.Header.Set("Origin", "https://mpass.gov.md")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("preflight status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://mpass.gov.md" {
		t.Fatalf("preflight ACAO = %q", got)
	}
}

// --- GET /certificates ------------------------------------------------------

func TestCertificatesShape(t *testing.T) {
	der := makeTestCertDER(t, "Test Signer")
	s := newTestServer(t, WithCertProvider(fakeCertProvider{certs: []TokenCertificate{
		{DER: der, CKAIDHex: "aabbcc", Label: "Test Signer", SlotIndex: 0, PrivateKeyPresent: true},
	}}))

	req := httptest.NewRequest(http.MethodGet, "/certificates?private_only=true", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp certificatesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
	}
	if len(resp.CertificateModel) != 1 {
		t.Fatalf("got %d certs, want 1", len(resp.CertificateModel))
	}
	m := resp.CertificateModel[0]
	if m.CertificateID != "aabbcc" {
		t.Errorf("certificateId = %q", m.CertificateID)
	}
	if m.ProviderID != "libeToken.dylib-0" {
		t.Errorf("providerId = %q, want libeToken.dylib-0", m.ProviderID)
	}
	if m.Policy != "1.2.498.3.32.1.1" {
		t.Errorf("policy = %q", m.Policy)
	}
	if !m.PrivateKeyPresent {
		t.Errorf("privateKeyPresent = false, want true")
	}
	if !strings.Contains(m.SubjectDN, "CN=Test Signer") {
		t.Errorf("subjectDN = %q", m.SubjectDN)
	}
	if m.CertificateBase64 == "" {
		t.Errorf("certificateBase64 empty")
	}
	// The exact §4.1 envelope key must be present, even when empty.
	if !strings.Contains(rr.Body.String(), "certificateModel") {
		t.Errorf("missing certificateModel envelope key")
	}
}

func TestCertificatesPrivateOnlyFilters(t *testing.T) {
	der := makeTestCertDER(t, "CA Cert")
	s := newTestServer(t, WithCertProvider(fakeCertProvider{certs: []TokenCertificate{
		{DER: der, CKAIDHex: "11", Label: "no-key", SlotIndex: 0, PrivateKeyPresent: false},
	}}))
	req := httptest.NewRequest(http.MethodGet, "/certificates?private_only=true", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	var resp certificatesResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.CertificateModel) != 0 {
		t.Fatalf("private_only should have filtered the keyless cert; got %d", len(resp.CertificateModel))
	}
	// Envelope still non-null.
	if !strings.Contains(rr.Body.String(), "certificateModel") {
		t.Errorf("empty list must still carry the certificateModel envelope")
	}
}

func TestCertificatesEmptyOnProviderError(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{err: io.ErrUnexpectedEOF}))
	req := httptest.NewRequest(http.MethodGet, "/certificates", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (provider error → empty list)", rr.Code)
	}
	var resp certificatesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.CertificateModel) != 0 {
		t.Fatalf("want empty list on provider error")
	}
}

// --- POST /sign/data --------------------------------------------------------

func TestSignParsesBodyAndReturns501(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}))
	bodyObj := map[string]any{
		"algorithm":     "SHA-1", // §5: a lie — must NOT drive the digest
		"certificate":   map[string]any{"certificateId": "aabbcc"},
		"signatureType": "Embedded",
		"signFormat":    "PAdES-T",
		"contentType":   "Pdf",
		"data":          base64.StdEncoding.EncodeToString([]byte("%PDF-1.7 test")),
	}
	b, _ := json.Marshal(bodyObj)
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (Phase B stub); body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Phase C") {
		t.Errorf("501 body should point to Phase C; got %s", rr.Body.String())
	}
}

func TestSignRejectsBadFormat(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}))
	body := `{"signFormat":"BOGUS","certificate":{"x":1},"data":""}`
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unsupported signFormat", rr.Code)
	}
}

func TestSignRejectsBadBase64(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}))
	body := `{"signFormat":"XAdES-T","certificate":{"x":1},"data":"!!!not base64!!!"}`
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for bad base64 data", rr.Code)
	}
}

// fakeSigner exercises the intended 201 + Location success path that Phase C
// will drive, proving the JobStore wiring end-to-end.
type fakeSigner struct{}

func (fakeSigner) Sign(context.Context, SignRequest) (SignResult, error) {
	return SignResult{UUID: "job-123", Format: "pdf", Base64File: "c2lnbmVk"}, nil
}

func TestSignSuccessPathStoresJobAndSets201(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}), WithSigner(fakeSigner{}))
	body := `{"signFormat":"PAdES-T","certificate":{"x":1},"data":""}`
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	want := "https://localhost.cts.md:18443/sign/data/PKCS11/job-123/pdf"
	if loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

// --- GET /sign/data/PKCS11/{uuid}/{format} ----------------------------------

func TestSignResultFromStore(t *testing.T) {
	js := NewMemJobStore()
	js.Put("uuid-1", Job{Format: "pdf", Base64File: "aGVsbG8="})
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}), WithJobStore(js))

	req := httptest.NewRequest(http.MethodGet, "/sign/data/PKCS11/uuid-1/pdf", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["base64File"] != "aGVsbG8=" {
		t.Fatalf("base64File = %q", got["base64File"])
	}
}

func TestSignResultMissingJob404(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}))
	req := httptest.NewRequest(http.MethodGet, "/sign/data/PKCS11/nope/pdf", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

// --- dev cert ---------------------------------------------------------------

func TestDevCertGeneratesForHostname(t *testing.T) {
	cert, err := DevCert("localhost.cts.md")
	if err != nil {
		t.Fatalf("DevCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := leaf.VerifyHostname("localhost.cts.md"); err != nil {
		t.Fatalf("dev cert does not cover hostname: %v", err)
	}
}
