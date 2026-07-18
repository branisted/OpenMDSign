package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/branistedev/openmdsign/internal/sign"
)

// --- SignFormat → params mapping (pure, no hardware) ------------------------

func TestMapSignFormatPAdES(t *testing.T) {
	p, err := mapSignFormat(SignRequest{SignFormat: "PAdES-T", ContentType: "Pdf", Data: []byte("%PDF-1.7 x")})
	if err != nil {
		t.Fatalf("PAdES-T mapping error: %v", err)
	}
	if p.profile != "pades" || p.formatSeg != "pdf" || p.level != sign.LevelT {
		t.Fatalf("PAdES params = %+v", p)
	}
}

func TestMapSignFormatXAdESDocument(t *testing.T) {
	// A full document (not a short pre-hash) ⇒ document XAdES, detached SHA-256.
	doc := []byte(strings.Repeat("some document text ", 20))
	p, err := mapSignFormat(SignRequest{SignFormat: "XAdES-T", ContentType: "Text", Data: doc})
	if err != nil {
		t.Fatalf("XAdES-T document mapping error: %v", err)
	}
	if p.profile != "xades" || p.formatSeg != "XAdES" || p.packaging != sign.PackagingDetached || p.digest != "sha256" {
		t.Fatalf("XAdES document params = %+v", p)
	}
}

func TestMapSignFormatAuthChallenge(t *testing.T) {
	// A short (~20-byte) Text pre-hash is the mpass auth challenge ⇒ XAdES-T
	// ENVELOPING with SHA-1 (interop-required), auth-flagged for the dialog.
	challenge := make([]byte, 20) // SHA-1 sized pre-hash
	p, err := mapSignFormat(SignRequest{SignFormat: "XAdES-T", ContentType: "Text", Data: challenge})
	if err != nil {
		t.Fatalf("auth challenge mapping error: %v", err)
	}
	if p.profile != "xades" || p.formatSeg != "XAdES" || p.packaging != sign.PackagingEnveloping ||
		p.digest != "sha1" || p.level != sign.LevelT || !p.isAuth {
		t.Fatalf("auth challenge params = %+v", p)
	}
	// The neutral input name must never carry a filesystem path (anti-leak).
	if strings.ContainsAny(p.inputName, `/\`) {
		t.Fatalf("auth input name must be a neutral basename, got %q", p.inputName)
	}
}

func TestMapSignFormatUnsupported(t *testing.T) {
	_, err := mapSignFormat(SignRequest{SignFormat: "CAdES-T"})
	if !errors.Is(err, ErrUnsupportedSignFormat) {
		t.Fatalf("err = %v, want ErrUnsupportedSignFormat", err)
	}
}

// --- Confirmer plumbing: Origin threading & cancel --------------------------

// recordingConfirmer captures the ConfirmRequest and can be told to cancel. It
// never touches osascript, a token, or a real PIN.
type recordingConfirmer struct {
	mu      sync.Mutex
	last    ConfirmRequest
	seen    bool
	cancel  bool
	pin     string
	onEnter func()
}

func (c *recordingConfirmer) Confirm(_ context.Context, req ConfirmRequest) (string, error) {
	c.mu.Lock()
	c.last = req
	c.seen = true
	c.mu.Unlock()
	if c.onEnter != nil {
		c.onEnter()
	}
	if c.cancel {
		return "", ErrUserCancelled
	}
	return c.pin, nil
}

func TestTokenSignerCancelAbortsBeforeToken(t *testing.T) {
	// No module ⇒ if the cancel gate were skipped we'd hit the "no module"
	// error; instead we must get ErrUserCancelled with NO token access.
	conf := &recordingConfirmer{cancel: true}
	ts := NewTokenSigner(TokenSignerConfig{}, conf, nil)
	_, err := ts.Sign(context.Background(), SignRequest{
		SignFormat:  "PAdES-T",
		ContentType: "Pdf",
		Data:        []byte("%PDF-1.7 x"),
		Certificate: json.RawMessage(`{"certificateId":"aabbcc"}`),
		Origin:      "https://msign.gov.md",
	})
	if !errors.Is(err, ErrUserCancelled) {
		t.Fatalf("err = %v, want ErrUserCancelled", err)
	}
}

func TestTokenSignerThreadsOriginToConfirmer(t *testing.T) {
	conf := &recordingConfirmer{cancel: true} // cancel to stop before the token
	ts := NewTokenSigner(TokenSignerConfig{}, conf, nil)
	_, _ = ts.Sign(context.Background(), SignRequest{
		SignFormat:  "PAdES-T",
		ContentType: "Pdf",
		Data:        []byte("%PDF-1.7 x"),
		Certificate: json.RawMessage(`{"certificateId":"aabbcc"}`),
		Origin:      "https://msign.gov.md",
	})
	if !conf.seen {
		t.Fatal("confirmer was never called")
	}
	if conf.last.Origin != "https://msign.gov.md" {
		t.Fatalf("confirmer Origin = %q, want the request Origin", conf.last.Origin)
	}
	if conf.last.SignFormat != "PAdES-T" {
		t.Fatalf("confirmer SignFormat = %q", conf.last.SignFormat)
	}
}

func TestTokenSignerAuthChallengeReachesConfirmAsAuth(t *testing.T) {
	// The mpass auth challenge is now wired: it must reach the confirm/PIN gate
	// flagged as an authentication request (so the dialog says "log you in"), and
	// a cancel there aborts before any token access.
	conf := &recordingConfirmer{cancel: true}
	ts := NewTokenSigner(TokenSignerConfig{}, conf, nil)
	_, err := ts.Sign(context.Background(), SignRequest{
		SignFormat:  "XAdES-T",
		ContentType: "Text",
		Data:        make([]byte, 20),
		Certificate: json.RawMessage(`{"certificateId":"aabbcc"}`),
		Origin:      "https://mpass.gov.md",
	})
	if !errors.Is(err, ErrUserCancelled) {
		t.Fatalf("err = %v, want ErrUserCancelled", err)
	}
	if !conf.seen {
		t.Fatal("auth-challenge must reach the confirm/PIN gate")
	}
	if !conf.last.IsAuth {
		t.Fatal("confirm request for the mpass challenge must be flagged IsAuth")
	}
	if conf.last.Origin != "https://mpass.gov.md" {
		t.Fatalf("confirm Origin = %q, want the mpass origin", conf.last.Origin)
	}
}

// --- Concurrency: overlapping Sign calls serialize on the token mutex -------

// entryExitConfirmer records concurrent entries so a test can prove the mutex
// serializes token operations (no interleave).
type entryExitConfirmer struct {
	inFlight int32
	maxSeen  int32
	block    chan struct{}
}

func (c *entryExitConfirmer) Confirm(_ context.Context, _ ConfirmRequest) (string, error) {
	n := atomic.AddInt32(&c.inFlight, 1)
	for {
		m := atomic.LoadInt32(&c.maxSeen)
		if n <= m || atomic.CompareAndSwapInt32(&c.maxSeen, m, n) {
			break
		}
	}
	<-c.block // hold the "critical section" until released
	atomic.AddInt32(&c.inFlight, -1)
	return "", ErrUserCancelled // cancel so we never touch a token
}

func TestTokenSignerSerializesConcurrentSigns(t *testing.T) {
	conf := &entryExitConfirmer{block: make(chan struct{})}
	ts := NewTokenSigner(TokenSignerConfig{}, conf, nil)
	req := SignRequest{
		SignFormat:  "PAdES-T",
		ContentType: "Pdf",
		Data:        []byte("%PDF-1.7 x"),
		Certificate: json.RawMessage(`{"certificateId":"aabbcc"}`),
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = ts.Sign(context.Background(), req)
		}()
	}
	// Give both goroutines time to try to enter; the mutex must admit only one.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&conf.maxSeen); got != 1 {
		t.Fatalf("max concurrent confirmer entries = %d, want 1 (mutex must serialize)", got)
	}
	close(conf.block) // release; both complete
	wg.Wait()
}

// --- Full handler path with a fake Signer (201 + Location, fetch) -----------

// stubResultSigner returns a canned SignResult, standing in for a completed
// TokenSigner run so the handler wiring is proven without hardware.
type stubResultSigner struct {
	format string
	origin *string
}

func (s *stubResultSigner) Sign(_ context.Context, req SignRequest) (SignResult, error) {
	if s.origin != nil {
		*s.origin = req.Origin
	}
	return SignResult{UUID: "job-xyz", Format: s.format, Base64File: "c2lnbmVkLWJ5dGVz"}, nil
}

func TestHandlerPAdESFullPath(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}), WithSigner(&stubResultSigner{format: "pdf"}))
	body := map[string]any{
		"signFormat":  "PAdES-T",
		"contentType": "Pdf",
		"certificate": map[string]any{"certificateId": "aabbcc"},
		"data":        base64.StdEncoding.EncodeToString([]byte("%PDF-1.7 x")),
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(string(b)))
	req.Header.Set("Origin", "https://msign.gov.md")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	want := "https://localhost.cts.md:18443/sign/data/PKCS11/job-xyz/pdf"
	if loc := rr.Header().Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
	// §4.3 fetch returns the stored base64File.
	greq := httptest.NewRequest(http.MethodGet, "/sign/data/PKCS11/job-xyz/pdf", nil)
	grr := httptest.NewRecorder()
	s.Handler().ServeHTTP(grr, greq)
	if grr.Code != http.StatusOK {
		t.Fatalf("fetch status = %d, want 200", grr.Code)
	}
	var got map[string]string
	_ = json.Unmarshal(grr.Body.Bytes(), &got)
	if got["base64File"] != "c2lnbmVkLWJ5dGVz" {
		t.Fatalf("base64File = %q", got["base64File"])
	}
}

func TestHandlerXAdESLocationSegment(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}), WithSigner(&stubResultSigner{format: "XAdES"}))
	body := `{"signFormat":"XAdES-T","contentType":"Text","certificate":{"certificateId":"aabbcc"},"data":""}`
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	want := "https://localhost.cts.md:18443/sign/data/PKCS11/job-xyz/XAdES"
	if loc := rr.Header().Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestHandlerThreadsOriginIntoSignRequest(t *testing.T) {
	var seen string
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}), WithSigner(&stubResultSigner{format: "pdf", origin: &seen}))
	body := `{"signFormat":"PAdES-T","contentType":"Pdf","certificate":{"certificateId":"aabbcc"},"data":""}`
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(body))
	req.Header.Set("Origin", "https://mpass.gov.md")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if seen != "https://mpass.gov.md" {
		t.Fatalf("SignRequest.Origin = %q, want the request Origin header", seen)
	}
}

// --- Handler error mapping for the typed Signer errors ----------------------

type errSigner struct{ err error }

func (e errSigner) Sign(context.Context, SignRequest) (SignResult, error) {
	return SignResult{}, e.err
}

func TestHandlerCancelMapsTo403(t *testing.T) {
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}), WithSigner(errSigner{err: ErrUserCancelled}))
	body := `{"signFormat":"PAdES-T","contentType":"Pdf","certificate":{"certificateId":"aabbcc"},"data":""}`
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cancel status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlerAuthChallengeRoutesToSigner(t *testing.T) {
	// An auth-shaped XAdES-T body now routes to the signer (no longer 501) and,
	// behind a completed signer, returns 201 + a .../XAdES Location.
	s := newTestServer(t, WithCertProvider(fakeCertProvider{}), WithSigner(&stubResultSigner{format: "XAdES"}))
	// A short base64 pre-hash challenge (20 bytes) with contentType Text.
	body := map[string]any{
		"signFormat":  "XAdES-T",
		"contentType": "Text",
		"certificate": map[string]any{"certificateId": "aabbcc"},
		"data":        base64.StdEncoding.EncodeToString(make([]byte, 20)),
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/sign/data", strings.NewReader(string(b)))
	req.Header.Set("Origin", "https://mpass.gov.md")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("auth-challenge status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	want := "https://localhost.cts.md:18443/sign/data/PKCS11/job-xyz/XAdES"
	if loc := rr.Header().Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

// --- certificateID extraction -----------------------------------------------

func TestCertificateIDExtraction(t *testing.T) {
	id, err := certificateID(json.RawMessage(`{"certificateId":"379ee7b7","label":"x"}`))
	if err != nil || id != "379ee7b7" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if _, err := certificateID(json.RawMessage(`{"label":"x"}`)); err == nil {
		t.Fatal("want error when certificateId missing")
	}
}
