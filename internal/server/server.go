// Package server implements the `openmdsignd` local HTTPS daemon skeleton — the
// browser⇄daemon transport, routing, CORS and certificate enumeration defined
// in docs/PROTOCOL.md. It is Daemon Phase B: everything EXCEPT the actual
// signing, which is Phase C and plugs in behind the Signer seam (see signer.go).
//
// Design seams that let Phase B stand and Phase C slot in without reshaping:
//   - CertProvider (certs.go) sources /certificates — real token or test fake.
//   - Signer (signer.go) performs POST /sign/data — Phase B stub returns 501.
//   - JobStore (signer.go) bridges submit → fetch — wired now, filled by Phase C.
//
// No PIN is handled anywhere in this package: the synchronous PIN + confirmation
// gate lives inside a Phase C Signer implementation (PROTOCOL.md §7), and the
// one-attempt PIN policy stays in internal/token.
package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

// Config configures a Server. Zero-value fields fall back to PROTOCOL.md
// defaults via config.DefaultDaemon at the cmd layer; the Server itself assumes
// the caller already resolved them.
type Config struct {
	// HTTPSAddr is the loopback TLS listen address (PROTOCOL.md §1).
	HTTPSAddr string
	// HTTPAddr, when non-empty, enables the plain-HTTP probe listener (§1).
	HTTPAddr string
	// Hostname is the TLS server name the browser targets (§2).
	Hostname string
	// CORSAllowlist is the STRICT origin allowlist echoed in ACAO (§3).
	CORSAllowlist []string
	// ModulePath is the vendor PKCS#11 module path used by the token-backed
	// CertProvider when one is not injected.
	ModulePath string
	// TLSDir is the directory holding the persistent per-machine serving cert+key
	// (Daemon Phase D). Empty falls back to DefaultTLSDir at serve time.
	TLSDir string
	// EphemeralDevCert, when true, serves the in-memory ephemeral dev cert
	// (DevCert) instead of the persistent serving cert — a dev/test fallback
	// (`serve --dev-cert`) that installs no trust anchor.
	EphemeralDevCert bool
}

// Server is the daemon's HTTP surface. Construct with New; run with the
// listener helpers in listen.go.
type Server struct {
	cfg       Config
	log       *slog.Logger
	certs     CertProvider
	signer    Signer
	jobs      JobStore
	allowlist map[string]bool
	handler   http.Handler
}

// Option customizes a Server. The defaults wire the production token-backed
// CertProvider, the Phase B stub Signer, and an in-memory JobStore; tests
// override these to run without hardware.
type Option func(*Server)

// WithCertProvider injects a CertProvider (e.g. a test fake). Defaults to a
// token-backed provider over cfg.ModulePath.
func WithCertProvider(cp CertProvider) Option { return func(s *Server) { s.certs = cp } }

// WithSigner injects a Signer. Defaults to the Phase B stub (501).
func WithSigner(sg Signer) Option { return func(s *Server) { s.signer = sg } }

// WithJobStore injects a JobStore. Defaults to an in-memory store.
func WithJobStore(js JobStore) Option { return func(s *Server) { s.jobs = js } }

// WithLogger injects a slog.Logger. Defaults to slog.Default().
func WithLogger(l *slog.Logger) Option { return func(s *Server) { s.log = l } }

// New builds a Server from cfg and options.
func New(cfg Config, opts ...Option) *Server {
	s := &Server{
		cfg:  cfg,
		log:  slog.Default(),
		jobs: NewMemJobStore(),
	}
	s.allowlist = make(map[string]bool, len(cfg.CORSAllowlist))
	for _, o := range cfg.CORSAllowlist {
		s.allowlist[o] = true
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.certs == nil {
		s.certs = NewTokenCertProvider(cfg.ModulePath)
	}
	if s.signer == nil {
		s.signer = NewStubSigner()
	}
	s.handler = s.corsMiddleware(s.routes())
	return s
}

// Handler exposes the fully-wired http.Handler (CORS + routes) for httptest.
func (s *Server) Handler() http.Handler { return s.handler }

// routes builds the PROTOCOL.md §4 router. Go's method-aware ServeMux dispatches
// the three documented routes; the CORS middleware handles OPTIONS preflight
// ahead of the mux so unmatched-method requests still preflight cleanly.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /certificates", s.handleCertificates)
	mux.HandleFunc("POST /sign/data", s.handleSign)
	mux.HandleFunc("GET /sign/data/PKCS11/{uuid}/{format}", s.handleSignResult)
	return mux
}

// corsHeaders are the constant CORS headers PROTOCOL.md §3 puts on every
// response (ACAO is added separately and only for an allowlisted Origin).
var corsHeaders = [][2]string{
	{"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
	{"Access-Control-Allow-Headers", "Origin, x-requested-with, content-type, accept, error, Location"},
	{"Access-Control-Expose-Headers", "Origin, x-requested-with, content-type, accept, error, Location"},
	{"Access-Control-Max-Age", "3600"},
}

// corsMiddleware applies PROTOCOL.md §3 to every response and answers OPTIONS
// preflight with 200. The Access-Control-Allow-Origin header is emitted ONLY
// when the caller's Origin is in the STRICT allowlist — never reflect-any, per
// the brief (a reflect-any daemon is a signing oracle, PROTOCOL.md §3 note).
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for _, kv := range corsHeaders {
			h.Set(kv[0], kv[1])
		}
		origin := r.Header.Get("Origin")
		if origin != "" && s.allowlist[origin] {
			// Vary on Origin: the ACAO value depends on the request Origin.
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Origin", origin)
		} else if origin != "" {
			s.log.Debug("CORS origin not in allowlist; no ACAO emitted", "origin", origin)
		}

		if r.Method == http.MethodOptions {
			// Preflight: 200 with the CORS headers already set, no body.
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleCertificates implements GET /certificates?private_only=true
// (PROTOCOL.md §4.1). It enumerates certs via the CertProvider (no login/PIN)
// and returns the {"certificateModel":[...]} envelope. When private_only=true
// (the value the page always sends) only certs with a private key are listed.
// No token / no certs ⇒ 200 with an empty list.
func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	privateOnly := r.URL.Query().Get("private_only") == "true"

	raw, err := s.certs.Certificates(r.Context())
	if err != nil {
		s.log.Warn("certificate enumeration failed", "err", err.Error())
		// A token/module problem is not fatal to the page's flow: return an
		// empty list so the UI shows "no certificate" rather than a hard error.
		s.writeJSON(w, http.StatusOK, certificatesResponse{CertificateModel: []CertificateModel{}})
		return
	}

	models := make([]CertificateModel, 0, len(raw))
	for _, tc := range raw {
		if privateOnly && !tc.PrivateKeyPresent {
			continue
		}
		models = append(models, toCertificateModel(s.cfg.ModulePath, tc))
	}
	s.writeJSON(w, http.StatusOK, certificatesResponse{CertificateModel: models})
}

// signRequestBody is the raw JSON shape POSTed to /sign/data (PROTOCOL.md §4.2).
type signRequestBody struct {
	Algorithm     string          `json:"algorithm"`
	Certificate   json.RawMessage `json:"certificate"`
	SignatureType string          `json:"signatureType"`
	SignFormat    string          `json:"signFormat"`
	ContentType   string          `json:"contentType"`
	Data          string          `json:"data"`
}

// handleSign implements POST /sign/data (PROTOCOL.md §4.2). Phase B fully parses
// and validates the body and lays out the intended 201 + Location flow, but the
// actual signing is Phase C: the injected Signer is the Phase B stub, so this
// returns 501. The success path (behind a real Signer) stores the result in the
// JobStore and returns 201 with the §4.2 Location header.
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var body signRequestBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)) // 64 MiB cap
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	// Validate the §4.2 fields. NOTE: `algorithm` is intentionally NOT used to
	// choose the container digest — per PROTOCOL.md §5 it is a client hint that
	// lied in the captures. The digest is driven by signFormat + profile in the
	// Phase C Signer; here we only sanity-check signFormat.
	switch body.SignFormat {
	case "PAdES-T", "XAdES-T":
		// ok
	default:
		s.writeError(w, http.StatusBadRequest,
			fmt.Sprintf("unsupported signFormat %q (want PAdES-T or XAdES-T)", body.SignFormat))
		return
	}
	if len(body.Certificate) == 0 {
		s.writeError(w, http.StatusBadRequest, "missing certificate object")
		return
	}
	data, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "data is not valid base64: "+err.Error())
		return
	}

	req := SignRequest{
		Algorithm:     body.Algorithm, // hint only; never the digest source (§5)
		Certificate:   body.Certificate,
		SignatureType: body.SignatureType,
		SignFormat:    body.SignFormat,
		ContentType:   body.ContentType,
		Data:          data,
		// Origin names the requesting site to the per-operation confirmation
		// dialog (§7). Empty when the caller sent no Origin header.
		Origin: r.Header.Get("Origin"),
	}

	// ── Phase C seam ─────────────────────────────────────────────────────────
	// The synchronous PIN entry + per-operation confirmation dialog (§7) live
	// inside Signer.Sign. The 201 below is emitted only once that returns a
	// finished container. Phase B's stub returns ErrSignerNotImplemented ⇒ 501.
	res, err := s.signer.Sign(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, ErrSignerNotImplemented):
			s.writeError(w, http.StatusNotImplemented,
				"signing not yet implemented (Daemon Phase C); request parsed and validated OK")
		case errors.Is(err, ErrUserCancelled):
			// The user declined the per-operation confirmation dialog (§7). No
			// token access occurred. The exact vendor error shape for a cancel
			// is unconfirmed (PROTOCOL.md §8.3); we answer 403 with a small body.
			s.writeError(w, http.StatusForbidden, "signing cancelled by user")
		case errors.Is(err, ErrUnsupportedSignFormat):
			s.writeError(w, http.StatusBadRequest, err.Error())
		default:
			// Never surface the raw error to the client (may name internals); log
			// it (never a PIN — the Signer guarantees none reaches an error).
			s.log.Warn("sign failed", "err", err.Error(), "signFormat", body.SignFormat)
			s.writeError(w, http.StatusInternalServerError, "signing failed")
		}
		return
	}

	// Success path (Phase C): persist the finished job and hand back the §4.2
	// 201 + Location. Content-Length: 0, body empty — the page then GETs the
	// Location (§4.3).
	if res.UUID == "" {
		res.UUID = newUUID()
	}
	s.jobs.Put(res.UUID, Job{Format: res.Format, Base64File: res.Base64File})
	loc := fmt.Sprintf("https://%s%s/sign/data/PKCS11/%s/%s",
		s.cfg.Hostname, hostPortSuffix(s.cfg.HTTPSAddr), res.UUID, res.Format)
	w.Header().Set("Location", loc)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// handleSignResult implements GET /sign/data/PKCS11/{uuid}/{format}
// (PROTOCOL.md §4.3): returns {"base64File": ...} from the JobStore. A missing
// job ⇒ 404. Phase B wires this end-to-end; Phase C fills the store.
func (s *Server) handleSignResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	job, ok := s.jobs.Get(id)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no such signing job")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"base64File": job.Base64File})
}

// hostPortSuffix returns ":<port>" from a listen address so the Location header
// carries the port the browser expects (PROTOCOL.md §2: :18443). An address
// without a parseable port yields no suffix.
func hostPortSuffix(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ""
	}
	return ":" + port
}

// newUUID returns a random RFC 4122 v4 UUID string, avoiding an external
// dependency for the small use here (job identifiers in the §4.2 Location).
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail; fall back to a zero UUID rather than
		// panic in a request handler.
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Debug("write json response failed", "err", err.Error())
	}
}

// writeError emits a small JSON error body. The page keys off HTTP status; the
// body is a human-readable aid.
func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}
