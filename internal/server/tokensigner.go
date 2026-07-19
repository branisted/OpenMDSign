package server

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/branisted/openmdsign/internal/sign"
	"github.com/branisted/openmdsign/internal/sign/pades"
	"github.com/branisted/openmdsign/internal/sign/xades"
	"github.com/branisted/openmdsign/internal/sign/xadesauth"
	"github.com/branisted/openmdsign/internal/token"
)

// DefaultTSAURL is the observed MoldSign RFC 3161 timestamp authority, used by
// the -T profiles when the daemon config does not override it.
const DefaultTSAURL = "http://tsp.pki.gov.md/moldsign2/"

// Typed errors the Sign path can return. The handler maps each to a documented
// HTTP status (see handleSign); everything else becomes a generic 500 so no
// internal detail leaks. None of these ever carries PIN material.
var (
	// ErrUserCancelled is returned when the user declines the per-operation
	// confirmation dialog (§7). NO token access happens in this case.
	ErrUserCancelled = errors.New("openmdsignd: signing cancelled by user")

	// ErrUnsupportedSignFormat is returned for a signFormat the Signer cannot map
	// to a profile (the handler already rejects unknown formats at parse time;
	// this guards the Signer as a standalone unit).
	ErrUnsupportedSignFormat = errors.New("openmdsignd: unsupported signFormat")
)

// authChallengeMaxBytes bounds the "this is a pre-hashed mpass challenge, not a
// document" heuristic. The captured challenge was a 20-byte SHA-1 digest
// (PROTOCOL.md §5); a real document XAdES carries the full file in Data.
const authChallengeMaxBytes = 64

// authChallengeInputName is the neutral basename used to label the enveloping
// FileObject reference for the mpass auth challenge. The vendor leaks a local
// path here (…\signData_*.tmp); we deliberately do NOT — no filesystem path ever
// reaches the signature.
const authChallengeInputName = "authentication-challenge"

// ConfirmRequest describes WHAT is about to be signed, for the synchronous
// per-operation confirmation dialog (PROTOCOL.md §7). It names the requesting
// Origin so the user consciously authorizes THIS site's THIS operation.
type ConfirmRequest struct {
	// Origin is the requesting site (e.g. https://msign.gov.md). May be empty.
	Origin string
	// ContentType is the §4.2 contentType ("Pdf" | "Text").
	ContentType string
	// SignFormat is the §4.2 signFormat ("PAdES-T" | "XAdES-T").
	SignFormat string
	// Filename is a best-effort display name for the payload (the protocol does
	// not carry one; the Signer synthesizes it from ContentType).
	Filename string
	// IsAuth is true for the mpass.gov.md authentication/login challenge (a short
	// SHA-1 pre-hash, not a document). The confirmation dialog uses it to tell the
	// user this authorizes a LOGIN to the requesting Origin, not a document
	// signature.
	IsAuth bool
}

// Confirmer performs the synchronous per-operation confirmation AND collects the
// PIN in one step (§7). It is the single seam that keeps osascript out of tests:
// the production implementation shells out to a native macOS dialog, while tests
// inject a fake. A denial/cancel MUST be reported as ErrUserCancelled so no token
// access is attempted. The returned PIN is handed straight to the single C_Login
// and scrubbed immediately after; a Confirmer MUST NOT retain or log it.
type Confirmer interface {
	Confirm(ctx context.Context, req ConfirmRequest) (pin string, err error)
}

// TokenSignerConfig configures a TokenSigner. All paths come from daemon config
// / flags; none is hardcoded or redistributed.
type TokenSignerConfig struct {
	// ModulePath is the vendor PKCS#11 module (.dylib) path. Required.
	ModulePath string
	// ChainPEM is a PEM bundle of the issuer chain (issuing CA + root) embedded
	// in the PAdES CMS. Absence is a warning (chain-incomplete signature).
	ChainPEM string
	// DSSHelperJar is the EU DSS helper jar path (required for XAdES document
	// signing). Absence surfaces only when a XAdES job is attempted.
	DSSHelperJar string
	// TSAURL is the RFC 3161 TSA URL for the -T profiles. Empty ⇒ DefaultTSAURL.
	TSAURL string
	// JavaPath optionally pins the Java launcher for the XAdES helper. Empty
	// auto-resolves (OPENMDSIGN_JAVA / JAVA_HOME / PATH).
	JavaPath string
}

// TokenSigner is the production server.Signer: it wires the PAdES/XAdES profile
// signers behind POST /sign/data with the synchronous confirm + PIN gate (§7).
//
// It reuses internal/sign + internal/token through their exported interfaces
// only and never reshapes them. Token operations are serialized by mu because
// the hardware token is single-threaded: concurrent /sign/data requests queue.
type TokenSigner struct {
	cfg       TokenSignerConfig
	confirmer Confirmer
	log       *slog.Logger
	chain     []*x509.Certificate

	// mu serializes the whole confirm→login→sign operation. The token cannot
	// service two logins/signatures at once, so overlapping calls queue here.
	mu sync.Mutex
}

// NewTokenSigner builds the production Signer. confirmer must be non-nil (inject
// a real osascript Confirmer in production, a fake in tests). The issuer chain is
// loaded once here; a missing/empty chain logs a warning (matters for PAdES).
func NewTokenSigner(cfg TokenSignerConfig, confirmer Confirmer, log *slog.Logger) *TokenSigner {
	if log == nil {
		log = slog.Default()
	}
	if cfg.TSAURL == "" {
		cfg.TSAURL = DefaultTSAURL
	}
	ts := &TokenSigner{cfg: cfg, confirmer: confirmer, log: log}
	if cfg.ChainPEM != "" {
		chain, err := loadChainPEM(cfg.ChainPEM)
		if err != nil {
			log.Warn("could not load issuer chain PEM; PAdES signatures will embed the leaf only",
				"chain", cfg.ChainPEM, "err", err.Error())
		} else {
			ts.chain = chain
		}
	} else {
		log.Warn("no issuer chain PEM configured; PAdES signatures will embed the leaf only " +
			"(pass --chain a PEM bundle of the MoldSign issuing CA + root)")
	}
	return ts
}

// signParams is the profile-driven plan for one job, derived ONLY from
// signFormat + contentType (never from the untrusted Algorithm hint, §5).
type signParams struct {
	profile   string         // "pades" | "xades"
	level     sign.Level     // always LevelT for the observed -T profiles
	packaging sign.Packaging // XAdES only
	digest    string         // XAdES only; profile-driven, never the request hint
	formatSeg string         // Location path segment: "pdf" | "XAdES"
	inputName string         // synthesized display/basename (protocol carries none)
	isAuth    bool           // true ⇒ mpass authentication/login challenge
}

// mapSignFormat is the pure SignFormat→profile mapping. It is separated from the
// hardware path so it can be unit-tested exhaustively (including the auth path).
//
//   - "PAdES-T"                 → PAdES-T, SHA-256, input = full PDF, seg "pdf".
//   - "XAdES-T" (document)      → XAdES-T detached, SHA-256, seg "XAdES".
//   - "XAdES-T" (auth challenge)→ XAdES-T enveloping, SHA-1, seg "XAdES" (mpass).
//   - anything else             → ErrUnsupportedSignFormat.
func mapSignFormat(req SignRequest) (signParams, error) {
	switch req.SignFormat {
	case "PAdES-T":
		return signParams{
			profile:   "pades",
			level:     sign.LevelT,
			formatSeg: "pdf",
			inputName: "document.pdf",
		}, nil

	case "XAdES-T":
		// The mpass.gov.md authentication flow signs a short pre-hashed challenge
		// (a ~20-byte SHA-1 value, contentType "Text") as an ENVELOPING XAdES-T
		// with SHA-1 everywhere (PROTOCOL.md §5/§6, verified against the captured
		// auth.xades). SHA-1 is interop-required by the government protocol here;
		// it is NOT used for document signing.
		if isAuthChallenge(req) {
			return signParams{
				profile:   "xades",
				level:     sign.LevelT,
				packaging: sign.PackagingEnveloping,
				digest:    "sha1",
				formatSeg: "XAdES",
				inputName: authChallengeInputName,
				isAuth:    true,
			}, nil
		}
		// Document XAdES: a full document in Data, detached, SHA-256.
		return signParams{
			profile:   "xades",
			level:     sign.LevelT,
			packaging: sign.PackagingDetached,
			digest:    "sha256",
			formatSeg: "XAdES",
			inputName: xadesInputName(req.ContentType),
		}, nil

	default:
		return signParams{}, fmt.Errorf("%w %q (want PAdES-T or XAdES-T)",
			ErrUnsupportedSignFormat, req.SignFormat)
	}
}

// isAuthChallenge distinguishes the mpass authentication challenge from a real
// document XAdES. Heuristic: the payload is Text AND small (≤
// authChallengeMaxBytes, matching a ~20-byte SHA-1 pre-hash) AND not a PDF. A
// genuine document XAdES carries the full file bytes, which are larger and/or a
// recognizable document. The two profiles are otherwise disjoint: auth = Text +
// small pre-hash → SHA-1 enveloping; document XAdES → SHA-256 detached.
func isAuthChallenge(req SignRequest) bool {
	return req.ContentType == "Text" &&
		len(req.Data) > 0 &&
		len(req.Data) <= authChallengeMaxBytes &&
		!looksLikePDFBytes(req.Data)
}

// xadesInputName synthesizes a basename for the detached XAdES file:/ reference
// (the protocol carries no filename). It only ever influences the reference
// label, never a real local path.
func xadesInputName(contentType string) string {
	if contentType == "Pdf" {
		return "document.pdf"
	}
	return "document.txt"
}

// looksLikePDFBytes reports whether b begins with a %PDF- header (mirrors the
// PAdES profile's own check, kept local to avoid reshaping that package).
func looksLikePDFBytes(b []byte) bool {
	limit := 1024
	if len(b) < limit {
		limit = len(b)
	}
	return strings.Contains(string(b[:limit]), "%PDF-")
}

// Sign performs the whole synchronous operation for one /sign/data request:
// map the profile, confirm + collect the PIN (§7), open the token with EXACTLY
// ONE C_Login, produce the container, and return it base64-encoded. Token
// operations are serialized by mu.
func (ts *TokenSigner) Sign(ctx context.Context, req SignRequest) (SignResult, error) {
	params, err := mapSignFormat(req)
	if err != nil {
		ts.log.Warn("sign: unsupported request", "signFormat", req.SignFormat, "contentType", req.ContentType, "err", err.Error())
		return SignResult{}, err
	}
	ts.log.Info("sign: request accepted",
		"origin", req.Origin, "signFormat", req.SignFormat, "contentType", req.ContentType,
		"dataLen", len(req.Data), "profile", params.profile, "digest", params.digest,
		"packaging", string(params.packaging), "isAuth", params.isAuth)

	// Recover the on-token key: the CKA_ID hex from the verbatim certificateModel.
	keyID, err := certificateID(req.Certificate)
	if err != nil {
		ts.log.Warn("sign: could not read certificateId from request", "err", err.Error())
		return SignResult{}, err
	}

	// Serialize: the hardware token is single-threaded. Overlapping requests
	// queue here so no two logins/signatures ever race on the device.
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// ── §7 confirm + PIN gate — BEFORE any token access ──────────────────────
	// The dialog names the requesting Origin so the user authorizes THIS site.
	ts.log.Info("sign: prompting for confirmation + PIN", "origin", req.Origin, "isAuth", params.isAuth)
	pin, err := ts.confirmer.Confirm(ctx, ConfirmRequest{
		Origin:      req.Origin,
		ContentType: req.ContentType,
		SignFormat:  req.SignFormat,
		Filename:    params.inputName,
		IsAuth:      params.isAuth,
	})
	if err != nil {
		// A real user Cancel aborts before ANY token access — that is a normal
		// outcome, logged at info. A dialog that could NOT run (ErrConfirmUnavailable)
		// is a real failure the operator must see: log it loudly and return it as
		// itself (→ 500) rather than masquerading as a user cancel (the old bug
		// that made a broken dialog look like a silent decline).
		if errors.Is(err, ErrUserCancelled) {
			ts.log.Info("sign: declined by user at confirmation", "origin", req.Origin)
			return SignResult{}, ErrUserCancelled
		}
		ts.log.Error("sign: confirmation dialog could not run", "origin", req.Origin, "err", err.Error())
		return SignResult{}, err
	}

	ts.log.Info("sign: confirmed; opening token", "origin", req.Origin)
	res, err := ts.signWithToken(ctx, params, keyID, pin, req)
	if err != nil {
		ts.log.Warn("sign: token signing failed", "profile", params.profile, "err", err.Error())
	} else {
		ts.log.Info("sign: completed", "format", res.Format, "bytes", len(res.Base64File))
	}
	// Scrub our copy of the PIN as soon as the single login attempt is done.
	pin = strings.Repeat("x", len(pin))
	_ = pin
	return res, err
}

// signWithToken opens the token (one C_Login), runs the profile signer to a
// secure temp file, reads the bytes back, and returns the base64 result. The PIN
// is consumed here and scrubbed by the caller immediately after return.
func (ts *TokenSigner) signWithToken(ctx context.Context, params signParams, keyID, pin string, req SignRequest) (SignResult, error) {
	if ts.cfg.ModulePath == "" {
		return SignResult{}, fmt.Errorf("no PKCS#11 module configured for signing")
	}

	tctx, err := token.Load(ts.cfg.ModulePath)
	if err != nil {
		return SignResult{}, fmt.Errorf("load PKCS#11 module: %w", err)
	}
	defer tctx.Close()

	// EXACTLY ONE C_Login. On a *LoginError, DO NOT retry (the token can lock).
	signer, err := tctx.OpenSigner(token.SignerRequest{PIN: pin, KeyIDHex: keyID})
	if err != nil {
		var le *token.LoginError
		if errors.As(err, &le) {
			// Report a clear, PIN-free error. No retry, ever.
			ts.log.Warn("token login failed; NOT retrying (token can lock)", "ckr", le.CKR)
			return SignResult{}, fmt.Errorf("token login failed (%s); not retried to avoid locking the token", le.CKR)
		}
		return SignResult{}, fmt.Errorf("open token signer: %w", err)
	}
	defer signer.Close()

	// Write the container to a secure temp dir (MkdirTemp ⇒ 0700), read it back,
	// then delete it. This gets the bytes without reshaping sign.Result (which
	// only carries a path).
	dir, err := os.MkdirTemp("", "openmdsignd-sign-")
	if err != nil {
		return SignResult{}, fmt.Errorf("create secure temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	outPath := filepath.Join(dir, "container")

	var profileSigner sign.Signer
	switch {
	case params.profile == "pades":
		profileSigner = pades.New()
	case params.profile == "xades" && params.isAuth:
		// The mpass authentication XAdES-T is hand-built by our dedicated pure-Go
		// signer: DSS cannot produce its reference order (SignedProperties first)
		// nor its enveloped-file digest (SHA-1 over C14N of the <ds:Object>). The
		// document XAdES path below stays on DSS, byte-for-byte unchanged.
		profileSigner = xadesauth.New()
	case params.profile == "xades":
		profileSigner = xades.New(ts.cfg.JavaPath)
	default:
		return SignResult{}, fmt.Errorf("%w: internal profile %q", ErrUnsupportedSignFormat, params.profile)
	}

	if _, err := profileSigner.Sign(ctx, sign.Request{
		InputPDF:    req.Data,
		InputName:   params.inputName,
		OutputPath:  outPath,
		Signer:      signer,
		Certificate: signer.Certificate(),
		Chain:       ts.chain,
		Level:       params.level,
		TSAURL:      ts.cfg.TSAURL,
		Packaging:   params.packaging,
		Digest:      params.digest,
		HelperJar:   ts.cfg.DSSHelperJar,
	}); err != nil {
		return SignResult{}, fmt.Errorf("%s signing failed: %w", params.profile, err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		return SignResult{}, fmt.Errorf("read signed container: %w", err)
	}

	return SignResult{
		Format:     params.formatSeg,
		Base64File: base64.StdEncoding.EncodeToString(raw),
	}, nil
}

// certificateID extracts certificateId (the CKA_ID hex) from the verbatim
// certificateModel JSON object POSTed in §4.2.
func certificateID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("missing certificate object")
	}
	var cm struct {
		CertificateID string `json:"certificateId"`
	}
	if err := json.Unmarshal(raw, &cm); err != nil {
		return "", fmt.Errorf("parse certificate object: %w", err)
	}
	if cm.CertificateID == "" {
		return "", fmt.Errorf("certificate object has no certificateId (CKA_ID) to select the key")
	}
	return cm.CertificateID, nil
}

// loadChainPEM reads a PEM bundle and returns the certificates in file order.
// It mirrors the CLI's loader (cmd/openmdsign/sign.go); that copy lives in
// package main and is not importable, so this is a local equivalent.
func loadChainPEM(path string) ([]*x509.Certificate, error) {
	rawPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read chain %q: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := rawPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate in chain %q: %w", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("chain %q contained no PEM CERTIFICATE blocks", path)
	}
	return certs, nil
}
