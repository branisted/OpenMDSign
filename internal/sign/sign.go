// Package sign defines the pluggable signing abstraction for openmdsign.
//
// A Signer turns an input document plus an already-authenticated crypto.Signer
// into a signed AdES container. The profile (PAdES, XAdES, ...) is selected by
// the caller; each profile is a separate Signer implementation so a single CLI
// can target whichever container the reference infrastructure requires.
//
// Login policy is deliberately OUT of this interface: the caller performs the
// single permitted C_Login and hands in a ready crypto.Signer (see
// internal/token.Signer). A Signer implementation MUST NOT perform or retry a
// login, and MUST NOT store the PIN -- it never sees one. See docs/decisions.md.
package sign

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
)

// ErrNotImplemented is returned by a profile that is not yet available.
var ErrNotImplemented = errors.New("openmdsign: signing profile not implemented in this phase")

// Level selects the AdES baseline level.
type Level string

const (
	// LevelB is the baseline signature (no timestamp): PAdES-B-B.
	LevelB Level = "b"
	// LevelT adds an RFC 3161 signature timestamp: PAdES-B-T.
	LevelT Level = "t"
)

// Packaging selects how a XAdES signature relates to the signed data. It is
// consumed only by the XAdES profile; PAdES ignores it.
type Packaging string

const (
	// PackagingDetached references the signed file by URI (file:/<basename>),
	// digesting the raw file bytes. This is the primary XAdES packaging.
	PackagingDetached Packaging = "detached"
	// PackagingEnveloping embeds the base64 file in a trailing ds:Object.
	PackagingEnveloping Packaging = "enveloping"
)

// Request describes one signing operation.
//
// The Signer is an already-logged-in crypto.Signer (the token). Certificate is
// its leaf certificate; Chain is the issuer chain (issuing CA + root) used to
// embed a complete CMS certificate set. TSAURL is consulted only for LevelT.
type Request struct {
	// InputPDF is the raw bytes of the document to sign. Despite the name it
	// carries the input bytes for any profile (the XAdES profile signs the same
	// field's raw bytes); it predates the XAdES profile.
	InputPDF []byte
	// InputName is a display name for the input (never a local filesystem path
	// that could leak into signature metadata).
	InputName string
	// OutputPath is where the signed container is written.
	OutputPath string
	// Signer is the authenticated on-token key as a crypto.Signer.
	Signer crypto.Signer
	// Certificate is the signer's leaf certificate.
	Certificate *x509.Certificate
	// Chain is the issuer chain (issuing CA .. root), leaf excluded. May be nil.
	Chain []*x509.Certificate
	// Level selects b (no timestamp) or t (RFC 3161 timestamp).
	Level Level
	// TSAURL is the RFC 3161 timestamp authority URL (used only for LevelT).
	TSAURL string

	// --- XAdES-only fields (ignored by the PAdES profile) ---

	// Packaging selects detached (primary) or enveloping XAdES packaging.
	Packaging Packaging
	// Digest names the digest algorithm ("sha256" default; "sha1" reserved for
	// the future authentication challenge case). It is driven by profile, never
	// read from an untrusted request hint. See docs/ROADMAP.md.
	Digest string
	// HelperJar is the filesystem path to the EU DSS helper jar (dss-helper.jar)
	// that the XAdES profile shells out to. Required for XAdES.
	HelperJar string
}

// Result describes the outcome of a signing operation.
type Result struct {
	// OutputPath is the path of the signed container that was written.
	OutputPath string
	// Profile names the container profile that was produced (e.g. "PAdES").
	Profile string
	// Level is the baseline level actually produced.
	Level Level
	// TimestampApplied reports whether an RFC 3161 timestamp was embedded.
	TimestampApplied bool
	// Bytes is the size of the signed container written.
	Bytes int
}

// Signer turns an input document plus an authenticated crypto.Signer into a
// signed container. Implementations are pluggable per container profile and
// MUST NOT attempt any C_Login.
type Signer interface {
	// Profile returns the container profile this Signer produces.
	Profile() string
	// Sign performs the signing operation.
	Sign(ctx context.Context, req Request) (Result, error)
}
