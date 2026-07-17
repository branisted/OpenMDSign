// Package sign defines the signing abstraction for openmdsign.
//
// Phase 0 ships ONLY the Signer interface and its supporting types. No concrete
// implementation exists yet: the signature profile (XAdES / CAdES / PAdES) used
// by the target infrastructure is still unknown and must be established by
// dissecting a reference signature (see docs/recon.md) before any signer is
// written. See docs/decisions.md for the pluggable-signer rationale.
package sign

import (
	"context"
	"errors"

	"github.com/miekg/pkcs11"
)

// ErrNotImplemented is returned by any placeholder signer. Concrete signers
// arrive in Phase 2.
var ErrNotImplemented = errors.New("openmdsign: signing not implemented in this phase")

// TokenHandle bundles the live PKCS#11 context and the session/private-key
// handles a Signer needs to perform on-token operations. It is produced by the
// internal/token package once a signing key has been located and (if required)
// a login has succeeded.
//
// A Signer MUST NOT itself perform login and MUST NOT retry a login: PIN policy
// is owned entirely by the caller (tokens lock after a few failed attempts).
type TokenHandle struct {
	Ctx        *pkcs11.Ctx
	Session    pkcs11.SessionHandle
	PrivateKey pkcs11.ObjectHandle
	// CertDER is the DER encoding of the signer's certificate, when known.
	CertDER []byte
}

// Request describes one signing operation.
type Request struct {
	// InputPath is the file to be signed.
	InputPath string
	// OutputPath is where the signed container should be written. When empty
	// the Signer chooses a path derived from InputPath and its profile.
	OutputPath string
	// Detached requests a detached signature where the profile supports it.
	Detached bool
}

// Result describes the outcome of a signing operation.
type Result struct {
	// OutputPath is the path of the signed container that was written.
	OutputPath string
	// Profile names the container profile that was produced
	// (e.g. "CAdES", "XAdES", "PAdES").
	Profile string
}

// Signer turns an input file plus a live token handle into a signed container.
//
// Implementations are pluggable so that a single CLI can target whichever
// container profile the reference infrastructure requires. This interface is
// intentionally the entire signing surface exposed in Phase 0.
type Signer interface {
	// Profile returns the container profile this Signer produces.
	Profile() string
	// Sign performs the signing operation. Implementations must treat tok as
	// read-mostly and must never attempt an additional C_Login.
	Sign(ctx context.Context, tok TokenHandle, req Request) (Result, error)
}
