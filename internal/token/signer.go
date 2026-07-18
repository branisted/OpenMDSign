package token

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
)

// Signer adapts a hardware PKCS#11 signing key to Go's crypto.Signer, so that
// higher-level AdES libraries (which expect a crypto.Signer) can drive the
// token without ever seeing a private key or a PIN.
//
// Lifetime & PIN policy: a Signer is produced by (*Ctx).OpenSigner, which opens
// a session and performs EXACTLY ONE C_Login before returning. The PIN is
// dropped the instant the login returns and is never stored on the Signer. The
// live login/session spans the whole signing operation; the caller MUST defer
// Close, which logs out and closes the session. The Signer NEVER logs in and
// NEVER retries a login -- that policy is owned entirely by the caller.
//
// Sign performs a raw CKM_RSA_PKCS operation over the PKCS#1 v1.5 DigestInfo
// (SHA-256 by default; SHA-1 for the mpass auth challenge), returning a standard
// RSASSA-PKCS1-v1_5 signature.
type Signer struct {
	ctx      *Ctx
	sess     pkcs11.SessionHandle
	key      pkcs11.ObjectHandle
	pub      crypto.PublicKey
	cert     *x509.Certificate
	keyIDHex string
	slotID   uint
	label    string
	closed   bool
}

// SignerRequest parameterises OpenSigner.
type SignerRequest struct {
	// PIN drives EXACTLY ONE C_Login. Never logged, never stored on the Signer.
	PIN string
	// SlotFilter, when non-nil, restricts to a single slot ID.
	SlotFilter *uint
	// TokenLabel, when non-empty, restricts to a token by label.
	TokenLabel string
	// KeyIDHex optionally selects the signing key/cert by CKA_ID (hex). When
	// empty, the single private key with CKA_SIGN=true is auto-selected.
	KeyIDHex string
}

// OpenSigner selects a present token, performs EXACTLY ONE C_Login, locates the
// signing key and its certificate, and returns a *Signer implementing
// crypto.Signer. The caller MUST call Close to log out and close the session.
//
// A failed login returns a *LoginError; the caller MUST NOT retry (the token
// can lock after a few attempts). The PIN is dropped as soon as login returns.
func (c *Ctx) OpenSigner(req SignerRequest) (*Signer, error) {
	slotID, label, err := c.selectSlot(req.SlotFilter, req.TokenLabel)
	if err != nil {
		return nil, err
	}

	sess, err := c.p.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("C_OpenSession on slot %d failed: %s", slotID, describeError(err))
	}

	// EXACTLY ONE C_Login. No retry loop anywhere.
	loginErr := c.p.Login(sess, pkcs11.CKU_USER, req.PIN)
	// Drop the PIN reference immediately; it is never stored on the Signer.
	req.PIN = ""
	if loginErr != nil {
		_ = c.p.CloseSession(sess)
		return nil, classifyLoginError(loginErr)
	}

	keyHandle, keyID, err := c.selectPrivateKey(sess, req.KeyIDHex)
	if err != nil {
		_ = c.p.Logout(sess)
		_ = c.p.CloseSession(sess)
		return nil, err
	}

	der, ok := c.findCertDERByID(sess, keyID)
	if !ok {
		_ = c.p.Logout(sess)
		_ = c.p.CloseSession(sess)
		return nil, fmt.Errorf("no certificate object found on the token for key CKA_ID %s; "+
			"a certificate is required to build the signature", keyID)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		_ = c.p.Logout(sess)
		_ = c.p.CloseSession(sess)
		return nil, fmt.Errorf("parse signing certificate (CKA_ID %s): %w", keyID, err)
	}

	return &Signer{
		ctx:      c,
		sess:     sess,
		key:      keyHandle,
		pub:      cert.PublicKey,
		cert:     cert,
		keyIDHex: keyID,
		slotID:   slotID,
		label:    label,
	}, nil
}

// Public returns the signing certificate's public key.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Certificate returns the signer's leaf certificate.
func (s *Signer) Certificate() *x509.Certificate { return s.cert }

// KeyIDHex returns the CKA_ID (hex) of the signing key that was located.
func (s *Signer) KeyIDHex() string { return s.keyIDHex }

// SlotID returns the slot the signer is bound to.
func (s *Signer) SlotID() uint { return s.slotID }

// TokenLabel returns the label of the token the signer is bound to.
func (s *Signer) TokenLabel() string { return s.label }

// Sign performs a raw RSASSA-PKCS1-v1_5 signature over digest using the on-token
// key. opts.HashFunc() selects the DigestInfo prefix:
//
//   - crypto.SHA256 (document PAdES/XAdES) — the general default.
//   - crypto.SHA1   (mpass authentication challenge ONLY) — mandated by the
//     government auth protocol for interop (PROTOCOL.md §5/§6); never used for
//     document signing.
//
// It builds the matching PKCS#1 v1.5 DigestInfo and signs it raw with
// CKM_RSA_PKCS, so the result is a standard RSASSA-PKCS1-v1_5 signature
// verifiable with rsa.VerifyPKCS1v15. rand is ignored (RSA PKCS#1 v1.5 is
// deterministic).
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.closed {
		return nil, fmt.Errorf("token signer already closed")
	}
	if opts == nil {
		return nil, fmt.Errorf("token signer: nil SignerOpts")
	}

	var payload []byte
	switch h := opts.HashFunc(); h {
	case crypto.SHA256:
		if len(digest) != crypto.SHA256.Size() {
			return nil, fmt.Errorf("token signer: digest length %d, expected %d for SHA-256", len(digest), crypto.SHA256.Size())
		}
		payload = DigestInfoSHA256(digest)
	case crypto.SHA1:
		if len(digest) != crypto.SHA1.Size() {
			return nil, fmt.Errorf("token signer: digest length %d, expected %d for SHA-1", len(digest), crypto.SHA1.Size())
		}
		payload = DigestInfoSHA1(digest)
	default:
		return nil, fmt.Errorf("token signer supports only SHA-256 (documents) or SHA-1 (mpass auth); got %v", hashName(opts))
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_RSA_PKCS, nil)}
	if err := s.ctx.p.SignInit(s.sess, mech, s.key); err != nil {
		return nil, fmt.Errorf("C_SignInit (CKM_RSA_PKCS) failed: %s", describeError(err))
	}
	sig, err := s.ctx.p.Sign(s.sess, payload)
	if err != nil {
		return nil, fmt.Errorf("C_Sign (CKM_RSA_PKCS) failed: %s", describeError(err))
	}
	return sig, nil
}

// Close logs out and closes the session. It is safe to call more than once.
func (s *Signer) Close() {
	if s == nil || s.closed || s.ctx == nil || s.ctx.p == nil {
		return
	}
	_ = s.ctx.p.Logout(s.sess)
	_ = s.ctx.p.CloseSession(s.sess)
	s.closed = true
}

func hashName(opts crypto.SignerOpts) string {
	if opts == nil {
		return "<nil>"
	}
	return opts.HashFunc().String()
}
