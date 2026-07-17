package token

import (
	"encoding/hex"
	"fmt"

	"github.com/miekg/pkcs11"
)

// LoginError classifies the outcome of the single permitted C_Login attempt.
//
// It exists so callers can print a precise, safety-conscious abort message
// (naming the CKR_* code and warning against blind retries) WITHOUT ever seeing
// or logging the PIN. A LoginError never carries any PIN material.
type LoginError struct {
	// CKR is the symbolic CKR_* name (with hex) of the failure.
	CKR string
	// Incorrect is true for CKR_PIN_INCORRECT.
	Incorrect bool
	// Locked is true for CKR_PIN_LOCKED.
	Locked bool
}

func (e *LoginError) Error() string {
	return "C_Login failed: " + e.CKR
}

// RawSignRequest describes a single raw-signature operation.
//
// The caller decides the exact bytes handed to C_Sign via Payload and picks the
// on-token MechanismCode. For CKM_SHA256_RSA_PKCS, Payload is the raw file bytes
// (the token hashes). For CKM_RSA_PKCS, Payload is the pre-built PKCS#1 v1.5
// DigestInfo (the token performs the raw modular exponentiation only).
type RawSignRequest struct {
	// PIN drives EXACTLY ONE C_Login. Never logged, never stored.
	PIN string
	// SlotFilter, when non-nil, restricts to a single slot ID.
	SlotFilter *uint
	// TokenLabel, when non-empty, restricts to a token by label.
	TokenLabel string
	// KeyIDHex optionally selects the signing key/cert by CKA_ID (hex). When
	// empty, the single private key with CKA_SIGN=true is auto-selected.
	KeyIDHex string
	// MechanismCode is the pkcs11 CKM_* code to sign with.
	MechanismCode uint
	// Payload is the exact byte string passed to C_Sign.
	Payload []byte
}

// RawSignResult is the outcome of a successful raw-signature operation.
type RawSignResult struct {
	// Signature is the raw signature bytes returned by C_Sign.
	Signature []byte
	// KeyIDHex is the CKA_ID (hex) of the private key that was used.
	KeyIDHex string
	// CertDER is the DER of the certificate object matching the key (may be
	// empty if no certificate object shares the key's CKA_ID).
	CertDER []byte
	// SlotID and TokenLabel identify where the signature was produced.
	SlotID     uint
	TokenLabel string
}

// SignRaw locates a signing key on a present token, performs EXACTLY ONE
// C_Login, signs Payload with the requested mechanism, then logs out and closes
// the session. It never retries login and never logs the PIN.
//
// A failed login returns a *LoginError; the caller MUST NOT retry.
func (c *Ctx) SignRaw(req RawSignRequest) (*RawSignResult, error) {
	slotID, label, err := c.selectSlot(req.SlotFilter, req.TokenLabel)
	if err != nil {
		return nil, err
	}

	sess, err := c.p.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("C_OpenSession on slot %d failed: %s", slotID, describeError(err))
	}
	defer c.p.CloseSession(sess)

	// EXACTLY ONE C_Login. No retry loop anywhere.
	loginErr := c.p.Login(sess, pkcs11.CKU_USER, req.PIN)
	// Drop the PIN reference immediately; it is never stored on the result.
	req.PIN = ""
	if loginErr != nil {
		return nil, classifyLoginError(loginErr)
	}
	// Always log out, even on later error paths.
	defer c.p.Logout(sess)

	keyHandle, keyID, err := c.selectPrivateKey(sess, req.KeyIDHex)
	if err != nil {
		return nil, err
	}

	res := &RawSignResult{KeyIDHex: keyID, SlotID: slotID, TokenLabel: label}
	if der, ok := c.findCertDERByID(sess, keyID); ok {
		res.CertDER = der
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(req.MechanismCode, nil)}
	if err := c.p.SignInit(sess, mech, keyHandle); err != nil {
		return nil, fmt.Errorf("C_SignInit (%s) failed: %s", MechName(req.MechanismCode), describeError(err))
	}
	sig, err := c.p.Sign(sess, req.Payload)
	if err != nil {
		return nil, fmt.Errorf("C_Sign (%s) failed: %s", MechName(req.MechanismCode), describeError(err))
	}
	res.Signature = sig
	return res, nil
}

// selectSlot picks the single slot that has a token present and matches the
// optional filters. It errors clearly when no token is present, or when the
// selection is ambiguous (so the caller can pass --slot).
func (c *Ctx) selectSlot(slotFilter *uint, tokenLabel string) (uint, string, error) {
	// GetSlotList(true) => only slots with a token present.
	slotIDs, err := c.p.GetSlotList(true)
	if err != nil {
		return 0, "", fmt.Errorf("C_GetSlotList failed: %s", describeError(err))
	}
	type cand struct {
		id    uint
		label string
	}
	var cands []cand
	for _, id := range slotIDs {
		if slotFilter != nil && *slotFilter != id {
			continue
		}
		label := ""
		if ti, err := c.p.GetTokenInfo(id); err == nil {
			label = trim(ti.Label)
		}
		if tokenLabel != "" && label != tokenLabel {
			continue
		}
		cands = append(cands, cand{id: id, label: label})
	}
	switch {
	case len(cands) == 0:
		if slotFilter != nil || tokenLabel != "" {
			return 0, "", fmt.Errorf("no token present matching the requested slot/label filter")
		}
		return 0, "", fmt.Errorf("no token present in any slot (is the hardware token plugged in?)")
	case len(cands) > 1:
		var ids []string
		for _, cd := range cands {
			ids = append(ids, fmt.Sprintf("slot %d (label %q)", cd.id, cd.label))
		}
		return 0, "", fmt.Errorf("multiple tokens present; disambiguate with --slot or --token-label: %v", ids)
	}
	return cands[0].id, cands[0].label, nil
}

// selectPrivateKey finds the signing private key. When keyIDHex is set it must
// match a private key's CKA_ID. Otherwise the single private key with
// CKA_SIGN=true is used; if there is not exactly one such key it errors and
// lists the candidates so the caller can pass --key-id.
func (c *Ctx) selectPrivateKey(sess pkcs11.SessionHandle, keyIDHex string) (pkcs11.ObjectHandle, string, error) {
	if keyIDHex != "" {
		id, err := hex.DecodeString(keyIDHex)
		if err != nil {
			return 0, "", fmt.Errorf("invalid --key-id %q: not valid hex: %w", keyIDHex, err)
		}
		tmpl := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
		handles, err := c.findHandles(sess, tmpl)
		if err != nil {
			return 0, "", err
		}
		if len(handles) == 0 {
			return 0, "", fmt.Errorf("no private key found with CKA_ID %s", keyIDHex)
		}
		return handles[0], keyIDHex, nil
	}

	// Auto-select: the single private key with CKA_SIGN=true.
	handles, err := c.findHandles(sess, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	})
	if err != nil {
		return 0, "", err
	}
	type keyCand struct {
		handle pkcs11.ObjectHandle
		idHex  string
	}
	var cands []keyCand
	var allIDs []string
	for _, h := range handles {
		idHex := ""
		if id, ok := c.getAttr(sess, h, pkcs11.CKA_ID); ok && len(id) > 0 {
			idHex = hex.EncodeToString(id)
		}
		allIDs = append(allIDs, idHex)
		canSign := false
		if s, ok := c.getAttr(sess, h, pkcs11.CKA_SIGN); ok {
			canSign = len(s) > 0 && s[0] != 0
		}
		if canSign {
			cands = append(cands, keyCand{handle: h, idHex: idHex})
		}
	}
	switch {
	case len(cands) == 1:
		return cands[0].handle, cands[0].idHex, nil
	case len(cands) == 0:
		return 0, "", fmt.Errorf("no private key with CKA_SIGN=true found on the token (candidates by CKA_ID: %v)", allIDs)
	default:
		var ids []string
		for _, cd := range cands {
			ids = append(ids, cd.idHex)
		}
		return 0, "", fmt.Errorf("multiple signing private keys found; select one with --key-id (candidates: %v)", ids)
	}
}

// findCertDERByID returns the DER of the certificate object whose CKA_ID equals
// keyIDHex, if one exists.
func (c *Ctx) findCertDERByID(sess pkcs11.SessionHandle, keyIDHex string) ([]byte, bool) {
	id, err := hex.DecodeString(keyIDHex)
	if err != nil || len(id) == 0 {
		return nil, false
	}
	handles, err := c.findHandles(sess, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
	if err != nil || len(handles) == 0 {
		return nil, false
	}
	if der, ok := c.getAttr(sess, handles[0], pkcs11.CKA_VALUE); ok && len(der) > 0 {
		return der, true
	}
	return nil, false
}

// findHandles runs a single FindObjects pass for the given template.
func (c *Ctx) findHandles(sess pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := c.p.FindObjectsInit(sess, tmpl); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit failed: %s", describeError(err))
	}
	handles, _, err := c.p.FindObjects(sess, 1024)
	finalErr := c.p.FindObjectsFinal(sess)
	if err != nil {
		return nil, fmt.Errorf("C_FindObjects failed: %s", describeError(err))
	}
	if finalErr != nil {
		return nil, fmt.Errorf("C_FindObjectsFinal failed: %s", describeError(finalErr))
	}
	return handles, nil
}

// classifyLoginError turns a raw C_Login error into a *LoginError with the
// CKR name and classification flags. It carries no PIN material.
func classifyLoginError(err error) *LoginError {
	return &LoginError{
		CKR:       describeError(err),
		Incorrect: isPINIncorrect(err),
		Locked:    isPINLocked(err),
	}
}
