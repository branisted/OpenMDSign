// Package token provides read-only PKCS#11 access for the `openmdsign inspect`
// recon harness. It loads a vendor PKCS#11 module via the standard Cryptoki C
// interface (github.com/miekg/pkcs11) and enumerates slots, tokens, mechanisms
// and objects.
//
// Safety invariants enforced here:
//   - The module path is always supplied by the caller; nothing is hardcoded.
//   - A PIN, if provided, is used for EXACTLY ONE C_Login attempt. There is no
//     retry loop anywhere: hardware tokens typically lock after ~3 failures.
//   - A PIN is never written to a log, error, or any Report field.
package token

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

// ErrLoginFailed signals that the single permitted C_Login attempt failed. The
// caller must NOT retry; doing so blindly risks locking the token.
var ErrLoginFailed = errors.New("login failed")

// Report is the full result of an inspection.
type Report struct {
	Module  string      `json:"module"`
	Library LibraryInfo `json:"library"`
	Slots   []Slot      `json:"slots"`
	Note    string      `json:"note,omitempty"`
}

// LibraryInfo mirrors CK_INFO from C_GetInfo.
type LibraryInfo struct {
	Manufacturer    string `json:"manufacturer"`
	Description     string `json:"description"`
	CryptokiVersion string `json:"cryptoki_version"`
	LibraryVersion  string `json:"library_version"`
	Flags           uint   `json:"flags"`
}

// Slot mirrors CK_SLOT_INFO plus any present token and its details.
type Slot struct {
	ID           uint        `json:"id"`
	Description  string      `json:"description"`
	Manufacturer string      `json:"manufacturer"`
	Flags        []string    `json:"flags"`
	TokenPresent bool        `json:"token_present"`
	Token        *TokenInfo  `json:"token,omitempty"`
	Mechanisms   []Mechanism `json:"mechanisms,omitempty"`
	Objects      []Object    `json:"objects,omitempty"`
	Login        *LoginInfo  `json:"login,omitempty"`
	// SignatureMechs summarizes which signing-relevant mechanisms are present.
	SignatureMechs *SigMechSummary `json:"signature_mechanisms,omitempty"`
	Warnings       []string        `json:"warnings,omitempty"`
}

// TokenInfo mirrors CK_TOKEN_INFO.
type TokenInfo struct {
	Label        string   `json:"label"`
	Manufacturer string   `json:"manufacturer"`
	Model        string   `json:"model"`
	SerialNumber string   `json:"serial_number"`
	Flags        []string `json:"flags"`
}

// Mechanism is one supported mechanism with its key-size range and flags.
type Mechanism struct {
	Code       uint     `json:"code"`
	Name       string   `json:"name"`
	MinKeySize uint     `json:"min_key_size"`
	MaxKeySize uint     `json:"max_key_size"`
	Flags      []string `json:"flags"`
}

// SigMechSummary answers the specific questions the recon phase cares about.
type SigMechSummary struct {
	HasSHA256RSAPKCS    bool `json:"has_ckm_sha256_rsa_pkcs"`
	HasRSAPKCS          bool `json:"has_ckm_rsa_pkcs"`
	HasRSAPKCSPSS       bool `json:"has_ckm_rsa_pkcs_pss"`
	HasSHA256RSAPKCSPSS bool `json:"has_ckm_sha256_rsa_pkcs_pss"`
	HasSHA256           bool `json:"has_ckm_sha256"`
}

// Object is a PKCS#11 object discovered on the token.
type Object struct {
	Class       string `json:"class"`
	IDHex       string `json:"id_hex,omitempty"`
	Label       string `json:"label,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
	ModulusBits uint   `json:"modulus_bits,omitempty"`
	CanSign     *bool  `json:"can_sign,omitempty"`
	// CertDER holds the DER of a certificate object; not serialized to JSON.
	CertDER []byte `json:"-"`
}

// LoginInfo records the outcome of the single login attempt.
type LoginInfo struct {
	Attempted bool   `json:"attempted"`
	Succeeded bool   `json:"succeeded"`
	Error     string `json:"error,omitempty"`
}

// Options control an inspection.
type Options struct {
	// PIN, when HasPIN is true, is used for exactly one C_Login per token.
	PIN    string
	HasPIN bool
	// SlotFilter, when non-nil, restricts inspection to one slot ID.
	SlotFilter *uint
	// TokenLabel, when non-empty, restricts inspection to a token by label.
	TokenLabel string
}

// Ctx wraps a loaded PKCS#11 module.
type Ctx struct {
	p      *pkcs11.Ctx
	module string
}

// Load loads and initializes the PKCS#11 module at path. The returned Ctx must
// be Closed by the caller.
func Load(path string) (*Ctx, error) {
	p := pkcs11.New(path)
	if p == nil {
		return nil, fmt.Errorf("could not load PKCS#11 module %q (dlopen failed): "+
			"check the file exists and its architecture matches this binary "+
			"(run: file %q)", path, path)
	}
	if err := p.Initialize(); err != nil {
		p.Destroy()
		return nil, fmt.Errorf("C_Initialize failed for %q: %s", path, describeError(err))
	}
	return &Ctx{p: p, module: path}, nil
}

// Close finalizes and unloads the module.
func (c *Ctx) Close() {
	if c == nil || c.p == nil {
		return
	}
	_ = c.p.Finalize()
	c.p.Destroy()
	c.p = nil
}

// Inspect performs a full read-only inspection and returns a Report.
//
// Fatal infrastructure failures (e.g. C_GetInfo) return an error. A failed
// login is NOT a fatal error at this level: it is recorded in the slot's
// LoginInfo and the caller decides the process exit code. This keeps the login
// to a single attempt with no retry.
func (c *Ctx) Inspect(opts Options) (*Report, error) {
	info, err := c.p.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("C_GetInfo failed: %s", describeError(err))
	}
	rep := &Report{
		Module: c.module,
		Library: LibraryInfo{
			Manufacturer:    trim(info.ManufacturerID),
			Description:     trim(info.LibraryDescription),
			CryptokiVersion: verString(info.CryptokiVersion),
			LibraryVersion:  verString(info.LibraryVersion),
			Flags:           info.Flags,
		},
	}

	slotIDs, err := c.p.GetSlotList(false)
	if err != nil {
		return nil, fmt.Errorf("C_GetSlotList failed: %s", describeError(err))
	}
	if len(slotIDs) == 0 {
		rep.Note = "no slots reported by the module (is a reader/token connected?)"
		return rep, nil
	}

	for _, id := range slotIDs {
		if opts.SlotFilter != nil && *opts.SlotFilter != id {
			continue
		}
		slot := c.inspectSlot(id, opts)
		if slot != nil {
			rep.Slots = append(rep.Slots, *slot)
		}
	}
	if len(rep.Slots) == 0 {
		rep.Note = "no matching slots"
	}
	return rep, nil
}

func (c *Ctx) inspectSlot(id uint, opts Options) *Slot {
	si, err := c.p.GetSlotInfo(id)
	if err != nil {
		return &Slot{ID: id, Description: "<C_GetSlotInfo failed: " + describeError(err) + ">"}
	}
	slot := &Slot{
		ID:           id,
		Description:  trim(si.SlotDescription),
		Manufacturer: trim(si.ManufacturerID),
		Flags:        slotFlagStrings(si.Flags),
		TokenPresent: si.Flags&pkcs11.CKF_TOKEN_PRESENT != 0,
	}
	if !slot.TokenPresent {
		return slot
	}

	ti, err := c.p.GetTokenInfo(id)
	if err != nil {
		slot.Warnings = append(slot.Warnings, "C_GetTokenInfo failed: "+describeError(err))
		return slot
	}
	slot.Token = &TokenInfo{
		Label:        trim(ti.Label),
		Manufacturer: trim(ti.ManufacturerID),
		Model:        trim(ti.Model),
		SerialNumber: trim(ti.SerialNumber),
		Flags:        tokenFlagStrings(ti.Flags),
	}
	// Surface dangerous PIN states prominently.
	if ti.Flags&pkcs11.CKF_USER_PIN_LOCKED != 0 {
		slot.Warnings = append(slot.Warnings, "USER PIN IS LOCKED (CKF_USER_PIN_LOCKED) — do NOT attempt a PIN")
	}
	if ti.Flags&pkcs11.CKF_USER_PIN_FINAL_TRY != 0 {
		slot.Warnings = append(slot.Warnings, "USER PIN ON FINAL TRY (CKF_USER_PIN_FINAL_TRY) — a wrong PIN will LOCK the token")
	}
	if ti.Flags&pkcs11.CKF_USER_PIN_COUNT_LOW != 0 {
		slot.Warnings = append(slot.Warnings, "USER PIN failure count is low (CKF_USER_PIN_COUNT_LOW)")
	}

	if opts.TokenLabel != "" && slot.Token.Label != opts.TokenLabel {
		return nil
	}

	slot.Mechanisms, slot.SignatureMechs = c.inspectMechanisms(id)

	// Read-only session for object enumeration.
	sess, err := c.p.OpenSession(id, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		slot.Warnings = append(slot.Warnings, "OpenSession failed: "+describeError(err))
		return slot
	}
	defer c.p.CloseSession(sess)

	// Public objects — no login required.
	slot.Objects = append(slot.Objects, c.findObjects(sess, pkcs11.CKO_CERTIFICATE, false)...)
	slot.Objects = append(slot.Objects, c.findObjects(sess, pkcs11.CKO_PUBLIC_KEY, false)...)

	// Private objects — require login. EXACTLY ONE attempt, no retry.
	if opts.HasPIN {
		slot.Login = c.attemptLoginAndListPrivate(sess, opts.PIN, slot)
	}
	return slot
}

func (c *Ctx) inspectMechanisms(id uint) ([]Mechanism, *SigMechSummary) {
	list, err := c.p.GetMechanismList(id)
	if err != nil {
		return nil, nil
	}
	sum := &SigMechSummary{}
	var out []Mechanism
	for _, m := range list {
		code := m.Mechanism
		mi, err := c.p.GetMechanismInfo(id, []*pkcs11.Mechanism{pkcs11.NewMechanism(code, nil)})
		mech := Mechanism{Code: code, Name: MechName(code)}
		if err == nil {
			mech.MinKeySize = mi.MinKeySize
			mech.MaxKeySize = mi.MaxKeySize
			mech.Flags = mechFlagStrings(mi.Flags)
		}
		out = append(out, mech)
		switch code {
		case pkcs11.CKM_SHA256_RSA_PKCS:
			sum.HasSHA256RSAPKCS = true
		case pkcs11.CKM_RSA_PKCS:
			sum.HasRSAPKCS = true
		case pkcs11.CKM_RSA_PKCS_PSS:
			sum.HasRSAPKCSPSS = true
		case pkcs11.CKM_SHA256_RSA_PKCS_PSS:
			sum.HasSHA256RSAPKCSPSS = true
		case pkcs11.CKM_SHA256:
			sum.HasSHA256 = true
		}
	}
	return out, sum
}

// findObjects enumerates objects of a given class. When withPrivateDetail is
// true it additionally reads private-key attributes (requires an active login).
func (c *Ctx) findObjects(sess pkcs11.SessionHandle, class uint, withPrivateDetail bool) []Object {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if err := c.p.FindObjectsInit(sess, template); err != nil {
		return nil
	}
	handles, _, err := c.p.FindObjects(sess, 1024)
	_ = c.p.FindObjectsFinal(sess)
	if err != nil {
		return nil
	}
	var out []Object
	for _, h := range handles {
		out = append(out, c.readObject(sess, h, class, withPrivateDetail))
	}
	return out
}

func (c *Ctx) readObject(sess pkcs11.SessionHandle, h pkcs11.ObjectHandle, class uint, withPrivateDetail bool) Object {
	obj := Object{Class: objectClassName(class)}
	if id, ok := c.getAttr(sess, h, pkcs11.CKA_ID); ok && len(id) > 0 {
		obj.IDHex = hex.EncodeToString(id)
	}
	if lbl, ok := c.getAttr(sess, h, pkcs11.CKA_LABEL); ok {
		obj.Label = string(lbl)
	}
	switch class {
	case pkcs11.CKO_CERTIFICATE:
		if der, ok := c.getAttr(sess, h, pkcs11.CKA_VALUE); ok {
			obj.CertDER = der
		}
	case pkcs11.CKO_PUBLIC_KEY, pkcs11.CKO_PRIVATE_KEY:
		if kt, ok := c.getAttr(sess, h, pkcs11.CKA_KEY_TYPE); ok {
			obj.KeyType = keyTypeName(bytesToUint(kt))
		}
		if mb, ok := c.getAttr(sess, h, pkcs11.CKA_MODULUS_BITS); ok {
			obj.ModulusBits = uint(bytesToUint(mb))
		} else if mod, ok := c.getAttr(sess, h, pkcs11.CKA_MODULUS); ok {
			obj.ModulusBits = uint(len(mod) * 8)
		}
	}
	if withPrivateDetail && class == pkcs11.CKO_PRIVATE_KEY {
		if s, ok := c.getAttr(sess, h, pkcs11.CKA_SIGN); ok {
			v := len(s) > 0 && s[0] != 0
			obj.CanSign = &v
		}
	}
	return obj
}

// attemptLoginAndListPrivate performs the single permitted C_Login. On success
// it lists private keys and logs out. On failure it records the error; the
// caller must not retry.
func (c *Ctx) attemptLoginAndListPrivate(sess pkcs11.SessionHandle, pin string, slot *Slot) *LoginInfo {
	li := &LoginInfo{Attempted: true}
	err := c.p.Login(sess, pkcs11.CKU_USER, pin)
	// Immediately drop the PIN reference; it is never stored.
	pin = ""
	_ = pin
	if err != nil {
		li.Error = describeError(err)
		switch {
		case isPINIncorrect(err):
			slot.Warnings = append(slot.Warnings,
				"LOGIN FAILED: PIN incorrect. DO NOT RETRY — the token locks after a few failures. "+
					"Check remaining attempts on the physical device before trying again.")
		case isPINLocked(err):
			slot.Warnings = append(slot.Warnings,
				"LOGIN FAILED: PIN is LOCKED. The token must be unlocked with its PUK.")
		default:
			slot.Warnings = append(slot.Warnings, "LOGIN FAILED: "+li.Error+" (not retrying)")
		}
		return li
	}
	li.Succeeded = true
	defer c.p.Logout(sess)
	slot.Objects = append(slot.Objects, c.findObjects(sess, pkcs11.CKO_PRIVATE_KEY, true)...)
	return li
}

// getAttr reads a single attribute, tolerating unsupported/absent attributes.
func (c *Ctx) getAttr(sess pkcs11.SessionHandle, h pkcs11.ObjectHandle, attrType uint) ([]byte, bool) {
	attrs, err := c.p.GetAttributeValue(sess, h, []*pkcs11.Attribute{
		pkcs11.NewAttribute(attrType, nil),
	})
	if err != nil || len(attrs) == 0 {
		return nil, false
	}
	return attrs[0].Value, true
}
