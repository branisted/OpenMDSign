package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/branistedev/openmdsign/internal/token"
	"github.com/branistedev/openmdsign/internal/x509util"
)

// rawMechanism describes how a --mechanism value maps to an on-token operation.
type rawMechanism struct {
	// flag is the user-facing --mechanism value.
	flag string
	// ckm is the pkcs11 CKM_* code used for C_SignInit.
	ckm uint
	// onTokenHash is true when the token hashes the input (CKM_SHA256_RSA_PKCS);
	// false when Go builds the DigestInfo and the token signs it raw
	// (CKM_RSA_PKCS).
	onTokenHash bool
	// name is the symbolic CKM name for display.
	name string
}

// parseMechanism validates a --mechanism value.
func parseMechanism(s string) (rawMechanism, error) {
	switch s {
	case "sha256-rsa":
		return rawMechanism{flag: "sha256-rsa", ckm: token.CKM_SHA256_RSA_PKCS, onTokenHash: true, name: "CKM_SHA256_RSA_PKCS"}, nil
	case "rsa-pkcs":
		return rawMechanism{flag: "rsa-pkcs", ckm: token.CKM_RSA_PKCS, onTokenHash: false, name: "CKM_RSA_PKCS"}, nil
	default:
		return rawMechanism{}, fmt.Errorf("invalid --mechanism %q: expected \"sha256-rsa\" or \"rsa-pkcs\"", s)
	}
}

type signRawFlags struct {
	module     string
	slot       uint
	tokenLabel string
	keyID      string
	file       string
	out        string
	mechanism  string
	pin        string
	pinStdin   bool
	json       bool
}

func newSignRawCmd(gf *globalFlags) *cobra.Command {
	f := &signRawFlags{}
	cmd := &cobra.Command{
		Use:   "sign-raw",
		Short: "Sign a file's SHA-256 digest with the token and verify against its certificate",
		Long: "sign-raw is a crypto proof-of-life: it makes the hardware token produce a\n" +
			"raw RSASSA-PKCS1-v1_5 signature over a file's SHA-256 digest, headless on\n" +
			"macOS, then verifies that signature in-process against the certificate's\n" +
			"public key. This is NOT an AdES container -- it is a raw signature only.\n\n" +
			"Two mechanisms exercise the two token hand-off strategies used later by the\n" +
			"DSS integration:\n" +
			"  sha256-rsa  CKM_SHA256_RSA_PKCS -- the raw file bytes are sent; the token\n" +
			"              hashes and signs in one operation.\n" +
			"  rsa-pkcs    CKM_RSA_PKCS -- Go computes the SHA-256 DigestInfo and the\n" +
			"              token performs the raw signature over it.\n\n" +
			"A PIN is REQUIRED and is used for EXACTLY ONE login attempt with no retry:\n" +
			"the token can lock after a few failures. Never rerun blindly on failure.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSignRaw(cmd, gf, f)
		},
	}
	cmd.Flags().StringVar(&f.module, "module", "", "path to the PKCS#11 module (.dylib)")
	cmd.Flags().UintVar(&f.slot, "slot", 0, "restrict to a single slot ID")
	cmd.Flags().StringVar(&f.tokenLabel, "token-label", "", "restrict to a token by label")
	cmd.Flags().StringVar(&f.keyID, "key-id", "", "signing key/cert CKA_ID in hex (default: auto-select the single CKA_SIGN key)")
	cmd.Flags().StringVar(&f.file, "file", "", "path to the input file to sign (required)")
	cmd.Flags().StringVar(&f.out, "out", "", "path to write the raw signature (default ./sign-raw-out/<basename>.sig)")
	cmd.Flags().StringVar(&f.mechanism, "mechanism", "sha256-rsa", "signing mechanism: sha256-rsa | rsa-pkcs")
	cmd.Flags().StringVar(&f.pin, "pin", "", "user PIN (required). Prefer --pin-stdin")
	cmd.Flags().BoolVar(&f.pinStdin, "pin-stdin", false, "read the PIN from stdin (keeps it out of shell history)")
	cmd.Flags().BoolVar(&f.json, "json", false, "emit machine-readable JSON instead of text")
	cmd.MarkFlagsMutuallyExclusive("pin", "pin-stdin")
	return cmd
}

func runSignRaw(cmd *cobra.Command, gf *globalFlags, f *signRawFlags) error {
	if f.file == "" {
		return fmt.Errorf("--file is required")
	}
	mech, err := parseMechanism(f.mechanism)
	if err != nil {
		return err
	}

	// Config precedence: flags > config file > defaults.
	cfg, err := loadConfig(cmd, gf)
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("module") {
		cfg.Module = f.module
	}
	if cmd.Flags().Changed("slot") {
		s := f.slot
		cfg.Slot = &s
	}
	if cmd.Flags().Changed("token-label") {
		cfg.TokenLabel = f.tokenLabel
	}
	keyID := cfg.KeyID
	if cmd.Flags().Changed("key-id") {
		keyID = f.keyID
	}
	if cfg.Module == "" {
		return fmt.Errorf("no PKCS#11 module configured: pass --module <path> or set 'module' in the config file")
	}

	// Read the input file and compute its SHA-256 digest.
	data, err := os.ReadFile(f.file)
	if err != nil {
		return fmt.Errorf("read --file %q: %w", f.file, err)
	}
	digest := sha256.Sum256(data)

	// Choose the exact payload handed to C_Sign per the mechanism strategy.
	var payload []byte
	if mech.onTokenHash {
		payload = data // token hashes the raw file bytes
	} else {
		payload = token.DigestInfoSHA256(digest[:]) // token raw-signs the DigestInfo
	}

	// PIN is required. --pin-stdin preferred; the two are mutually exclusive.
	pin, hasPIN, err := resolvePIN(cmd, f.pin, f.pinStdin)
	if err != nil {
		return err
	}
	if !hasPIN {
		return fmt.Errorf("a PIN is required to sign: pass --pin-stdin (preferred) or --pin")
	}
	slog.Debug("sign-raw starting",
		"module", cfg.Module, "file", f.file, "mechanism", mech.flag,
		"bytes", len(data), "pin_provided", true)

	ctx, err := token.Load(cfg.Module)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		if hint := fileHint(cfg.Module); hint != "" {
			fmt.Fprintln(os.Stderr, "hint: "+hint)
		}
		return errSilent
	}
	defer ctx.Close()

	res, signErr := ctx.SignRaw(token.RawSignRequest{
		PIN:           pin,
		SlotFilter:    cfg.Slot,
		TokenLabel:    cfg.TokenLabel,
		KeyIDHex:      keyID,
		MechanismCode: mech.ckm,
		Payload:       payload,
	})
	// Scrub the PIN from local memory as soon as it is no longer needed.
	pin = strings.Repeat("x", len(pin))
	_ = pin

	if signErr != nil {
		var le *token.LoginError
		if errors.As(signErr, &le) {
			printLoginAbort(le)
			return errSilent
		}
		return signErr
	}

	// Verify the signature in-process against the certificate's public key.
	verifyErr, subject := verifySignature(res.CertDER, digest[:], res.Signature)

	if f.json {
		if err := emitSignRawJSON(res, mech, digest[:], subject, verifyErr); err != nil {
			return err
		}
	}

	// Write the signature bytes.
	outPath := f.out
	if outPath == "" {
		outPath = filepath.Join("sign-raw-out", filepath.Base(f.file)+".sig")
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create out dir for %q: %w", outPath, err)
	}
	if err := os.WriteFile(outPath, res.Signature, 0o644); err != nil {
		return fmt.Errorf("write signature %q: %w", outPath, err)
	}

	if !f.json {
		printSignRawText(res, mech, digest[:], subject, outPath, verifyErr)
	}

	if verifyErr != nil {
		return errSilent
	}
	return nil
}

// verifySignature verifies sig over digest using the certificate's RSA public
// key (RSASSA-PKCS1-v1_5, SHA-256). It returns the verification error (nil on
// success) and the certificate subject for display.
func verifySignature(certDER, digest, sig []byte) (error, string) {
	if len(certDER) == 0 {
		return fmt.Errorf("no certificate object found on the token for the signing key; cannot verify"), ""
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err), ""
	}
	subject := cert.Subject.String()
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is %T, expected RSA", cert.PublicKey), subject
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err), subject
	}
	return nil, subject
}

// printLoginAbort writes the safety-conscious abort message for a failed login.
// The PIN never appears here.
func printLoginAbort(le *token.LoginError) {
	w := os.Stderr
	fmt.Fprintf(w, "ABORT: login failed (%s).\n", le.CKR)
	switch {
	case le.Locked:
		fmt.Fprintln(w, "The PIN is LOCKED. It must be unlocked with the PUK on the physical device.")
	case le.Incorrect:
		fmt.Fprintln(w, "The PIN was incorrect.")
	}
	fmt.Fprintln(w, "DO NOT rerun blindly: the token typically locks after ~3 wrong attempts.")
	fmt.Fprintln(w, "Verify the correct PIN and check the remaining attempts on the physical device")
	fmt.Fprintln(w, "(e.g. run `openmdsign inspect` and look for CKF_USER_PIN_* flags) before retrying.")
}

func printSignRawText(res *token.RawSignResult, mech rawMechanism, digest []byte, subject, outPath string, verifyErr error) {
	w := os.Stdout
	fmt.Fprintln(w, "=== openmdsign sign-raw ===")
	fmt.Fprintf(w, "  Slot:           %d\n", res.SlotID)
	fmt.Fprintf(w, "  Token label:    %s\n", res.TokenLabel)
	fmt.Fprintf(w, "  Key CKA_ID:     %s\n", res.KeyIDHex)
	fmt.Fprintf(w, "  Mechanism:      %s (%s)\n", mech.flag, mech.name)
	if subject != "" {
		fmt.Fprintf(w, "  Cert subject:   %s\n", subject)
	}
	fmt.Fprintf(w, "  SHA-256 digest: %s\n", hex.EncodeToString(digest))
	fmt.Fprintf(w, "  Signature (hex):    %s\n", hex.EncodeToString(res.Signature))
	fmt.Fprintf(w, "  Signature (base64): %s\n", base64.StdEncoding.EncodeToString(res.Signature))
	fmt.Fprintf(w, "  Signature written:  %s (%d bytes)\n", outPath, len(res.Signature))
	if verifyErr == nil {
		fmt.Fprintln(w, "  Verify: PASS (signature verifies against the certificate public key)")
	} else {
		fmt.Fprintf(w, "  Verify: FAIL -- %v\n", verifyErr)
	}
}

func emitSignRawJSON(res *token.RawSignResult, mech rawMechanism, digest []byte, subject string, verifyErr error) error {
	out := map[string]any{
		"slot":             res.SlotID,
		"token_label":      res.TokenLabel,
		"key_id_hex":       res.KeyIDHex,
		"mechanism":        mech.flag,
		"mechanism_ckm":    mech.name,
		"cert_subject":     subject,
		"digest_sha256":    hex.EncodeToString(digest),
		"signature_hex":    hex.EncodeToString(res.Signature),
		"signature_base64": base64.StdEncoding.EncodeToString(res.Signature),
		"signature_bytes":  len(res.Signature),
		"verify_pass":      verifyErr == nil,
	}
	if verifyErr != nil {
		out["verify_error"] = verifyErr.Error()
	}
	if len(res.CertDER) > 0 {
		if ci, err := x509util.Parse(res.CertDER); err == nil {
			out["certificate"] = ci
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
