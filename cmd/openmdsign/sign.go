package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/branistedev/openmdsign/internal/sign"
	"github.com/branistedev/openmdsign/internal/sign/pades"
	"github.com/branistedev/openmdsign/internal/sign/xades"
	"github.com/branistedev/openmdsign/internal/token"
)

// defaultTSAURL is the observed MoldSign RFC 3161 timestamp authority.
const defaultTSAURL = "http://tsp.pki.gov.md/moldsign2/"

// defaultDSSHelperJar is the conventional build location of the EU DSS helper
// jar, relative to the repo root (where `mvn package` writes it).
const defaultDSSHelperJar = "java/dss-helper/target/dss-helper.jar"

type signFlags struct {
	module     string
	slot       uint
	tokenLabel string
	keyID      string
	file       string
	out        string
	profile    string
	level      string
	packaging  string
	digest     string
	tsaURL     string
	chain      string
	dssHelper  string
	pin        string
	pinStdin   bool
	json       bool
}

func newSignCmd(gf *globalFlags) *cobra.Command {
	f := &signFlags{}
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a document with the token into an AdES container (PAdES for PDF, XAdES otherwise)",
		Long: "sign produces a real AdES signature with the hardware token.\n\n" +
			"For a PDF input it produces a PAdES-B-T signature: an embedded CMS\n" +
			"(/SubFilter /ETSI.CAdES.detached) over a single /ByteRange, with SHA-256,\n" +
			"the ESS signingCertificateV2 signed attribute, and (level t) an RFC 3161\n" +
			"signature timestamp from the TSA.\n\n" +
			"For any other input it produces a standalone XAdES signature (ETSI TS 101\n" +
			"903 v1.3.2, root ds:Signature, not ASiC-E): RSA + SHA-256, detached (primary,\n" +
			"URI=\"file:/<basename>\" over the raw bytes) or enveloping, with the v1.3.2\n" +
			"SigningCertificate, and (level t) an RFC 3161 SignatureTimeStamp. XAdES is\n" +
			"assembled by an EU DSS (Java) helper via two-step external signing -- the\n" +
			"token stays in Go and the PIN never leaves it. It needs a Java 21 runtime\n" +
			"and the built helper jar (see --dss-helper).\n\n" +
			"Certificate chain: the token holds only the leaf. Pass --chain <file> (a PEM\n" +
			"bundle of issuing CA + root) to embed the full chain in the CMS (PAdES). The\n" +
			"public MoldSign chain can be fetched from:\n" +
			"  issuing CA: http://pki.md/cert/mdqsign.crt\n" +
			"  root:       http://pki.md/cer/mdtrustca.cer\n" +
			"(convert DER to PEM and concatenate). Without --chain the signature embeds\n" +
			"only the leaf and is flagged as chain-incomplete.\n\n" +
			"A PIN is REQUIRED and drives EXACTLY ONE login attempt with no retry: the\n" +
			"token can lock after a few failures. Never rerun blindly on failure.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(cmd, gf, f)
		},
	}
	cmd.Flags().StringVar(&f.module, "module", "", "path to the PKCS#11 module (.dylib)")
	cmd.Flags().UintVar(&f.slot, "slot", 0, "restrict to a single slot ID")
	cmd.Flags().StringVar(&f.tokenLabel, "token-label", "", "restrict to a token by label")
	cmd.Flags().StringVar(&f.keyID, "key-id", "", "signing key/cert CKA_ID in hex (default: auto-select the single CKA_SIGN key)")
	cmd.Flags().StringVar(&f.file, "file", "", "path to the input document to sign (required)")
	cmd.Flags().StringVar(&f.out, "out", "", "output path (default ./sign-out/<basename>.signed.pdf for PAdES, <filename>.xades for XAdES)")
	cmd.Flags().StringVar(&f.profile, "profile", "auto", "signature profile: auto | pades | xades")
	cmd.Flags().StringVar(&f.level, "level", "t", "AdES level: b (no timestamp) | t (RFC 3161 timestamp)")
	cmd.Flags().StringVar(&f.packaging, "xades-packaging", "detached", "XAdES packaging: detached | enveloping")
	cmd.Flags().StringVar(&f.digest, "digest", "sha256", "digest algorithm: sha256 (documents) | sha1 (interop-required, mpass auth challenge only)")
	cmd.Flags().StringVar(&f.tsaURL, "tsa-url", defaultTSAURL, "RFC 3161 TSA URL (level t only)")
	cmd.Flags().StringVar(&f.chain, "chain", "", "PEM bundle of the issuer chain (issuing CA + root) to embed (PAdES)")
	cmd.Flags().StringVar(&f.dssHelper, "dss-helper", "", "path to the EU DSS helper jar (XAdES). Default: "+defaultDSSHelperJar+" or $OPENMDSIGN_DSS_HELPER")
	cmd.Flags().StringVar(&f.pin, "pin", "", "user PIN (required). Prefer --pin-stdin")
	cmd.Flags().BoolVar(&f.pinStdin, "pin-stdin", false, "read the PIN from stdin (keeps it out of shell history)")
	cmd.Flags().BoolVar(&f.json, "json", false, "emit machine-readable JSON instead of text")
	cmd.MarkFlagsMutuallyExclusive("pin", "pin-stdin")
	return cmd
}

func runSign(cmd *cobra.Command, gf *globalFlags, f *signFlags) error {
	if f.file == "" {
		return fmt.Errorf("--file is required")
	}

	level, err := parseLevel(f.level)
	if err != nil {
		return err
	}

	profileName, err := resolveProfile(f.profile, f.file)
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
	tsaURL := f.tsaURL
	if !cmd.Flags().Changed("tsa-url") && cfg.TSAURL != "" {
		tsaURL = cfg.TSAURL
	}
	chainPath := f.chain
	if chainPath == "" && cfg.CAChain != "" {
		chainPath = cfg.CAChain
	}
	if cfg.Module == "" {
		return fmt.Errorf("no PKCS#11 module configured: pass --module <path> or set 'module' in the config file")
	}

	// Read the input document.
	data, err := os.ReadFile(f.file)
	if err != nil {
		return fmt.Errorf("read --file %q: %w", f.file, err)
	}

	// Load the issuer chain, if provided. Absence is a warning for PAdES only;
	// XAdES intentionally embeds the signer certificate alone (profile-spec §1).
	var chain []*x509.Certificate
	if chainPath != "" {
		chain, err = loadChainPEM(chainPath)
		if err != nil {
			return err
		}
	} else if profileName == pades.Profile {
		fmt.Fprintln(os.Stderr, "warning: no --chain supplied; the signature will embed only the leaf "+
			"certificate. Verifiers may still accept a -T signature, but the chain is incomplete "+
			"(fetch the MoldSign issuing CA + root and pass --chain a PEM bundle).")
	}

	// PIN is required. --pin-stdin preferred; the two are mutually exclusive.
	pin, hasPIN, err := resolvePIN(cmd, f.pin, f.pinStdin)
	if err != nil {
		return err
	}
	if !hasPIN {
		return fmt.Errorf("a PIN is required to sign: pass --pin-stdin (preferred) or --pin")
	}

	packaging, err := parsePackaging(f.packaging)
	if err != nil {
		return err
	}

	outPath := f.out
	if outPath == "" {
		name := filepath.Base(f.file)
		if profileName == xades.Profile {
			// Match the vendor convention: <original-filename>.xades (keeping the
			// source extension). MoldSign's validator keys off the .xades
			// extension, and pairing e.g. test.txt.xades next to test.txt makes
			// the detached file:/<name> reference resolve cleanly.
			name = name + ".xades"
		} else {
			name = strings.TrimSuffix(name, filepath.Ext(name)) + ".signed.pdf"
		}
		outPath = filepath.Join("sign-out", name)
	}

	// Resolve the DSS helper jar (XAdES only): flag > env > config > default.
	helperJar := f.dssHelper
	if helperJar == "" {
		helperJar = os.Getenv("OPENMDSIGN_DSS_HELPER")
	}
	if helperJar == "" && cfg.DSSHelperJar != "" {
		helperJar = cfg.DSSHelperJar
	}
	if helperJar == "" {
		helperJar = defaultDSSHelperJar
	}

	slog.Debug("sign starting",
		"module", cfg.Module, "file", f.file, "profile", profileName,
		"level", string(level), "bytes", len(data), "chain_supplied", chainPath != "",
		"pin_provided", true)

	ctx, err := token.Load(cfg.Module)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		if hint := fileHint(cfg.Module); hint != "" {
			fmt.Fprintln(os.Stderr, "hint: "+hint)
		}
		return errSilent
	}
	defer ctx.Close()

	// EXACTLY ONE C_Login happens inside OpenSigner. The PIN is dropped there.
	signer, err := ctx.OpenSigner(token.SignerRequest{
		PIN:        pin,
		SlotFilter: cfg.Slot,
		TokenLabel: cfg.TokenLabel,
		KeyIDHex:   keyID,
	})
	// Scrub our local PIN copy as soon as the single login attempt is done.
	pin = strings.Repeat("x", len(pin))
	_ = pin
	if err != nil {
		var le *token.LoginError
		if errors.As(err, &le) {
			printLoginAbort(le)
			return errSilent
		}
		return err
	}
	defer signer.Close()

	// Build the profile Signer.
	var profileSigner sign.Signer
	switch profileName {
	case pades.Profile:
		profileSigner = pades.New()
	case xades.Profile:
		profileSigner = xades.New("")
	default:
		return fmt.Errorf("internal: unhandled profile %q", profileName)
	}

	res, err := profileSigner.Sign(context.Background(), sign.Request{
		InputPDF:    data,
		InputName:   filepath.Base(f.file),
		OutputPath:  outPath,
		Signer:      signer,
		Certificate: signer.Certificate(),
		Chain:       chain,
		Level:       level,
		TSAURL:      tsaURL,
		Packaging:   packaging,
		Digest:      f.digest,
		HelperJar:   helperJar,
	})
	if err != nil {
		return err
	}

	if f.json {
		return emitSignJSON(signer, res, chainPath, len(chain))
	}
	printSignText(signer, res, chainPath, len(chain), tsaURL)
	return nil
}

// parseLevel validates the --level value.
func parseLevel(s string) (sign.Level, error) {
	switch s {
	case "b":
		return sign.LevelB, nil
	case "t":
		return sign.LevelT, nil
	default:
		return "", fmt.Errorf("invalid --level %q: expected \"b\" or \"t\"", s)
	}
}

// resolveProfile determines the profile from --profile and the input extension.
// auto: .pdf -> PAdES, anything else -> XAdES.
func resolveProfile(profile, file string) (string, error) {
	ext := strings.ToLower(filepath.Ext(file))
	switch profile {
	case "pades":
		if ext != ".pdf" {
			return "", fmt.Errorf("--profile pades requires a .pdf input (got %q)", ext)
		}
		return pades.Profile, nil
	case "xades":
		return xades.Profile, nil
	case "auto", "":
		if ext == ".pdf" {
			return pades.Profile, nil
		}
		return xades.Profile, nil
	default:
		return "", fmt.Errorf("invalid --profile %q: expected \"auto\", \"pades\" or \"xades\"", profile)
	}
}

// parsePackaging validates the --xades-packaging value.
func parsePackaging(s string) (sign.Packaging, error) {
	switch s {
	case "detached", "":
		return sign.PackagingDetached, nil
	case "enveloping":
		return sign.PackagingEnveloping, nil
	default:
		return "", fmt.Errorf("invalid --xades-packaging %q: expected \"detached\" or \"enveloping\"", s)
	}
}

// loadChainPEM reads a PEM bundle and returns the certificates in file order.
func loadChainPEM(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --chain %q: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := raw
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
			return nil, fmt.Errorf("parse certificate in --chain %q: %w", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("--chain %q contained no PEM CERTIFICATE blocks", path)
	}
	return certs, nil
}

func printSignText(signer *token.Signer, res sign.Result, chainPath string, chainLen int, tsaURL string) {
	w := os.Stdout
	fmt.Fprintln(w, "=== openmdsign sign ===")
	fmt.Fprintf(w, "  Slot:            %d\n", signer.SlotID())
	fmt.Fprintf(w, "  Token label:     %s\n", signer.TokenLabel())
	fmt.Fprintf(w, "  Key CKA_ID:      %s\n", signer.KeyIDHex())
	fmt.Fprintf(w, "  Cert subject:    %s\n", signer.Certificate().Subject.String())
	fmt.Fprintf(w, "  Profile:         %s\n", res.Profile)
	fmt.Fprintf(w, "  Level:           %s\n", strings.ToUpper(string(res.Level)))
	if res.TimestampApplied {
		fmt.Fprintf(w, "  Timestamp:       applied (TSA %s)\n", tsaURL)
	} else {
		fmt.Fprintln(w, "  Timestamp:       none (level b)")
	}
	if res.Profile == pades.Profile {
		if chainLen > 0 {
			fmt.Fprintf(w, "  Chain embedded:  leaf + %d issuer cert(s) from %s\n", chainLen, chainPath)
		} else {
			fmt.Fprintln(w, "  Chain embedded:  leaf only (INCOMPLETE — pass --chain)")
		}
	} else {
		fmt.Fprintln(w, "  Chain embedded:  signer certificate only (per XAdES profile)")
	}
	fmt.Fprintf(w, "  Signed file:     %s (%d bytes)\n", res.OutputPath, res.Bytes)
}

func emitSignJSON(signer *token.Signer, res sign.Result, chainPath string, chainLen int) error {
	out := map[string]any{
		"slot":               signer.SlotID(),
		"token_label":        signer.TokenLabel(),
		"key_id_hex":         signer.KeyIDHex(),
		"cert_subject":       signer.Certificate().Subject.String(),
		"profile":            res.Profile,
		"level":              string(res.Level),
		"timestamp_applied":  res.TimestampApplied,
		"chain_issuer_certs": chainLen,
		"chain_complete":     chainLen > 0,
		"chain_source":       chainPath,
		"output_path":        res.OutputPath,
		"output_bytes":       res.Bytes,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
