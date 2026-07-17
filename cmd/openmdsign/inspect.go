package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/branistedev/openmdsign/internal/config"
	"github.com/branistedev/openmdsign/internal/token"
	"github.com/branistedev/openmdsign/internal/x509util"
)

type inspectFlags struct {
	module     string
	slot       uint
	tokenLabel string
	pin        string
	pinStdin   bool
	out        string
	json       bool
}

func newInspectCmd(gf *globalFlags) *cobra.Command {
	f := &inspectFlags{}
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Read-only recon of a PKCS#11 token: library info, slots, mechanisms, objects, certs",
		Long: "inspect loads the configured PKCS#11 module and reports, read-only, the\n" +
			"library info, slots and tokens, supported mechanisms, and public objects.\n\n" +
			"A PIN is OPTIONAL and only enables listing private-key objects. If supplied\n" +
			"it is used for EXACTLY ONE login attempt with no retry: hardware tokens lock\n" +
			"after a few failures.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(cmd, gf, f)
		},
	}
	cmd.Flags().StringVar(&f.module, "module", "", "path to the PKCS#11 module (.dylib)")
	cmd.Flags().UintVar(&f.slot, "slot", 0, "restrict to a single slot ID")
	cmd.Flags().StringVar(&f.tokenLabel, "token-label", "", "restrict to a token by label")
	cmd.Flags().StringVar(&f.pin, "pin", "", "user PIN (optional; enables private-key listing). Prefer --pin-stdin")
	cmd.Flags().BoolVar(&f.pinStdin, "pin-stdin", false, "read the PIN from stdin (keeps it out of shell history)")
	cmd.Flags().StringVar(&f.out, "out", "./inspect-out", "directory for exported certificate DER files")
	cmd.Flags().BoolVar(&f.json, "json", false, "emit machine-readable JSON instead of text")
	return cmd
}

// resolvedConfig applies precedence flags > config file > defaults.
func resolveConfig(cmd *cobra.Command, gf *globalFlags, f *inspectFlags) (config.Config, error) {
	path := gf.configPath
	required := path != ""
	if path == "" && config.FileExists("openmdsign.toml") {
		path = "openmdsign.toml"
	}
	cfg, err := config.LoadFile(path, required)
	if err != nil {
		return cfg, err
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
	return cfg, nil
}

func runInspect(cmd *cobra.Command, gf *globalFlags, f *inspectFlags) error {
	cfg, err := resolveConfig(cmd, gf, f)
	if err != nil {
		return err
	}
	if cfg.Module == "" {
		return fmt.Errorf("no PKCS#11 module configured: pass --module <path> or set 'module' in the config file")
	}

	// Resolve the PIN (never logged). --pin-stdin takes precedence.
	pin, hasPIN, err := resolvePIN(cmd, f)
	if err != nil {
		return err
	}
	// Defensive: never let a PIN reach a log call.
	slog.Debug("inspect starting", "module", cfg.Module, "pin_provided", hasPIN)

	ctx, err := token.Load(cfg.Module)
	if err != nil {
		// Add a `file` hint diagnostic for load failures.
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		if hint := fileHint(cfg.Module); hint != "" {
			fmt.Fprintln(os.Stderr, "hint: "+hint)
		}
		return errSilent
	}
	defer ctx.Close()

	opts := token.Options{PIN: pin, HasPIN: hasPIN, SlotFilter: cfg.Slot, TokenLabel: cfg.TokenLabel}
	rep, err := ctx.Inspect(opts)
	// Scrub the PIN from memory as soon as it is no longer needed.
	pin = strings.Repeat("x", len(pin))
	_ = pin
	if err != nil {
		return err
	}

	// Export certificates and parse them.
	certErr := exportAndParseCerts(rep, f.out)

	if f.json {
		if err := emitJSON(rep); err != nil {
			return err
		}
	} else {
		emitText(rep, f.out)
	}

	// Decide exit code. A failed login is a hard abort (non-zero) so callers
	// notice, but we do NOT retry.
	if loginFailed(rep) {
		fmt.Fprintln(os.Stderr, "\nABORT: login failed. Do NOT re-run with the PIN blindly — "+
			"the token can lock after a few failed attempts. Verify the correct PIN and "+
			"remaining attempts on the physical device first.")
		return errSilent
	}
	if certErr != nil {
		return certErr
	}
	return nil
}

// errSilent signals main to exit non-zero without cobra reprinting a message
// we already wrote to stderr.
var errSilent = &silentError{}

type silentError struct{}

func (*silentError) Error() string { return "" }

func resolvePIN(cmd *cobra.Command, f *inspectFlags) (string, bool, error) {
	if f.pinStdin {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if err != nil && line == "" {
			return "", false, fmt.Errorf("failed to read PIN from stdin")
		}
		if line == "" {
			return "", false, fmt.Errorf("empty PIN read from stdin")
		}
		return line, true, nil
	}
	if cmd.Flags().Changed("pin") {
		if f.pin == "" {
			return "", false, fmt.Errorf("--pin was empty")
		}
		return f.pin, true, nil
	}
	return "", false, nil
}

func loginFailed(rep *token.Report) bool {
	for _, s := range rep.Slots {
		if s.Login != nil && s.Login.Attempted && !s.Login.Succeeded {
			return true
		}
	}
	return false
}

// exportAndParseCerts writes each certificate object's DER to outdir and
// attaches parsed info for rendering.
func exportAndParseCerts(rep *token.Report, outdir string) error {
	var anyCert bool
	for _, s := range rep.Slots {
		for _, o := range s.Objects {
			if len(o.CertDER) > 0 {
				anyCert = true
			}
		}
	}
	if !anyCert {
		return nil
	}
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		return fmt.Errorf("create out dir %q: %w", outdir, err)
	}
	for _, s := range rep.Slots {
		for _, o := range s.Objects {
			if len(o.CertDER) == 0 {
				continue
			}
			id := o.IDHex
			if id == "" {
				id = "noid"
			}
			path := filepath.Join(outdir, "cert-"+id+".der")
			if err := os.WriteFile(path, o.CertDER, 0o644); err != nil {
				slog.Warn("failed to write cert", "path", path, "err", err.Error())
			}
		}
	}
	return nil
}

func emitJSON(rep *token.Report) error {
	// Augment JSON with parsed certificate info.
	type certOut struct {
		token.Object
		Parsed *x509util.CertInfo `json:"parsed_certificate,omitempty"`
	}
	// Build a parallel structure so parsed certs appear in JSON.
	out := map[string]any{
		"module":  rep.Module,
		"library": rep.Library,
		"note":    rep.Note,
	}
	var slots []map[string]any
	for _, s := range rep.Slots {
		sm := map[string]any{
			"id":                   s.ID,
			"description":          s.Description,
			"manufacturer":         s.Manufacturer,
			"flags":                s.Flags,
			"token_present":        s.TokenPresent,
			"token":                s.Token,
			"mechanisms":           s.Mechanisms,
			"signature_mechanisms": s.SignatureMechs,
			"login":                s.Login,
			"warnings":             s.Warnings,
		}
		var objs []any
		for _, o := range s.Objects {
			co := certOut{Object: o}
			if len(o.CertDER) > 0 {
				if ci, err := x509util.Parse(o.CertDER); err == nil {
					co.Parsed = ci
				}
			}
			objs = append(objs, co)
		}
		sm["objects"] = objs
		slots = append(slots, sm)
	}
	out["slots"] = slots

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
