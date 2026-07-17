package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/branistedev/openmdsign/internal/config"
	"github.com/branistedev/openmdsign/internal/server"
)

// globalFlags are shared across openmdsignd subcommands.
type globalFlags struct {
	configPath string
	verbose    bool
}

func newRootCmd() *cobra.Command {
	gf := &globalFlags{}

	root := &cobra.Command{
		Use:   "openmdsignd",
		Short: "Local HTTPS daemon for browser-driven PKCS#11 signing (interop-focused, unofficial)",
		Long: "openmdsignd is the local HTTPS daemon half of openmdsign. It answers the\n" +
			"browser⇄daemon localhost REST contract (docs/PROTOCOL.md) so the Moldovan\n" +
			"e-signature web front-ends can enumerate and drive a hardware PKCS#11 token.\n\n" +
			"This is Daemon Phase B: the transport, routing, CORS allowlist and certificate\n" +
			"enumeration SKELETON. It does NOT sign yet — POST /sign/data returns 501 until\n" +
			"Phase C wires the signers. It is unofficial and makes no \"qualified\" claim.\n\n" +
			"Commands:\n" +
			"  serve   run the loopback HTTPS daemon.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&gf.configPath, "config", "",
		"path to TOML config file (default ./openmdsign.toml if present)")
	root.PersistentFlags().BoolVar(&gf.verbose, "verbose", false, "verbose logging to stderr")

	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		level := slog.LevelInfo
		if gf.verbose {
			level = slog.LevelDebug
		}
		h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
		slog.SetDefault(slog.New(h))
	}

	root.AddCommand(newServeCmd(gf))
	return root
}

// serveFlags are the `serve` command's flags. Each overrides the corresponding
// config value when explicitly set (precedence: flags > config file > defaults).
type serveFlags struct {
	httpsAddr  string
	httpAddr   string
	hostname   string
	corsOrigin []string
	module     string
	devCertDir string
	chain      string
	dssHelper  string
	tsaURL     string
	fakeSigner bool
}

// defaultDSSHelperJar is the conventional build location of the EU DSS helper
// jar, relative to the repo root (where `mvn package` writes it).
const defaultDSSHelperJar = "java/dss-helper/target/dss-helper.jar"

func newServeCmd(gf *globalFlags) *cobra.Command {
	f := &serveFlags{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the loopback HTTPS daemon (PROTOCOL.md §1–4)",
		Long: "serve binds the loopback HTTPS listener (default 127.0.0.1:18443 for host\n" +
			"localhost.cts.md) and answers the three PROTOCOL.md routes: GET /certificates,\n" +
			"POST /sign/data (501 until Phase C), and GET /sign/data/PKCS11/{uuid}/{format}.\n\n" +
			"TLS uses a SELF-SIGNED dev certificate (Phase B). The real publicly-trusted-cert\n" +
			"trust gate is Daemon Phase D. localhost.cts.md must resolve to 127.0.0.1 (public\n" +
			"DNS provides it; a hosts entry is a fallback).",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd, gf, f)
		},
	}
	d := config.DefaultDaemon()
	cmd.Flags().StringVar(&f.httpsAddr, "https-addr", d.HTTPSAddr, "loopback HTTPS listen address")
	cmd.Flags().StringVar(&f.httpAddr, "http-addr", d.HTTPAddr, "optional plain-HTTP probe listen address (empty disables)")
	cmd.Flags().StringVar(&f.hostname, "hostname", d.Hostname, "TLS server name the browser targets")
	cmd.Flags().StringSliceVar(&f.corsOrigin, "cors-origin", d.CORSAllowlist, "strict CORS allowlist (repeatable)")
	cmd.Flags().StringVar(&f.module, "module", "", "path to the vendor PKCS#11 module (.dylib) for /certificates and signing (enables the real signer)")
	cmd.Flags().StringVar(&f.devCertDir, "dev-cert-dir", d.DevCertDir, "directory to cache the self-signed dev cert (empty = in-memory)")
	cmd.Flags().StringVar(&f.chain, "chain", "", "PEM bundle of the issuer chain (issuing CA + root) embedded in PAdES signatures")
	cmd.Flags().StringVar(&f.dssHelper, "dss-helper", "", "path to the EU DSS helper jar (XAdES document signing). Default: "+defaultDSSHelperJar)
	cmd.Flags().StringVar(&f.tsaURL, "tsa-url", "", "RFC 3161 TSA URL for -T signatures (default: the MoldSign TSA)")
	// Dev/smoke aid: inject a canned signer that returns a fixed base64 without a
	// token, PIN, or dialog. Hidden and OFF by default; never a production path.
	cmd.Flags().BoolVar(&f.fakeSigner, "dev-fake-signer", false, "DEV ONLY: wire a canned fake signer (no token/PIN) for smoke testing")
	_ = cmd.Flags().MarkHidden("dev-fake-signer")
	return cmd
}

// cannedSigner is a hardware-free server.Signer for `--dev-fake-signer`: it
// returns a fixed base64 payload so the 201 + Location + fetch flow can be
// exercised over real HTTP without a token, PIN, or dialog. It is NEVER wired
// unless the hidden dev flag is set.
type cannedSigner struct{}

func (cannedSigner) Sign(_ context.Context, req server.SignRequest) (server.SignResult, error) {
	format := "pdf"
	if req.SignFormat == "XAdES-T" {
		format = "XAdES"
	}
	// "canned-signed-container" in base64.
	return server.SignResult{Format: format, Base64File: "Y2FubmVkLXNpZ25lZC1jb250YWluZXI="}, nil
}

func runServe(cmd *cobra.Command, gf *globalFlags, f *serveFlags) error {
	cfg, err := loadConfig(gf)
	if err != nil {
		return err
	}
	dc := cfg.Daemon

	// Apply precedence: explicit flags override the config file.
	if cmd.Flags().Changed("https-addr") {
		dc.HTTPSAddr = f.httpsAddr
	}
	if cmd.Flags().Changed("http-addr") {
		dc.HTTPAddr = f.httpAddr
	}
	if cmd.Flags().Changed("hostname") {
		dc.Hostname = f.hostname
	}
	if cmd.Flags().Changed("cors-origin") {
		dc.CORSAllowlist = f.corsOrigin
	}
	if cmd.Flags().Changed("dev-cert-dir") {
		dc.DevCertDir = f.devCertDir
	}
	modulePath := cfg.Module
	if cmd.Flags().Changed("module") {
		modulePath = f.module
	}
	chainPEM := cfg.CAChain
	if cmd.Flags().Changed("chain") {
		chainPEM = f.chain
	}
	dssHelper := cfg.DSSHelperJar
	if cmd.Flags().Changed("dss-helper") {
		dssHelper = f.dssHelper
	}
	if dssHelper == "" {
		dssHelper = defaultDSSHelperJar
	}
	tsaURL := cfg.TSAURL
	if cmd.Flags().Changed("tsa-url") {
		tsaURL = f.tsaURL
	}

	opts := []server.Option{server.WithLogger(slog.Default())}
	// Signer selection precedence:
	//   --dev-fake-signer → a canned, hardware-free signer (smoke testing only);
	//   --module set      → the REAL TokenSigner (PAdES/XAdES + PIN/confirm gate);
	//   neither           → the Phase B stub (501), keeping dev/tests hardware-free.
	switch {
	case f.fakeSigner:
		slog.Default().Warn("DEV: wiring the canned fake signer (--dev-fake-signer); no token, PIN, or dialog is used")
		opts = append(opts, server.WithSigner(cannedSigner{}))
	case modulePath != "":
		signer := server.NewTokenSigner(server.TokenSignerConfig{
			ModulePath:   modulePath,
			ChainPEM:     chainPEM,
			DSSHelperJar: dssHelper,
			TSAURL:       tsaURL,
		}, server.NewOSAScriptConfirmer(), slog.Default())
		opts = append(opts, server.WithSigner(signer))
	}

	srv := server.New(server.Config{
		HTTPSAddr:     dc.HTTPSAddr,
		HTTPAddr:      dc.HTTPAddr,
		Hostname:      dc.Hostname,
		CORSAllowlist: dc.CORSAllowlist,
		ModulePath:    modulePath,
		DevCertDir:    dc.DevCertDir,
	}, opts...)

	// Cancel on SIGINT/SIGTERM for a graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

// loadConfig reads the config honoring --config precedence (a default
// ./openmdsign.toml is used when present).
func loadConfig(gf *globalFlags) (config.Config, error) {
	path := gf.configPath
	required := path != ""
	if path == "" && config.FileExists("openmdsign.toml") {
		path = "openmdsign.toml"
	}
	return config.LoadFile(path, required)
}
