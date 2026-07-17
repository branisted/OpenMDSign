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
}

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
	cmd.Flags().StringVar(&f.module, "module", "", "path to the vendor PKCS#11 module (.dylib) for /certificates")
	cmd.Flags().StringVar(&f.devCertDir, "dev-cert-dir", d.DevCertDir, "directory to cache the self-signed dev cert (empty = in-memory)")
	return cmd
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

	srv := server.New(server.Config{
		HTTPSAddr:     dc.HTTPSAddr,
		HTTPAddr:      dc.HTTPAddr,
		Hostname:      dc.Hostname,
		CORSAllowlist: dc.CORSAllowlist,
		ModulePath:    modulePath,
		DevCertDir:    dc.DevCertDir,
	}, server.WithLogger(slog.Default()))

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
