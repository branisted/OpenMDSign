package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// global flags shared across subcommands.
type globalFlags struct {
	configPath string
	verbose    bool
}

func newRootCmd() *cobra.Command {
	gf := &globalFlags{}

	root := &cobra.Command{
		Use:   "openmdsign",
		Short: "Sign files with a hardware PKCS#11 token (interop-focused, unofficial)",
		Long: "openmdsign is an open-source macOS CLI for signing files with a hardware\n" +
			"PKCS#11 token. It is unofficial, not affiliated with any authority, and does\n" +
			"not claim to produce a legally \"qualified\" signature.\n\n" +
			"Phase 0 provides the read-only `inspect` recon command.",
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

	root.AddCommand(newInspectCmd(gf))
	return root
}
