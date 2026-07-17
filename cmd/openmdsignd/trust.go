package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/branistedev/openmdsign/internal/config"
	"github.com/branistedev/openmdsign/internal/server"
)

// trustFlags scope which serving cert the trust operations target. They mirror
// the serve flags so `trust` and `serve` agree on the cert location.
type trustFlags struct {
	hostname string
	tlsDir   string
}

func newTrustCmd(gf *globalFlags) *cobra.Command {
	f := &trustFlags{}
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage OS trust for the persistent serving cert (Daemon Phase D)",
		Long: "trust manages whether the browser trusts openmdsignd's TLS.\n\n" +
			"The daemon serves a PERSISTENT, per-machine, self-signed leaf for\n" +
			"CN/SAN=localhost.cts.md (fresh unique key per machine — never bundled or\n" +
			"shared). Because localhost.cts.md resolves only to 127.0.0.1, trusting this\n" +
			"one leaf can impersonate nothing but the local daemon (docs/PROTOCOL.md §2).\n\n" +
			"'trust install' adds it to your macOS login keychain as a trusted SSL anchor\n" +
			"(this prompts for your login-keychain password). 'trust uninstall' removes it.\n" +
			"'trust status' reports whether the cert exists and is trusted, changing nothing.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	d := config.DefaultDaemon()
	cmd.PersistentFlags().StringVar(&f.hostname, "hostname", d.Hostname,
		"TLS server name the serving cert covers")
	cmd.PersistentFlags().StringVar(&f.tlsDir, "tls-dir", d.TLSDir,
		"directory for the persistent serving cert+key (empty = default ~/Library/Application Support/openmdsign/tls)")

	cmd.AddCommand(newTrustInstallCmd(f))
	cmd.AddCommand(newTrustUninstallCmd(f))
	cmd.AddCommand(newTrustStatusCmd(f))
	return cmd
}

// trustStore resolves the CertStore + platform TrustStore for the flags. When
// tlsDir is empty it falls back to the default per-user TLS directory.
func trustStore(f *trustFlags) (server.CertStore, server.TrustStore, error) {
	dir := f.tlsDir
	if dir == "" {
		d, err := server.DefaultTLSDir()
		if err != nil {
			return server.CertStore{}, nil, err
		}
		dir = d
	}
	store := server.CertStore{Hostname: f.hostname, Dir: dir}
	return store, server.NewTrustStore(store), nil
}

func newTrustInstallCmd(f *trustFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Add the serving cert to the login keychain as a trusted SSL anchor",
		Long: "install ensures the per-machine serving cert exists, then adds it as a\n" +
			"trusted SSL anchor in your login keychain via macOS `security`. This prompts\n" +
			"for your login-keychain password — that is expected. It is idempotent.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, ts, err := trustStore(f)
			if err != nil {
				return err
			}
			cmd.Printf("This will ensure the serving cert exists at %s and run:\n", store.CertPath())
			announce := func(line string) { cmd.Printf("  %s\n", line) }
			if err := ts.Install(cmd.Context(), announce); err != nil {
				return fmt.Errorf("trust install: %w", err)
			}
			cmd.Println("Done. The serving cert is now a trusted SSL anchor in your login keychain.")
			return nil
		},
	}
}

func newTrustUninstallCmd(f *trustFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the serving cert's trust and delete it from the login keychain",
		Long: "uninstall removes the serving cert's SSL trust settings, deletes it from the\n" +
			"login keychain, and removes the on-disk cert+key — leaving the machine clean.\n" +
			"It is idempotent (safe to run when nothing is installed).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, ts, err := trustStore(f)
			if err != nil {
				return err
			}
			cmd.Println("This will run:")
			announce := func(line string) { cmd.Printf("  %s\n", line) }
			if err := ts.Uninstall(cmd.Context(), announce); err != nil {
				return fmt.Errorf("trust uninstall: %w", err)
			}
			cmd.Println("Done. Serving-cert trust removed and files deleted.")
			return nil
		},
	}
}

func newTrustStatusCmd(f *trustFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the serving cert exists and is trusted (read-only)",
		Long:  "status reports the serving cert's on-disk presence and OS trust state. It mutates nothing.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, ts, err := trustStore(f)
			if err != nil {
				return err
			}
			st, statusErr := ts.Status(cmd.Context())
			cmd.Printf("hostname:  %s\n", f.hostname)
			cmd.Printf("cert path: %s\n", store.CertPath())
			cmd.Printf("cert:      %s\n", certExistsLabel(st))
			cmd.Printf("trusted:   %s\n", trustedLabel(st, statusErr))
			// A platform-unsupported status is informative, not a hard failure.
			if statusErr != nil && statusErr != server.ErrTrustUnsupported {
				return fmt.Errorf("trust status: %w", statusErr)
			}
			return nil
		},
	}
}

func certExistsLabel(st server.TrustStatus) string {
	switch {
	case st.CertExists && st.Expired:
		return "present (EXPIRED — will regenerate on next serve/install)"
	case st.CertExists:
		return "present"
	default:
		return "not generated yet (run 'openmdsignd trust install' or 'openmdsignd serve')"
	}
}

func trustedLabel(st server.TrustStatus, statusErr error) string {
	if statusErr == server.ErrTrustUnsupported {
		return "unknown (trust management is macOS-only on this platform)"
	}
	if st.Trusted {
		return "yes (trusted SSL anchor in the login keychain)"
	}
	return "no (run 'openmdsignd trust install')"
}
