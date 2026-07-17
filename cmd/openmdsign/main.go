// Command openmdsign is an open-source macOS CLI for signing files with a
// hardware PKCS#11 token, aimed at interoperability with existing Moldovan
// electronic-signature infrastructure.
//
// This is NOT affiliated with or endorsed by any government body or the
// proprietary vendor tooling, and it does NOT claim to produce a legally
// "qualified" electronic signature. See README.md.
//
// Phase 0 provides a single read-only command, `inspect`, a recon harness for
// understanding a token before any signing code is written.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		// errSilent means a detailed diagnostic was already written to stderr.
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, "Error: "+msg)
		}
		os.Exit(1)
	}
}
