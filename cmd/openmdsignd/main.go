// Command openmdsignd is the local HTTPS daemon that reimplements the browser⇄
// daemon localhost contract documented in docs/PROTOCOL.md, so a browser on the
// Moldovan e-signature front-ends can drive a hardware PKCS#11 token.
//
// This binary is Daemon Phase B: the transport + routing + CORS + certificate
// enumeration SKELETON. It does NOT sign — POST /sign/data returns 501 until
// Phase C wires the signers behind the Signer seam (internal/server). It is
// unofficial and not affiliated with any authority.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, "Error: "+msg)
		}
		os.Exit(1)
	}
}
