package server

import (
	"crypto/tls"
	"time"
)

// DevCert returns an EPHEMERAL, in-memory self-signed certificate for hostname,
// regenerated on every call and never written to disk.
//
// ⚠️ This is the DEVELOPMENT/test fallback only (`serve --dev-cert`). Production
// serving uses the PERSISTENT per-machine cert in CertStore (servingcert.go),
// which the Daemon Phase D `trust` subcommand can add to the login keychain as a
// trusted SSL anchor (docs/PROTOCOL.md §2). DevCert installs no trust anchor and
// a browser will not trust it; `curl -k` works for smoke testing.
func DevCert(hostname string) (tls.Certificate, error) {
	cert, _, _, err := generateLeafCert(hostname, 397*24*time.Hour)
	return cert, err
}
