package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Serving-cert on-disk names and policy.
//
// The persistent per-machine serving certificate implements the Daemon Phase D
// trust model (docs/PROTOCOL.md §2, ROADMAP STOP decision #1): a self-signed
// LEAF for CN/SAN=localhost.cts.md, generated once per machine with a fresh
// unique key that is NEVER bundled or shared (no Superfish-style shared key).
// Because localhost.cts.md resolves only to 127.0.0.1, trusting this one leaf
// can impersonate nothing but the local daemon — minimal blast radius.
const (
	servingCertFile = "serving-cert.pem"
	servingKeyFile  = "serving-key.pem"

	// servingCertValidity is the leaf lifetime (5 years). Long-lived so a user
	// installs trust once; it is a local, loopback-only anchor.
	servingCertValidity = 5 * 365 * 24 * time.Hour

	// servingCertRenewBefore regenerates a cert this close to expiry.
	servingCertRenewBefore = 24 * time.Hour
)

// DefaultTLSDir resolves the stable per-user directory that holds the persistent
// serving cert+key: ~/Library/Application Support/openmdsign/tls on macOS
// (os.UserConfigDir()/openmdsign/tls elsewhere). Never under the repo, so no
// cert/key can accidentally be committed.
func DefaultTLSDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(base, "openmdsign", "tls"), nil
}

// CertStore locates and manages the persistent serving cert+key for Hostname
// under Dir. It is the single source of truth shared by the TLS listener and the
// `trust` subcommand for the cert/key paths.
type CertStore struct {
	Hostname string
	Dir      string
}

// CertPath is the PEM certificate path.
func (c CertStore) CertPath() string { return filepath.Join(c.Dir, servingCertFile) }

// KeyPath is the PEM private-key path (mode 0600).
func (c CertStore) KeyPath() string { return filepath.Join(c.Dir, servingKeyFile) }

// EnsureCert returns the persistent serving certificate, reusing the on-disk
// cert+key when present and still valid, and (re)generating a fresh per-machine
// keypair when the files are missing, unparseable, expired, or no longer cover
// Hostname. The key file is written mode 0600.
func (c CertStore) EnsureCert() (tls.Certificate, error) {
	if cert, ok := c.load(); ok {
		return cert, nil
	}
	cert, certPEM, keyPEM, err := generateLeafCert(c.Hostname, servingCertValidity)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := c.write(certPEM, keyPEM); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

// LoadLeaf parses the on-disk leaf certificate, reporting ok=false when it is
// absent or unparseable. It does not consider expiry, so `trust status` can
// report an existing-but-expired cert.
func (c CertStore) LoadLeaf() (*x509.Certificate, bool) {
	der, err := os.ReadFile(c.CertPath())
	if err != nil {
		return nil, false
	}
	block, _ := pem.Decode(der)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}
	return leaf, true
}

// load reads and validates the cached cert+key, returning ok=false when it must
// be regenerated (missing, unparseable, near expiry, or wrong hostname).
func (c CertStore) load() (tls.Certificate, bool) {
	certPEM, err := os.ReadFile(c.CertPath())
	if err != nil {
		return tls.Certificate{}, false
	}
	keyPEM, err := os.ReadFile(c.KeyPath())
	if err != nil {
		return tls.Certificate{}, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, false
	}
	if time.Now().Add(servingCertRenewBefore).After(leaf.NotAfter) {
		return tls.Certificate{}, false
	}
	if leaf.VerifyHostname(c.Hostname) != nil {
		return tls.Certificate{}, false
	}
	return cert, true
}

// write persists the cert (0644) and key (0600) into Dir (created 0700 — a
// per-user private directory).
func (c CertStore) write(certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return fmt.Errorf("create tls dir: %w", err)
	}
	if err := os.WriteFile(c.CertPath(), certPEM, 0o644); err != nil {
		return fmt.Errorf("write serving cert: %w", err)
	}
	if err := os.WriteFile(c.KeyPath(), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write serving key: %w", err)
	}
	return nil
}

// generateLeafCert mints a fresh self-signed EC leaf for hostname with a random
// per-machine key: SAN DNS:hostname + IP:127.0.0.1/::1, EKU serverAuth, KeyUsage
// digitalSignature+keyEncipherment, valid for the given window.
func generateLeafCert(hostname string, validity time.Duration) (tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate serving key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("create serving cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("marshal serving key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("assemble serving keypair: %w", err)
	}
	return cert, certPEM, keyPEM, nil
}
