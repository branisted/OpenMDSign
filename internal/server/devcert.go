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

// devCertFiles are the on-disk names used when DevCertDir is configured.
const (
	devCertFile = "dev-cert.pem"
	devKeyFile  = "dev-key.pem"
)

// DevCert returns a TLS certificate for hostname, self-signed by an ephemeral
// key generated at startup.
//
// ⚠️ This is a DEVELOPMENT stand-in ONLY. PROTOCOL.md §2 documents that the real
// browser flow requires a PUBLICLY-TRUSTED cert for `localhost.cts.md` (or a
// locally-installed trust anchor). That trust gate is a SEPARATE later STOP
// decision — Daemon Phase D — and this function deliberately does NOT install
// any trust anchor. A browser hitting this listener will see an untrusted cert
// until Phase D lands; `curl -k` works for smoke testing.
//
// When dir is non-empty a generated cert+key is cached there and reused across
// restarts (regenerated only if missing/expired/unparseable). When dir is empty
// the cert lives in memory for the process lifetime.
func DevCert(hostname, dir string) (tls.Certificate, error) {
	if dir != "" {
		if cert, ok := loadCachedDevCert(dir); ok {
			return cert, nil
		}
	}
	cert, certPEM, keyPEM, err := generateDevCert(hostname)
	if err != nil {
		return tls.Certificate{}, err
	}
	if dir != "" {
		if err := writeDevCert(dir, certPEM, keyPEM); err != nil {
			return tls.Certificate{}, err
		}
	}
	return cert, nil
}

// generateDevCert mints a fresh self-signed EC cert for hostname (plus the
// loopback SANs) valid for ~397 days.
func generateDevCert(hostname string) (tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate dev key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(397 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("create dev cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("marshal dev key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("assemble dev keypair: %w", err)
	}
	return cert, certPEM, keyPEM, nil
}

// loadCachedDevCert loads a cached dev cert from dir, returning ok=false if it
// is absent, unparseable, or within 24h of expiry (so it gets regenerated).
func loadCachedDevCert(dir string) (tls.Certificate, bool) {
	certPath := filepath.Join(dir, devCertFile)
	keyPath := filepath.Join(dir, devKeyFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, false
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || time.Now().Add(24*time.Hour).After(leaf.NotAfter) {
		return tls.Certificate{}, false
	}
	return cert, true
}

// writeDevCert persists the cert (0644) and key (0600) into dir.
func writeDevCert(dir string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dev cert dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, devCertFile), certPEM, 0o644); err != nil {
		return fmt.Errorf("write dev cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, devKeyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write dev key: %w", err)
	}
	return nil
}
