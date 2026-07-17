package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testHost = "localhost.cts.md"

// leafFromStore reads and parses the on-disk leaf, failing the test if absent.
func leafFromStore(t *testing.T, c CertStore) *x509.Certificate {
	t.Helper()
	leaf, ok := c.LoadLeaf()
	if !ok {
		t.Fatalf("LoadLeaf: cert missing/unparseable at %s", c.CertPath())
	}
	return leaf
}

func TestServingCertSpec(t *testing.T) {
	c := CertStore{Hostname: testHost, Dir: t.TempDir()}
	if _, err := c.EnsureCert(); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	leaf := leafFromStore(t, c)

	// CN + SAN DNS.
	if leaf.Subject.CommonName != testHost {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, testHost)
	}
	if err := leaf.VerifyHostname(testHost); err != nil {
		t.Errorf("VerifyHostname(%q): %v", testHost, err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != testHost {
		t.Errorf("DNSNames = %v, want [%q]", leaf.DNSNames, testHost)
	}
	// SAN IP 127.0.0.1.
	var hasLoopback bool
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Errorf("IPAddresses = %v, want 127.0.0.1 present", leaf.IPAddresses)
	}
	// EKU serverAuth.
	var serverAuth bool
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		t.Errorf("ExtKeyUsage = %v, want serverAuth present", leaf.ExtKeyUsage)
	}
	// KeyUsage digitalSignature + keyEncipherment.
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Errorf("KeyUsage missing digitalSignature")
	}
	if leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Errorf("KeyUsage missing keyEncipherment")
	}
	// Self-signed: issuer == subject and the leaf's own key verifies its
	// signature. We check the signature directly (not CheckSignatureFrom, which
	// requires CA semantics) because this is deliberately a pure LEAF — not a CA,
	// so it can sign nothing but itself.
	if leaf.Subject.String() != leaf.Issuer.String() {
		t.Errorf("not self-signed: subject %q != issuer %q", leaf.Subject, leaf.Issuer)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Errorf("self-signature check: %v", err)
	}
	if leaf.IsCA {
		t.Errorf("cert is marked IsCA — must be a pure leaf that cannot sign other names")
	}
	// EC key (fresh per machine).
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("public key type = %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	// ~5-year validity.
	got := leaf.NotAfter.Sub(leaf.NotBefore)
	if got < 4*365*24*time.Hour {
		t.Errorf("validity = %s, want ~5 years", got)
	}
}

func TestServingCertKeyFileMode0600(t *testing.T) {
	c := CertStore{Hostname: testHost, Dir: t.TempDir()}
	if _, err := c.EnsureCert(); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	info, err := os.Stat(c.KeyPath())
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}
}

func TestServingCertReusedWhenValid(t *testing.T) {
	c := CertStore{Hostname: testHost, Dir: t.TempDir()}
	if _, err := c.EnsureCert(); err != nil {
		t.Fatalf("EnsureCert #1: %v", err)
	}
	first := leafFromStore(t, c).SerialNumber

	if _, err := c.EnsureCert(); err != nil {
		t.Fatalf("EnsureCert #2: %v", err)
	}
	second := leafFromStore(t, c).SerialNumber

	if first.Cmp(second) != 0 {
		t.Errorf("cert regenerated when it should have been reused: %s != %s", first, second)
	}
}

func TestServingCertRegeneratedWhenExpired(t *testing.T) {
	dir := t.TempDir()
	c := CertStore{Hostname: testHost, Dir: dir}

	// Plant an already-expired cert+key so load() rejects it.
	cert, certPEM, keyPEM, err := generateLeafCert(testHost, -1*time.Hour)
	if err != nil {
		t.Fatalf("generate expired: %v", err)
	}
	if err := c.write(certPEM, keyPEM); err != nil {
		t.Fatalf("write expired: %v", err)
	}
	expiredSerial, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse expired: %v", err)
	}

	if _, err := c.EnsureCert(); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	fresh := leafFromStore(t, c)
	if fresh.SerialNumber.Cmp(expiredSerial.SerialNumber) == 0 {
		t.Errorf("expired cert was reused instead of regenerated")
	}
	if !fresh.NotAfter.After(time.Now()) {
		t.Errorf("regenerated cert already expired: NotAfter=%s", fresh.NotAfter)
	}
}

func TestServingCertRegeneratedWhenMissingKey(t *testing.T) {
	dir := t.TempDir()
	c := CertStore{Hostname: testHost, Dir: dir}
	if _, err := c.EnsureCert(); err != nil {
		t.Fatalf("EnsureCert #1: %v", err)
	}
	first := leafFromStore(t, c).SerialNumber

	// Remove only the key: an unpaired cert must force regeneration.
	if err := os.Remove(c.KeyPath()); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	if _, err := c.EnsureCert(); err != nil {
		t.Fatalf("EnsureCert #2: %v", err)
	}
	if got := leafFromStore(t, c).SerialNumber; got.Cmp(first) == 0 {
		t.Errorf("cert not regenerated after key loss")
	}
	if _, err := os.Stat(c.KeyPath()); err != nil {
		t.Errorf("key not rewritten: %v", err)
	}
}

func TestDefaultTLSDir(t *testing.T) {
	dir, err := DefaultTLSDir()
	if err != nil {
		t.Fatalf("DefaultTLSDir: %v", err)
	}
	if filepath.Base(dir) != "tls" || filepath.Base(filepath.Dir(dir)) != "openmdsign" {
		t.Errorf("DefaultTLSDir = %q, want .../openmdsign/tls", dir)
	}
}
