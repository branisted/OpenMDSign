package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/branistedev/openmdsign/internal/token"
	"math/big"
	"testing"
	"time"
)

// TestBuildSHA256DigestInfoRoundTrip proves the rsa-pkcs hand-off is correct
// WITHOUT a token: the DigestInfo we build, when signed raw (crypto.Hash(0),
// i.e. no further prefixing), must be byte-identical to a standard
// crypto/rsa.SignPKCS1v15 signature over the digest with crypto.SHA256. That is
// exactly the equivalence the token relies on: the token performs CKM_RSA_PKCS
// (raw RSASSA over our DigestInfo) and the result must be a standard PKCS#1 v1.5
// SHA-256 signature.
func TestBuildSHA256DigestInfoRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msg := []byte("openmdsign phase 1 raw digestinfo round-trip")
	digest := sha256.Sum256(msg)

	// The bytes we would hand to the token for CKM_RSA_PKCS.
	di := token.DigestInfoSHA256(digest[:])

	// Emulate the token's raw RSASSA over the DigestInfo. crypto.Hash(0) means
	// "the input is already the DigestInfo; do not prepend a prefix".
	rawSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), di)
	if err != nil {
		t.Fatalf("raw sign DigestInfo: %v", err)
	}

	// The reference: the standard library builds the DigestInfo itself.
	refSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("reference sign: %v", err)
	}

	if !bytes.Equal(rawSig, refSig) {
		t.Fatalf("raw-signed DigestInfo != standard SHA-256 signature\n raw=%x\n ref=%x", rawSig, refSig)
	}

	// And it must verify with the standard verifier.
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], rawSig); err != nil {
		t.Fatalf("verify raw-signed DigestInfo: %v", err)
	}
}

// TestBuildSHA256DigestInfoPrefix pins the exact DigestInfo prefix bytes.
func TestBuildSHA256DigestInfoPrefix(t *testing.T) {
	digest := make([]byte, 32)
	di := token.DigestInfoSHA256(digest)
	if len(di) != 19+32 {
		t.Fatalf("DigestInfo length = %d, want %d", len(di), 19+32)
	}
	want := []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20,
	}
	if !bytes.Equal(di[:19], want) {
		t.Fatalf("prefix = %x, want %x", di[:19], want)
	}
}

// makeTestCert builds a self-signed RSA certificate DER for a keypair.
func makeTestCert(t *testing.T, key *rsa.PrivateKey, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

// TestVerifySignature exercises the in-process verify step with a software
// keypair, covering pass, tamper-fail, and missing-cert paths.
func TestVerifySignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certDER := makeTestCert(t, key, "OpenMDSign Test")
	msg := []byte("verify me")
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	t.Run("pass", func(t *testing.T) {
		err, subject := verifySignature(certDER, digest[:], sig)
		if err != nil {
			t.Fatalf("expected PASS, got: %v", err)
		}
		if subject == "" {
			t.Fatalf("expected non-empty subject")
		}
	})

	t.Run("tampered_signature", func(t *testing.T) {
		bad := bytes.Clone(sig)
		bad[len(bad)-1] ^= 0xff
		err, _ := verifySignature(certDER, digest[:], bad)
		if err == nil {
			t.Fatalf("expected verify FAIL for tampered signature")
		}
	})

	t.Run("wrong_digest", func(t *testing.T) {
		other := sha256.Sum256([]byte("different message"))
		err, _ := verifySignature(certDER, other[:], sig)
		if err == nil {
			t.Fatalf("expected verify FAIL for wrong digest")
		}
	})

	t.Run("no_certificate", func(t *testing.T) {
		err, _ := verifySignature(nil, digest[:], sig)
		if err == nil {
			t.Fatalf("expected error when no certificate is present")
		}
	})
}

func TestParseMechanism(t *testing.T) {
	cases := []struct {
		in          string
		wantErr     bool
		wantOnToken bool
		wantName    string
	}{
		{in: "sha256-rsa", wantErr: false, wantOnToken: true, wantName: "CKM_SHA256_RSA_PKCS"},
		{in: "rsa-pkcs", wantErr: false, wantOnToken: false, wantName: "CKM_RSA_PKCS"},
		{in: "SHA256-RSA", wantErr: true},
		{in: "pss", wantErr: true},
		{in: "", wantErr: true},
		{in: "rsa", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			m, err := parseMechanism(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if m.onTokenHash != tc.wantOnToken {
				t.Fatalf("%q onTokenHash = %v, want %v", tc.in, m.onTokenHash, tc.wantOnToken)
			}
			if m.name != tc.wantName {
				t.Fatalf("%q name = %q, want %q", tc.in, m.name, tc.wantName)
			}
		})
	}
}
