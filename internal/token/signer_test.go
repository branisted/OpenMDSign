package token

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// TestDigestInfoSHA256Prefix pins the exact 19-byte SHA-256 DigestInfo prefix.
func TestDigestInfoSHA256Prefix(t *testing.T) {
	di := DigestInfoSHA256(make([]byte, 32))
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

// TestTokenSignerDigestPathVerifies proves the exact byte hand-off the token
// Signer.Sign performs -- raw RSASSA-PKCS1-v1_5 over DigestInfoSHA256(digest) --
// produces a signature that verifies with the standard rsa.VerifyPKCS1v15, i.e.
// the DigestInfo path is correct for what digitorus/pkcs7 (and any RSA verifier)
// expects. This is done with a SOFTWARE key: C_Sign under CKM_RSA_PKCS is exactly
// rsa.SignPKCS1v15(key, crypto.Hash(0), DigestInfo).
func TestTokenSignerDigestPathVerifies(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// This is exactly what pkcs7.signAttributes hands to signer.Sign:
	// hash = SHA256(signedAttrs), opts = crypto.SHA256.
	attrs := []byte("marshaled signed attributes stand-in")
	digest := sha256.Sum256(attrs)

	// Emulate Signer.Sign's on-token step: raw CKM_RSA_PKCS over the DigestInfo.
	payload := DigestInfoSHA256(digest[:])
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), payload)
	if err != nil {
		t.Fatalf("raw sign DigestInfo: %v", err)
	}

	// A standard verifier must accept it as a SHA-256 PKCS#1 v1.5 signature.
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("VerifyPKCS1v15 rejected the token-path signature: %v", err)
	}

	// And it must be byte-identical to the standard library building DigestInfo.
	ref, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("reference sign: %v", err)
	}
	if !bytes.Equal(sig, ref) {
		t.Fatalf("token-path signature != standard SHA-256 signature")
	}
}
