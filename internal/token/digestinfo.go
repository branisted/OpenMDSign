package token

// sha256DigestInfoPrefix is the fixed ASN.1 DigestInfo prefix for a SHA-256
// digest in PKCS#1 v1.5, i.e. the DER of
//
//	DigestInfo ::= SEQUENCE {
//	    digestAlgorithm AlgorithmIdentifier{{ id-sha256, NULL }},
//	    digest          OCTET STRING(32) }
//
// with the trailing 32-byte digest omitted. Concatenating this prefix with the
// raw SHA-256 digest yields the exact byte string the token must raw-sign under
// CKM_RSA_PKCS to produce a standard RSASSA-PKCS1-v1_5 signature. This matches
// what crypto/rsa prepends internally for crypto.SHA256.
var sha256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20,
}

// DigestInfoSHA256 returns the DER-encoded PKCS#1 v1.5 DigestInfo for a SHA-256
// digest. Signing this raw with CKM_RSA_PKCS yields a standard RSASSA-PKCS1-v1_5
// signature. The single canonical implementation lives here so both the
// sign-raw command and the crypto.Signer adapter build the identical bytes.
func DigestInfoSHA256(digest []byte) []byte {
	out := make([]byte, 0, len(sha256DigestInfoPrefix)+len(digest))
	out = append(out, sha256DigestInfoPrefix...)
	out = append(out, digest...)
	return out
}
