package token

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// Mechanisms of particular interest for signing interop. openmdsign reports
// explicitly whether each is present so a reviewer can decide between on-token
// hashing (CKM_SHA256_RSA_PKCS) and raw signing (CKM_RSA_PKCS).
const (
	CKM_RSA_PKCS            = pkcs11.CKM_RSA_PKCS
	CKM_SHA256              = pkcs11.CKM_SHA256
	CKM_SHA256_RSA_PKCS     = pkcs11.CKM_SHA256_RSA_PKCS
	CKM_RSA_PKCS_PSS        = pkcs11.CKM_RSA_PKCS_PSS
	CKM_SHA256_RSA_PKCS_PSS = pkcs11.CKM_SHA256_RSA_PKCS_PSS
)

// mechNames maps common CKM_* codes to their symbolic names.
var mechNames = map[uint]string{
	pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN:  "CKM_RSA_PKCS_KEY_PAIR_GEN",
	pkcs11.CKM_RSA_PKCS:               "CKM_RSA_PKCS",
	pkcs11.CKM_RSA_9796:               "CKM_RSA_9796",
	pkcs11.CKM_RSA_X_509:              "CKM_RSA_X_509",
	pkcs11.CKM_MD5_RSA_PKCS:           "CKM_MD5_RSA_PKCS",
	pkcs11.CKM_SHA1_RSA_PKCS:          "CKM_SHA1_RSA_PKCS",
	pkcs11.CKM_RSA_PKCS_OAEP:          "CKM_RSA_PKCS_OAEP",
	pkcs11.CKM_RSA_PKCS_PSS:           "CKM_RSA_PKCS_PSS",
	pkcs11.CKM_SHA1_RSA_PKCS_PSS:      "CKM_SHA1_RSA_PKCS_PSS",
	pkcs11.CKM_SHA256_RSA_PKCS:        "CKM_SHA256_RSA_PKCS",
	pkcs11.CKM_SHA384_RSA_PKCS:        "CKM_SHA384_RSA_PKCS",
	pkcs11.CKM_SHA512_RSA_PKCS:        "CKM_SHA512_RSA_PKCS",
	pkcs11.CKM_SHA256_RSA_PKCS_PSS:    "CKM_SHA256_RSA_PKCS_PSS",
	pkcs11.CKM_SHA384_RSA_PKCS_PSS:    "CKM_SHA384_RSA_PKCS_PSS",
	pkcs11.CKM_SHA512_RSA_PKCS_PSS:    "CKM_SHA512_RSA_PKCS_PSS",
	pkcs11.CKM_SHA224_RSA_PKCS:        "CKM_SHA224_RSA_PKCS",
	pkcs11.CKM_SHA224_RSA_PKCS_PSS:    "CKM_SHA224_RSA_PKCS_PSS",
	pkcs11.CKM_MD5:                    "CKM_MD5",
	pkcs11.CKM_SHA_1:                  "CKM_SHA_1",
	pkcs11.CKM_SHA224:                 "CKM_SHA224",
	pkcs11.CKM_SHA256:                 "CKM_SHA256",
	pkcs11.CKM_SHA384:                 "CKM_SHA384",
	pkcs11.CKM_SHA512:                 "CKM_SHA512",
	pkcs11.CKM_EC_KEY_PAIR_GEN:        "CKM_EC_KEY_PAIR_GEN",
	pkcs11.CKM_ECDSA:                  "CKM_ECDSA",
	pkcs11.CKM_ECDSA_SHA1:             "CKM_ECDSA_SHA1",
	pkcs11.CKM_ECDSA_SHA256:           "CKM_ECDSA_SHA256",
	pkcs11.CKM_ECDSA_SHA384:           "CKM_ECDSA_SHA384",
	pkcs11.CKM_ECDSA_SHA512:           "CKM_ECDSA_SHA512",
	pkcs11.CKM_AES_KEY_GEN:            "CKM_AES_KEY_GEN",
	pkcs11.CKM_AES_CBC:                "CKM_AES_CBC",
	pkcs11.CKM_AES_ECB:                "CKM_AES_ECB",
	pkcs11.CKM_GENERIC_SECRET_KEY_GEN: "CKM_GENERIC_SECRET_KEY_GEN",
}

// MechName returns the symbolic name for a CKM_* code, falling back to hex.
func MechName(code uint) string {
	if n, ok := mechNames[code]; ok {
		return n
	}
	return fmt.Sprintf("CKM_0x%08X", code)
}

// mechFlagStrings renders the sign/verify/hw-relevant flags of a mechanism.
func mechFlagStrings(flags uint) []string {
	var out []string
	pairs := []struct {
		bit  uint
		name string
	}{
		{pkcs11.CKF_HW, "hw"},
		{pkcs11.CKF_ENCRYPT, "encrypt"},
		{pkcs11.CKF_DECRYPT, "decrypt"},
		{pkcs11.CKF_DIGEST, "digest"},
		{pkcs11.CKF_SIGN, "sign"},
		{pkcs11.CKF_SIGN_RECOVER, "sign-recover"},
		{pkcs11.CKF_VERIFY, "verify"},
		{pkcs11.CKF_VERIFY_RECOVER, "verify-recover"},
		{pkcs11.CKF_GENERATE, "generate"},
		{pkcs11.CKF_GENERATE_KEY_PAIR, "generate-key-pair"},
		{pkcs11.CKF_WRAP, "wrap"},
		{pkcs11.CKF_UNWRAP, "unwrap"},
		{pkcs11.CKF_DERIVE, "derive"},
	}
	for _, p := range pairs {
		if flags&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}
