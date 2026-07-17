package token

import (
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// trim cleans the space-padded fixed-width strings PKCS#11 returns.
func trim(s string) string {
	return strings.TrimRight(s, " \x00")
}

func verString(v pkcs11.Version) string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// bytesToUint decodes a CK_ULONG attribute value. PKCS#11 returns these in the
// platform's native byte order; on macOS arm64/x86_64 that is little-endian.
func bytesToUint(b []byte) uint64 {
	var v uint64
	for i := 0; i < len(b) && i < 8; i++ {
		v |= uint64(b[i]) << (8 * uint(i))
	}
	return v
}

func slotFlagStrings(flags uint) []string {
	var out []string
	if flags&pkcs11.CKF_TOKEN_PRESENT != 0 {
		out = append(out, "CKF_TOKEN_PRESENT")
	}
	if flags&pkcs11.CKF_REMOVABLE_DEVICE != 0 {
		out = append(out, "CKF_REMOVABLE_DEVICE")
	}
	if flags&pkcs11.CKF_HW_SLOT != 0 {
		out = append(out, "CKF_HW_SLOT")
	}
	return out
}

func tokenFlagStrings(flags uint) []string {
	pairs := []struct {
		bit  uint
		name string
	}{
		{pkcs11.CKF_RNG, "CKF_RNG"},
		{pkcs11.CKF_WRITE_PROTECTED, "CKF_WRITE_PROTECTED"},
		{pkcs11.CKF_LOGIN_REQUIRED, "CKF_LOGIN_REQUIRED"},
		{pkcs11.CKF_USER_PIN_INITIALIZED, "CKF_USER_PIN_INITIALIZED"},
		{pkcs11.CKF_RESTORE_KEY_NOT_NEEDED, "CKF_RESTORE_KEY_NOT_NEEDED"},
		{pkcs11.CKF_CLOCK_ON_TOKEN, "CKF_CLOCK_ON_TOKEN"},
		{pkcs11.CKF_PROTECTED_AUTHENTICATION_PATH, "CKF_PROTECTED_AUTHENTICATION_PATH"},
		{pkcs11.CKF_DUAL_CRYPTO_OPERATIONS, "CKF_DUAL_CRYPTO_OPERATIONS"},
		{pkcs11.CKF_TOKEN_INITIALIZED, "CKF_TOKEN_INITIALIZED"},
		{pkcs11.CKF_SECONDARY_AUTHENTICATION, "CKF_SECONDARY_AUTHENTICATION"},
		{pkcs11.CKF_USER_PIN_COUNT_LOW, "CKF_USER_PIN_COUNT_LOW"},
		{pkcs11.CKF_USER_PIN_FINAL_TRY, "CKF_USER_PIN_FINAL_TRY"},
		{pkcs11.CKF_USER_PIN_LOCKED, "CKF_USER_PIN_LOCKED"},
		{pkcs11.CKF_USER_PIN_TO_BE_CHANGED, "CKF_USER_PIN_TO_BE_CHANGED"},
		{pkcs11.CKF_SO_PIN_COUNT_LOW, "CKF_SO_PIN_COUNT_LOW"},
		{pkcs11.CKF_SO_PIN_FINAL_TRY, "CKF_SO_PIN_FINAL_TRY"},
		{pkcs11.CKF_SO_PIN_LOCKED, "CKF_SO_PIN_LOCKED"},
		{pkcs11.CKF_SO_PIN_TO_BE_CHANGED, "CKF_SO_PIN_TO_BE_CHANGED"},
	}
	var out []string
	for _, p := range pairs {
		if flags&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}

func objectClassName(class uint) string {
	switch class {
	case pkcs11.CKO_DATA:
		return "CKO_DATA"
	case pkcs11.CKO_CERTIFICATE:
		return "CKO_CERTIFICATE"
	case pkcs11.CKO_PUBLIC_KEY:
		return "CKO_PUBLIC_KEY"
	case pkcs11.CKO_PRIVATE_KEY:
		return "CKO_PRIVATE_KEY"
	case pkcs11.CKO_SECRET_KEY:
		return "CKO_SECRET_KEY"
	default:
		return fmt.Sprintf("CKO_0x%08X", class)
	}
}

func keyTypeName(kt uint64) string {
	switch kt {
	case pkcs11.CKK_RSA:
		return "RSA"
	case pkcs11.CKK_DSA:
		return "DSA"
	case pkcs11.CKK_DH:
		return "DH"
	case pkcs11.CKK_EC:
		return "EC"
	case pkcs11.CKK_AES:
		return "AES"
	default:
		return fmt.Sprintf("CKK_0x%X", kt)
	}
}
