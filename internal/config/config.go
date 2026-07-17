// Package config loads openmdsign configuration with precedence:
// command-line flags > config file (TOML) > built-in defaults.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config holds all tunable settings for openmdsign.
//
// Only fields relevant to Phase 0 (recon) are wired into behavior today; the
// remainder (CAChain, OCSPURL, TSAURL) are parsed and carried forward so that
// signing phases can consume them without a config format change.
type Config struct {
	// Module is the filesystem path to the vendor PKCS#11 shared object
	// (a .dylib on macOS). This is ALWAYS supplied by the user and is never
	// hardcoded or redistributed with openmdsign.
	Module string `toml:"module"`

	// Slot optionally pins a specific PKCS#11 slot ID. When nil, openmdsign
	// enumerates all slots.
	Slot *uint `toml:"slot"`

	// TokenLabel optionally selects a token by its CKA/CK_TOKEN_INFO label.
	TokenLabel string `toml:"token_label"`

	// KeyID optionally selects a key/cert by CKA_ID, expressed in hex.
	KeyID string `toml:"key_id"`

	// CAChain is a path to a PEM bundle of intermediate/root CAs (signing).
	CAChain string `toml:"ca_chain"`

	// OCSPURL overrides the OCSP responder URL (otherwise taken from the
	// certificate's Authority Information Access extension).
	OCSPURL string `toml:"ocsp_url"`

	// TSAURL is the RFC 3161 timestamp authority URL (signing).
	TSAURL string `toml:"tsa_url"`
}

// Default returns the built-in defaults (all zero/empty).
func Default() Config {
	return Config{}
}

// LoadFile reads and parses a TOML config file at path. A missing file is not
// an error when required is false; instead the defaults are returned.
func LoadFile(path string, required bool) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}

// FileExists reports whether a regular file exists at path.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
