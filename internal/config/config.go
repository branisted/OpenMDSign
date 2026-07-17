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

	// Daemon holds settings for the `openmdsignd` local HTTPS daemon. These are
	// consumed only by the daemon front-end; the CLI ignores them.
	Daemon DaemonConfig `toml:"daemon"`
}

// DaemonConfig holds tunables for the `openmdsignd` browser⇄daemon HTTPS server
// (see docs/PROTOCOL.md). Every field has a built-in default (see DefaultDaemon)
// so an empty [daemon] table still yields a working, spec-faithful listener.
type DaemonConfig struct {
	// HTTPSAddr is the loopback listen address for the primary TLS channel.
	// PROTOCOL.md §1: https://localhost.cts.md:18443 (loopback only).
	HTTPSAddr string `toml:"https_addr"`

	// HTTPAddr, when non-empty, additionally binds the plain-HTTP probe listener
	// (PROTOCOL.md §1: 127.0.0.1:18480). Empty disables it.
	HTTPAddr string `toml:"http_addr"`

	// Hostname is the TLS server name the browser is hardcoded to reach
	// (PROTOCOL.md §2: localhost.cts.md). It must resolve to 127.0.0.1.
	Hostname string `toml:"hostname"`

	// CORSAllowlist is the STRICT set of origins echoed back in
	// Access-Control-Allow-Origin (PROTOCOL.md §3). An Origin outside this list
	// receives NO ACAO header. Never reflect-any.
	CORSAllowlist []string `toml:"cors_allowlist"`

	// DevCertDir, when non-empty, is where the self-signed dev cert+key for
	// Hostname are cached (dev-cert.pem / dev-key.pem). Empty keeps them
	// in-memory only. The real publicly-trusted-cert trust gate is Daemon
	// Phase D — this dev cert is a stand-in and installs no trust anchor.
	DevCertDir string `toml:"dev_cert_dir"`
}

// Default returns the built-in defaults (all zero/empty except Daemon, which
// carries its spec-faithful defaults so the daemon works out of the box).
func Default() Config {
	return Config{Daemon: DefaultDaemon()}
}

// DefaultDaemon returns the built-in daemon defaults straight from PROTOCOL.md.
func DefaultDaemon() DaemonConfig {
	return DaemonConfig{
		HTTPSAddr:     "127.0.0.1:18443",
		HTTPAddr:      "", // plain-HTTP probe listener disabled unless configured
		Hostname:      "localhost.cts.md",
		CORSAllowlist: []string{"https://msign.gov.md", "https://mpass.gov.md"},
		DevCertDir:    "",
	}
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
