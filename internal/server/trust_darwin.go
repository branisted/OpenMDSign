//go:build darwin

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

// NewTrustStore returns the macOS `security`-backed trust store for the serving
// cert in store. It shells to the real `security` binary; the login-keychain
// path defaults to ~/Library/Keychains/login.keychain-db.
func NewTrustStore(store CertStore) TrustStore {
	return securityTrustStore{
		store:    store,
		keychain: loginKeychainPath(),
		run:      execRunner,
	}
}

// loginKeychainPath resolves the current user's login keychain. Modern macOS
// stores it as login.keychain-db; fall back to the legacy name if that is
// absent so older systems still work.
func loginKeychainPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "login.keychain-db"
	}
	dbPath := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	if _, err := os.Stat(dbPath); err == nil {
		return dbPath
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain")
}

// execRunner is the production CommandRunner: it runs the command and returns
// its combined stdout+stderr.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
