//go:build !darwin

package server

// NewTrustStore returns the non-macOS stub: trust management (login-keychain
// SSL anchors) is a darwin-only capability, so every mutating operation reports
// ErrTrustUnsupported. Status still reports the on-disk cert presence.
func NewTrustStore(store CertStore) TrustStore {
	return unsupportedTrustStore{store: store}
}
