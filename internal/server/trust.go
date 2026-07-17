package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ErrTrustUnsupported is returned by the trust store on non-macOS platforms.
var ErrTrustUnsupported = errors.New("trust management is only supported on macOS (darwin)")

// CommandRunner executes an external command and returns its combined output.
// It is the single seam through which the trust store shells to macOS
// `security`; tests inject a fake to assert the exact argv WITHOUT ever touching
// the real keychain.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// TrustStatus is the read-only result of TrustStore.Status.
type TrustStatus struct {
	// CertExists reports whether the persistent serving cert is present on disk.
	CertExists bool
	// Trusted reports whether the serving cert is a trusted SSL anchor in the
	// login keychain (per `security dump-trust-settings`).
	Trusted bool
	// Expired reports an on-disk cert that is past its NotAfter.
	Expired bool
	// CertPath is the on-disk cert location (for user-facing messages).
	CertPath string
}

// TrustStore manages the OS trust state of the serving cert. Install/Uninstall
// mutate the login keychain (prompting the user for their password); Status is
// strictly read-only. announce, when non-nil, is called with the EXACT command
// text a mutation will run, BEFORE it runs, so the caller can print it.
type TrustStore interface {
	Install(ctx context.Context, announce func(string)) error
	Uninstall(ctx context.Context, announce func(string)) error
	Status(ctx context.Context) (TrustStatus, error)
}

// securityTrustStore drives macOS `security` via an injectable CommandRunner.
// It is compiled on every platform (the argv is pure string-building and thus
// unit-testable anywhere); only newDefaultTrustStore wires the real `security`
// exec runner, and only on darwin.
type securityTrustStore struct {
	store    CertStore
	keychain string // login keychain path
	run      CommandRunner
}

// securityAddTrustedCertArgs builds the argv that imports the leaf into the
// login keychain AND marks it a trusted SSL root:
//
//	security add-trusted-cert -r trustRoot -p ssl -k <loginKeychain> <certPath>
//
// No -d (admin/system domain) ⇒ the change lands in the USER domain and prompts
// only for the login-keychain password, not sudo.
func securityAddTrustedCertArgs(certPath, keychain string) []string {
	return []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", keychain, certPath}
}

// securityRemoveTrustedCertArgs removes the user-domain SSL trust settings:
//
//	security remove-trusted-cert <certPath>
func securityRemoveTrustedCertArgs(certPath string) []string {
	return []string{"remove-trusted-cert", certPath}
}

// securityDeleteCertificateArgs deletes the cert from the login keychain by
// common name:
//
//	security delete-certificate -c <hostname> <loginKeychain>
func securityDeleteCertificateArgs(hostname, keychain string) []string {
	return []string{"delete-certificate", "-c", hostname, keychain}
}

// securityDumpTrustSettingsArgs dumps the USER-domain trust settings (no -d),
// which `Status` scans for the serving cert's common name.
func securityDumpTrustSettingsArgs() []string {
	return []string{"dump-trust-settings"}
}

func (s securityTrustStore) Install(ctx context.Context, announce func(string)) error {
	// Ensure the persistent per-machine cert exists before trusting it.
	if _, err := s.store.EnsureCert(); err != nil {
		return fmt.Errorf("ensure serving cert: %w", err)
	}
	args := securityAddTrustedCertArgs(s.store.CertPath(), s.keychain)
	if announce != nil {
		announce("security " + strings.Join(args, " "))
	}
	if out, err := s.run(ctx, "security", args...); err != nil {
		return fmt.Errorf("security add-trusted-cert: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s securityTrustStore) Uninstall(ctx context.Context, announce func(string)) error {
	// Idempotent: tolerate "not found" from either command so re-running on an
	// already-clean machine is a no-op rather than an error.
	removeArgs := securityRemoveTrustedCertArgs(s.store.CertPath())
	deleteArgs := securityDeleteCertificateArgs(s.store.Hostname, s.keychain)
	if announce != nil {
		announce("security " + strings.Join(removeArgs, " "))
		announce("security " + strings.Join(deleteArgs, " "))
		announce("rm -f " + s.store.CertPath() + " " + s.store.KeyPath())
	}
	// remove-trusted-cert only matters if trust is set; ignore its error.
	_, _ = s.run(ctx, "security", removeArgs...)
	// delete-certificate errors when the cert is absent; ignore that too.
	_, _ = s.run(ctx, "security", deleteArgs...)
	// Leave the machine clean: drop the on-disk cert+key (absent ⇒ no error).
	if err := os.Remove(s.store.CertPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove serving cert file: %w", err)
	}
	if err := os.Remove(s.store.KeyPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove serving key file: %w", err)
	}
	return nil
}

func (s securityTrustStore) Status(ctx context.Context) (TrustStatus, error) {
	st := TrustStatus{CertPath: s.store.CertPath()}
	if leaf, ok := s.store.LoadLeaf(); ok {
		st.CertExists = true
		st.Expired = leaf.NotAfter.Before(time.Now())
	}
	// dump-trust-settings lists trusted certs by common name; a match on our
	// hostname means the serving cert is a trusted anchor in the user domain.
	out, err := s.run(ctx, "security", securityDumpTrustSettingsArgs()...)
	if err != nil {
		// `security dump-trust-settings` exits non-zero when the user domain has
		// NO trust settings at all — that is simply "not trusted", not a failure.
		return st, nil
	}
	if strings.Contains(string(out), s.store.Hostname) {
		st.Trusted = true
	}
	return st, nil
}

// unsupportedTrustStore is the non-darwin stub: every operation reports the
// platform is unsupported. It is also exercised directly by tests.
type unsupportedTrustStore struct{ store CertStore }

func (u unsupportedTrustStore) Install(context.Context, func(string)) error {
	return ErrTrustUnsupported
}
func (u unsupportedTrustStore) Uninstall(context.Context, func(string)) error {
	return ErrTrustUnsupported
}
func (u unsupportedTrustStore) Status(context.Context) (TrustStatus, error) {
	// Report what we can read locally (the cert file), but flag no trust info.
	st := TrustStatus{CertPath: u.store.CertPath()}
	if leaf, ok := u.store.LoadLeaf(); ok {
		st.CertExists = true
		st.Expired = leaf.NotAfter.Before(time.Now())
	}
	return st, ErrTrustUnsupported
}
