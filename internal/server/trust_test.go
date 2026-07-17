package server

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// recordedCall captures one invocation of the fake CommandRunner.
type recordedCall struct {
	name string
	args []string
}

// fakeRunner records every command and returns canned output/error per call.
// It NEVER executes anything — the real keychain is never touched.
type fakeRunner struct {
	calls  []recordedCall
	out    []byte
	err    error
	perArg map[string]fakeResult // keyed by first arg (the security subcommand)
}

type fakeResult struct {
	out []byte
	err error
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, recordedCall{name: name, args: args})
	if f.perArg != nil && len(args) > 0 {
		if r, ok := f.perArg[args[0]]; ok {
			return r.out, r.err
		}
	}
	return f.out, f.err
}

func newTestStore(t *testing.T) (CertStore, string) {
	t.Helper()
	dir := t.TempDir()
	return CertStore{Hostname: testHost, Dir: dir}, "/Users/tester/Library/Keychains/login.keychain-db"
}

func TestTrustInstallBuildsArgvAndEnsuresCert(t *testing.T) {
	store, keychain := newTestStore(t)
	fr := &fakeRunner{}
	ts := securityTrustStore{store: store, keychain: keychain, run: fr.run}

	var announced []string
	if err := ts.Install(context.Background(), func(s string) { announced = append(announced, s) }); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// The cert must have been generated on disk before trusting it.
	if _, ok := store.LoadLeaf(); !ok {
		t.Fatalf("Install did not create the serving cert")
	}
	if len(fr.calls) != 1 {
		t.Fatalf("want 1 security call, got %d: %+v", len(fr.calls), fr.calls)
	}
	want := []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", keychain, store.CertPath()}
	if !equalArgs(fr.calls[0].args, want) {
		t.Errorf("argv = %v, want %v", fr.calls[0].args, want)
	}
	if fr.calls[0].name != "security" {
		t.Errorf("command = %q, want security", fr.calls[0].name)
	}
	// The announce callback must have shown the exact command before running it.
	joined := strings.Join(announced, "\n")
	if !strings.Contains(joined, "security add-trusted-cert -r trustRoot -p ssl -k "+keychain) {
		t.Errorf("announce did not include the install command: %q", joined)
	}
}

func TestTrustInstallIdempotent(t *testing.T) {
	store, keychain := newTestStore(t)
	fr := &fakeRunner{}
	ts := securityTrustStore{store: store, keychain: keychain, run: fr.run}
	for i := 0; i < 2; i++ {
		if err := ts.Install(context.Background(), nil); err != nil {
			t.Fatalf("Install #%d: %v", i, err)
		}
	}
	if len(fr.calls) != 2 {
		t.Errorf("want 2 calls across 2 installs, got %d", len(fr.calls))
	}
}

func TestTrustInstallPropagatesSecurityError(t *testing.T) {
	store, keychain := newTestStore(t)
	fr := &fakeRunner{out: []byte("SecKeychainItemImport: authorization denied"), err: errors.New("exit 1")}
	ts := securityTrustStore{store: store, keychain: keychain, run: fr.run}
	if err := ts.Install(context.Background(), nil); err == nil {
		t.Fatalf("Install: want error, got nil")
	}
}

func TestTrustUninstallBuildsArgvAndCleansFiles(t *testing.T) {
	store, keychain := newTestStore(t)
	// Seed an installed cert.
	if _, err := store.EnsureCert(); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	fr := &fakeRunner{}
	ts := securityTrustStore{store: store, keychain: keychain, run: fr.run}

	if err := ts.Uninstall(context.Background(), nil); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("want 2 security calls, got %d: %+v", len(fr.calls), fr.calls)
	}
	wantRemove := []string{"remove-trusted-cert", store.CertPath()}
	if !equalArgs(fr.calls[0].args, wantRemove) {
		t.Errorf("remove argv = %v, want %v", fr.calls[0].args, wantRemove)
	}
	wantDelete := []string{"delete-certificate", "-c", testHost, keychain}
	if !equalArgs(fr.calls[1].args, wantDelete) {
		t.Errorf("delete argv = %v, want %v", fr.calls[1].args, wantDelete)
	}
	// Files are gone (machine left clean).
	if _, err := os.Stat(store.CertPath()); !os.IsNotExist(err) {
		t.Errorf("cert file still present after uninstall: %v", err)
	}
	if _, err := os.Stat(store.KeyPath()); !os.IsNotExist(err) {
		t.Errorf("key file still present after uninstall: %v", err)
	}
}

func TestTrustUninstallIdempotentToleratesSecurityErrors(t *testing.T) {
	store, keychain := newTestStore(t)
	// Nothing installed; security commands would fail — Uninstall must tolerate it.
	fr := &fakeRunner{err: errors.New("exit 1"), out: []byte("not found")}
	ts := securityTrustStore{store: store, keychain: keychain, run: fr.run}
	if err := ts.Uninstall(context.Background(), nil); err != nil {
		t.Fatalf("Uninstall on clean machine returned error: %v", err)
	}
}

func TestTrustStatusReadOnly(t *testing.T) {
	store, keychain := newTestStore(t)
	if _, err := store.EnsureCert(); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	// dump-trust-settings output that mentions our hostname ⇒ trusted.
	fr := &fakeRunner{perArg: map[string]fakeResult{
		"dump-trust-settings": {out: []byte("Cert 0: " + testHost + "\n   SSL trusted\n")},
	}}
	ts := securityTrustStore{store: store, keychain: keychain, run: fr.run}

	st, err := ts.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.CertExists {
		t.Errorf("CertExists = false, want true")
	}
	if !st.Trusted {
		t.Errorf("Trusted = false, want true")
	}
	// Status must ONLY read: the single call is dump-trust-settings, never a
	// mutating add/remove/delete command.
	if len(fr.calls) != 1 || fr.calls[0].args[0] != "dump-trust-settings" {
		t.Fatalf("Status performed non-read calls: %+v", fr.calls)
	}
	for _, c := range fr.calls {
		switch c.args[0] {
		case "add-trusted-cert", "remove-trusted-cert", "delete-certificate":
			t.Errorf("Status ran a mutating command: %v", c.args)
		}
	}
}

func TestTrustStatusNotTrustedWhenDumpMissesHostname(t *testing.T) {
	store, keychain := newTestStore(t)
	if _, err := store.EnsureCert(); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	fr := &fakeRunner{perArg: map[string]fakeResult{
		"dump-trust-settings": {out: []byte("Cert 0: some.other.host\n")},
	}}
	ts := securityTrustStore{store: store, keychain: keychain, run: fr.run}
	st, err := ts.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Trusted {
		t.Errorf("Trusted = true, want false (hostname absent from dump)")
	}
}

func TestTrustStatusDumpErrorMeansNotTrusted(t *testing.T) {
	store, keychain := newTestStore(t)
	// No cert seeded, dump-trust-settings errors (no user trust settings at all).
	fr := &fakeRunner{err: errors.New("exit 1")}
	ts := securityTrustStore{store: store, keychain: keychain, run: fr.run}
	st, err := ts.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.CertExists || st.Trusted {
		t.Errorf("status = %+v, want cert absent + not trusted", st)
	}
}

func TestUnsupportedTrustStore(t *testing.T) {
	store, _ := newTestStore(t)
	u := unsupportedTrustStore{store: store}

	if err := u.Install(context.Background(), nil); !errors.Is(err, ErrTrustUnsupported) {
		t.Errorf("Install err = %v, want ErrTrustUnsupported", err)
	}
	if err := u.Uninstall(context.Background(), nil); !errors.Is(err, ErrTrustUnsupported) {
		t.Errorf("Uninstall err = %v, want ErrTrustUnsupported", err)
	}
	_, err := u.Status(context.Background())
	if !errors.Is(err, ErrTrustUnsupported) {
		t.Errorf("Status err = %v, want ErrTrustUnsupported", err)
	}
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
