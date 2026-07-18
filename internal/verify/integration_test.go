package verify

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Integration tests run against the real, git-ignored signed fixtures in
// sign-out/ and signed-samples/. They are gated behind OPENMDSIGN_VERIFY_IT=1
// because those artifacts are not committed (they embed a real qualified
// certificate with personal data). The assertions here check only structural
// facts — never hardcoded personal values — so nothing personal ends up in the
// repo even though a local run may print the signer's name to stdout.
func requireIT(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENMDSIGN_VERIFY_IT") != "1" {
		t.Skip("set OPENMDSIGN_VERIFY_IT=1 to run against the real signed fixtures")
	}
}

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func TestIT_PAdES(t *testing.T) {
	requireIT(t)
	file := repoPath("sign-out", "test.signed.pdf")
	if _, err := os.Stat(file); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	res, err := Run(context.Background(), Options{Profile: "auto", FilePath: file})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Profile != "pades" {
		t.Errorf("profile = %q, want pades", res.Profile)
	}
	if res.Signer.SignatureValid == nil || !*res.Signer.SignatureValid {
		t.Error("expected CMS signature to be cryptographically valid")
	}
	if res.Chain.Status != "trusted" {
		t.Errorf("chain status = %q (%s), want trusted", res.Chain.Status, res.Chain.Detail)
	}
	if res.Overall != Valid {
		t.Errorf("overall = %q (%s), want VALID", res.Overall, res.Reason)
	}
	if res.Timestamp == nil || res.Timestamp.Time == "" {
		t.Error("expected an RFC 3161 signature timestamp")
	}
	// Structural: a MoldSign qualified cert carries an IDNP in subject serialNumber.
	if res.Signer.IDNP == "" {
		t.Error("expected an IDNP (subject serialNumber) on the signer certificate")
	}
	t.Logf("PAdES overall=%s chain-anchor=%s tsa=%s", res.Overall, res.Chain.Anchor, tsName(res))
}

func TestIT_XAdES(t *testing.T) {
	requireIT(t)
	file := repoPath("sign-out", "test.xades.xml")
	original := repoPath("test.txt")
	jar := repoPath("java", "dss-helper", "target", "dss-helper.jar")
	if _, err := os.Stat(file); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	if _, err := os.Stat(jar); err != nil {
		t.Skipf("DSS helper jar missing (build it): %v", err)
	}
	res, err := Run(context.Background(), Options{
		Profile:      "auto",
		FilePath:     file,
		OriginalPath: original,
		JarPath:      jar,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Profile != "xades" {
		t.Errorf("profile = %q, want xades", res.Profile)
	}
	// The whole point of seeding DSS with the anchors: no more
	// NO_CERTIFICATE_CHAIN_FOUND. Offline we expect a real indication.
	if res.Indication == "" {
		t.Error("expected a DSS indication")
	}
	if res.SubIndication == "NO_CERTIFICATE_CHAIN_FOUND" {
		t.Errorf("got NO_CERTIFICATE_CHAIN_FOUND; anchors were not seeded")
	}
	if res.Overall == Invalid {
		t.Errorf("did not expect INVALID offline; got indication=%s/%s", res.Indication, res.SubIndication)
	}
	t.Logf("XAdES overall=%s indication=%s/%s", res.Overall, res.Indication, res.SubIndication)
}

func tsName(res *Result) string {
	if res.Timestamp == nil {
		return ""
	}
	return res.Timestamp.TSA
}
