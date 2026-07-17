package xades

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/branistedev/openmdsign/internal/sign"
)

// TestXAdESIntegration drives the full two-step external-signing flow against
// the real EU DSS helper jar with a SOFTWARE RSA key/cert (no hardware, no PIN),
// and asserts the produced XAdES matches docs/profile-spec.md §1.
//
// Gated: it needs the built jar (OPENMDSIGN_DSS_HELPER) and a Java 21 runtime;
// the -T subtest additionally needs network access to the TSA. Set
// OPENMDSIGN_XADES_IT=1 to run. It is skipped in a plain `go test ./...`.
func TestXAdESIntegration(t *testing.T) {
	if os.Getenv("OPENMDSIGN_XADES_IT") != "1" {
		t.Skip("set OPENMDSIGN_XADES_IT=1 (and OPENMDSIGN_DSS_HELPER) to run the DSS jar integration test")
	}
	jar := os.Getenv("OPENMDSIGN_DSS_HELPER")
	if jar == "" {
		t.Skip("OPENMDSIGN_DSS_HELPER (path to dss-helper.jar) not set")
	}
	javaPath := os.Getenv("OPENMDSIGN_JAVA") // may be empty -> resolved from env

	// Software RSA key + self-signed certificate (stands in for the token).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "OpenMDSign IT", Organization: []string{"Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	fileBytes := []byte("openmdsign xades integration fixture\n")
	wantDigest := base64.StdEncoding.EncodeToString(sha256Sum(fileBytes))

	tests := []struct {
		name      string
		level     sign.Level
		packaging sign.Packaging
		wantTS    bool
	}{
		{"detached-B", sign.LevelB, sign.PackagingDetached, false},
		{"detached-T", sign.LevelT, sign.PackagingDetached, true},
		{"enveloping-T", sign.LevelT, sign.PackagingEnveloping, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "sig.xml")
			res, err := New(javaPath).Sign(context.Background(), sign.Request{
				InputPDF:    fileBytes,
				InputName:   "fixture.txt",
				OutputPath:  out,
				Signer:      key, // *rsa.PrivateKey implements crypto.Signer
				Certificate: cert,
				Level:       tc.level,
				TSAURL:      "http://tsp.pki.gov.md/moldsign2/",
				Packaging:   tc.packaging,
				Digest:      "sha256",
				HelperJar:   jar,
			})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if res.TimestampApplied != tc.wantTS {
				t.Errorf("TimestampApplied=%v, want %v", res.TimestampApplied, tc.wantTS)
			}
			xml := readFile(t, out)

			// Namespaces: xmldsig + XAdES v1.3.2.
			assertContains(t, xml, `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`, "xmldsig ns")
			assertContains(t, xml, `xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"`, "xades v1.3.2 ns")
			// Algorithms.
			assertContains(t, xml, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "rsa-sha256")
			assertContains(t, xml, "http://www.w3.org/2001/04/xmlenc#sha256", "sha256 digest")
			// SigningCertificate v1 present, V2 absent.
			assertContains(t, xml, "<xades:SigningCertificate>", "v1 SigningCertificate")
			if strings.Contains(xml, "SigningCertificateV2") {
				t.Error("SigningCertificateV2 present but must be absent (need the v1 form)")
			}
			// KeyInfo carries the signer cert only.
			signerCertB64 := base64.StdEncoding.EncodeToString(cert.Raw)
			assertContains(t, xml, signerCertB64, "signer certificate in X509Data")
			// Description must not leak any path (best: absent entirely).
			if strings.Contains(xml, "<xades:Description>") {
				t.Error("DataObjectFormat Description present; the profile forbids leaking a path")
			}

			switch tc.packaging {
			case sign.PackagingDetached:
				// Plain C14N (no WithComments) for detached SignedInfo.
				assertContains(t, xml,
					`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>`,
					"plain C14N")
				if strings.Contains(xml, "REC-xml-c14n-20010315#WithComments") {
					t.Error("detached must NOT use the #WithComments C14N variant")
				}
				// file:/<basename> reference over the raw bytes.
				assertContains(t, xml, `URI="file:/fixture.txt"`, "file:/ reference URI")
				if !fileRefDigestMatches(xml, wantDigest) {
					t.Errorf("detached file reference digest != SHA-256 of raw bytes (want %s)", wantDigest)
				}
			case sign.PackagingEnveloping:
				assertContains(t, xml, "<ds:Object", "enveloping ds:Object")
				embedded := base64.StdEncoding.EncodeToString(fileBytes)
				assertContains(t, xml, embedded, "base64 file body embedded in ds:Object")
			}

			if tc.wantTS {
				assertContains(t, xml, "<xades:SignatureTimeStamp", "SignatureTimeStamp")
				assertContains(t, xml, "<xades:EncapsulatedTimeStamp", "EncapsulatedTimeStamp")
			}
			t.Logf("%s: %d bytes, %s", tc.name, res.Bytes, out)
		})
	}
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertContains(t *testing.T, hay, needle, what string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Errorf("missing %s (%q)", what, needle)
	}
}

// fileRefDigestMatches confirms the ds:Reference with URI="file:/..." carries a
// DigestValue equal to want (the SHA-256 of the raw file bytes).
func fileRefDigestMatches(xml, want string) bool {
	re := regexp.MustCompile(`URI="file:/[^"]*".*?<ds:DigestValue>([^<]+)</ds:DigestValue>`)
	m := re.FindStringSubmatch(strings.ReplaceAll(xml, "\n", ""))
	return len(m) == 2 && m[1] == want
}
