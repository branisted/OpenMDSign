package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/branisted/openmdsign/internal/sign"
	"github.com/branisted/openmdsign/internal/sign/pades"
	"github.com/branisted/openmdsign/internal/verify/anchors"
)

func TestAnchorsLoad(t *testing.T) {
	list, err := anchors.Load()
	if err != nil {
		t.Fatalf("anchors.Load: %v", err)
	}
	if len(list) < 3 {
		t.Fatalf("expected at least 3 embedded anchors, got %d", len(list))
	}
	// Known fingerprints (lowercase hex, no colons) recorded in anchors/README.md.
	want := map[string]string{
		"mdtrustrootca.pem": "eb8a03219c3217fb9c038713745f96210c20b829403892a0774b07083eaf04e9",
		"mdtrustca.pem":     "211a8a9cc92de6916bab2024fcea4108e72d4acfca0fb8edd294b998e4e99c06",
		"mdqsign.pem":       "ba55d94bf91c0ed032dc2cddeeeddf70810ff641f58c50e7dff2e1a1ffa067bf",
	}
	got := map[string]string{}
	for _, a := range list {
		got[a.File] = a.SHA256
		if a.Certificate == nil {
			t.Errorf("%s: nil certificate", a.File)
		}
	}
	for file, fp := range want {
		if got[file] != fp {
			t.Errorf("%s fingerprint = %q, want %q", file, got[file], fp)
		}
	}

	roots, intermediates := anchors.Pools(list)
	if roots == nil || intermediates == nil {
		t.Fatal("Pools returned a nil pool")
	}
	// mdtrustca and mdtrustrootca are self-signed roots; mdqsign is an intermediate.
	// Verify the split by inspecting SelfSigned rather than the opaque pools.
	roleSelf := map[string]bool{}
	for _, a := range list {
		roleSelf[a.File] = a.SelfSigned
	}
	if !roleSelf["mdtrustca.pem"] || !roleSelf["mdtrustrootca.pem"] {
		t.Error("expected mdtrustca and mdtrustrootca to be self-signed roots")
	}
	if roleSelf["mdqsign.pem"] {
		t.Error("expected mdqsign to be a non-self-signed intermediate")
	}
}

func TestDetectProfile(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"pdf", []byte("%PDF-1.7\n..."), "pades"},
		{"pdf-bom", append([]byte{0xEF, 0xBB, 0xBF}, []byte("%PDF-1.4")...), "pades"},
		{"xades", []byte(`<?xml version="1.0"?><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>`), "xades"},
		{"xades-leading-ws", []byte("\n  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>"), "xades"},
		{"plain-xml-no-sig", []byte(`<?xml version="1.0"?><root/>`), ""},
		{"junk", []byte("hello world"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectProfile(tc.data); got != tc.want {
				t.Errorf("DetectProfile = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveProfile(t *testing.T) {
	pdf := []byte("%PDF-1.4")
	if p, err := resolveProfile("pades", pdf); err != nil || p != "pades" {
		t.Errorf("explicit pades: %q %v", p, err)
	}
	if p, err := resolveProfile("auto", pdf); err != nil || p != "pades" {
		t.Errorf("auto pdf: %q %v", p, err)
	}
	if _, err := resolveProfile("auto", []byte("nonsense")); err == nil {
		t.Error("auto on undetectable input: expected error")
	}
	if _, err := resolveProfile("bogus", pdf); err == nil {
		t.Error("bogus profile: expected error")
	}
}

func TestTrustAnchorsExtraPEM(t *testing.T) {
	_, certPEM := selfSignedFixture(t, "OpenMDSign Verify Test Root")
	base, err := anchors.Load()
	if err != nil {
		t.Fatal(err)
	}
	all, err := trustAnchors(certPEM)
	if err != nil {
		t.Fatalf("trustAnchors: %v", err)
	}
	if len(all) != len(base)+1 {
		t.Fatalf("expected %d anchors with extra PEM, got %d", len(base)+1, len(all))
	}
}

func TestResultJSONShape(t *testing.T) {
	valid := true
	res := &Result{
		Profile: "pades",
		Overall: Valid,
		Signer:  SignerInfo{Subject: "CN=Test", IDNP: "123", SignatureValid: &valid},
		Chain:   ChainInfo{Status: "trusted", Anchor: "CN=Root"},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"profile", "overall", "signer", "chain"} {
		if _, ok := m[k]; !ok {
			t.Errorf("JSON missing key %q", k)
		}
	}
	if m["overall"] != "VALID" {
		t.Errorf("overall = %v, want VALID", m["overall"])
	}
	// Empty timestamp is omitted.
	if _, ok := m["timestamp"]; ok {
		t.Error("expected timestamp to be omitted when nil")
	}
}

// TestPAdESSelfSignedFixture builds a PAdES-B (no timestamp, no network)
// signature over a minimal PDF with a self-signed software key, then verifies
// it against that same certificate supplied as an extra trust anchor.
func TestPAdESSelfSignedFixture(t *testing.T) {
	key, certPEM := selfSignedFixture(t, "OpenMDSign PAdES Test")
	cert := parsePEM(t, certPEM)

	inPDF := minimalPDF()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "signed.pdf")

	_, err := pades.New().Sign(context.Background(), sign.Request{
		InputPDF:    inPDF,
		InputName:   "test.pdf",
		OutputPath:  outPath,
		Signer:      key,
		Certificate: cert,
		Level:       sign.LevelB, // no TSA => fully offline
	})
	if err != nil {
		t.Fatalf("sign fixture PDF: %v", err)
	}

	signed, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}

	res, err := verifyPAdES(bytes.NewReader(signed), int64(len(signed)), Options{
		ExtraAnchorsPEM: certPEM,
	})
	if err != nil {
		t.Fatalf("verifyPAdES: %v", err)
	}

	if res.Signer.SignatureValid == nil || !*res.Signer.SignatureValid {
		t.Error("expected the CMS signature to verify over the ByteRange")
	}
	if res.Chain.Status != "trusted" {
		t.Errorf("chain status = %q (%s), want trusted", res.Chain.Status, res.Chain.Detail)
	}
	if res.Overall != Valid {
		t.Errorf("overall = %q (%s), want VALID", res.Overall, res.Reason)
	}
	if res.Signer.Subject == "" {
		t.Error("expected a signer subject")
	}
}

// TestPAdESTamperedIsNotValid flips a content byte and expects a non-VALID
// verdict (either a crypto failure or a broken chain, never VALID).
func TestPAdESTamperedIsNotValid(t *testing.T) {
	key, certPEM := selfSignedFixture(t, "OpenMDSign PAdES Tamper Test")
	cert := parsePEM(t, certPEM)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "signed.pdf")
	if _, err := pades.New().Sign(context.Background(), sign.Request{
		InputPDF: minimalPDF(), InputName: "t.pdf", OutputPath: outPath,
		Signer: key, Certificate: cert, Level: sign.LevelB,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate a covered content byte while keeping the PDF structurally valid:
	// flip the page MediaBox width "612" -> "912" (same length, so xref offsets
	// stay correct, but the ByteRange digest changes and the signature breaks).
	old, replacement := []byte("MediaBox[0 0 612 792]"), []byte("MediaBox[0 0 912 792]")
	if i := bytes.Index(signed, old); i >= 0 {
		copy(signed[i:], replacement)
	} else {
		t.Skip("could not locate covered content to tamper")
	}
	res, err := verifyPAdES(bytes.NewReader(signed), int64(len(signed)), Options{ExtraAnchorsPEM: certPEM})
	if err != nil {
		// A parse error is an acceptable "not valid" outcome for a mangled PDF.
		return
	}
	if res.Overall == Valid {
		t.Errorf("tampered PDF verified as VALID; want INVALID/INDETERMINATE")
	}
}

// --- helpers ---

func selfSignedFixture(t *testing.T, cn string) (crypto.Signer, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return key, certPEM
}

func parsePEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// minimalPDF builds a tiny but structurally valid PDF (catalog + pages + one
// page) with a correct cross-reference table, suitable as a signing input.
func minimalPDF() []byte {
	objs := []string{
		"<</Type/Catalog/Pages 2 0 R>>",
		"<</Type/Pages/Kids[3 0 R]/Count 1>>",
		"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	offsets := make([]int, len(objs)+1)
	for i, o := range objs {
		offsets[i+1] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xrefPos := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n", len(objs)+1)
	fmt.Fprintf(&b, "%010d %05d f \n", 0, 65535)
	for i := 1; i <= len(objs); i++ {
		fmt.Fprintf(&b, "%010d %05d n \n", offsets[i], 0)
	}
	fmt.Fprintf(&b, "trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xrefPos)
	return b.Bytes()
}
