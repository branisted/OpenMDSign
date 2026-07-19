package xadesauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/branisted/openmdsign/internal/sign"
	"github.com/digitorus/timestamp"
	dsig "github.com/russellhaering/goxmldsig"
)

// ── test helpers ────────────────────────────────────────────────────────────

func softwareSigner(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "OpenMDSign Test CA", Country: []string{"MD"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, cert
}

// mockTSA returns an httptest server that answers RFC 3161 requests with a token
// signed by a throwaway TSA cert, echoing the request's hash algorithm.
func mockTSA(t *testing.T) *httptest.Server {
	t.Helper()
	tsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("tsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "OpenMDSign Mock TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &tsaKey.PublicKey, tsaKey)
	if err != nil {
		t.Fatalf("tsa cert: %v", err)
	}
	tsaCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse tsa cert: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil && len(body) == 0 {
			http.Error(w, "read", 500)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, "parse: "+err.Error(), 400)
			return
		}
		// The mpass TSA (MDQTSA) requires SHA-256 requests; assert we send that.
		if req.HashAlgorithm != crypto.SHA256 {
			http.Error(w, "expected SHA-256 request", 400)
			return
		}
		resp := timestamp.Timestamp{
			HashAlgorithm: req.HashAlgorithm,
			HashedMessage: req.HashedMessage,
			Time:          time.Now(),
			Nonce:         req.Nonce,
			SerialNumber:  big.NewInt(1),
			Policy:        asn1OID(),
		}
		if req.Certificates {
			resp.Certificates = []*x509.Certificate{tsaCert}
		}
		tok, err := resp.CreateResponse(tsaCert, tsaKey)
		if err != nil {
			http.Error(w, "create: "+err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(tok)
	}))
}

func asn1OID() []int { return []int{1, 2, 3, 4, 1} }

// findObjectByIDPrefix returns the ds:Object element whose Id starts with prefix.
func childElem(t *testing.T, parent *etree.Element, path ...string) *etree.Element {
	t.Helper()
	cur := parent
	for _, tag := range path {
		next := cur.FindElement(tag)
		if next == nil {
			t.Fatalf("element %q not found under %q", tag, cur.Tag)
		}
		cur = next
	}
	return cur
}

// ── self-contained C14N canonical-form assertion (no personal data) ─────────

// TestObjectCanonicalForm proves the enveloping ds:Object canonicalizes to the
// exact inclusive C14N 1.0 byte string (inherited xmlns:ds pulled to the apex,
// attributes in document order) and that its SHA-1 is stable. This is the same
// pipeline the vendor oracle exercises, expressed without any captured data.
func TestObjectCanonicalForm(t *testing.T) {
	doc := etree.NewDocument()
	sig := doc.CreateElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", nsDsig)
	obj := sig.CreateElement("ds:Object")
	obj.CreateAttr("Encoding", "UTF-8")
	obj.CreateAttr("Id", "FileObject-test")
	obj.SetText("AAECAwQ=") // base64 of {0,1,2,3,4}

	got, err := dsig.MakeC14N10RecCanonicalizer().Canonicalize(obj)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Encoding="UTF-8" Id="FileObject-test">AAECAwQ=</ds:Object>`
	if string(got) != want {
		t.Fatalf("canonical form mismatch:\n got=%q\nwant=%q", got, want)
	}
	sum := sha1.Sum(got)
	if len(sum) != 20 {
		t.Fatalf("unexpected digest length")
	}
}

// ── DECISIVE vendor oracle (env-guarded; the reference file is never committed)
//
// Set OPENMDSIGN_AUTH_ORACLE to the captured auth.xades to run it. It proves our
// C14N+SHA-1 of the vendor's <ds:Object> equals the vendor's file-reference
// DigestValue exactly, and likewise for the SignedProperties reference.
func TestVendorOracle(t *testing.T) {
	path := os.Getenv("OPENMDSIGN_AUTH_ORACLE")
	if path == "" {
		t.Skip("set OPENMDSIGN_AUTH_ORACLE to the captured auth.xades to run the decisive oracle")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(path); err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	root := doc.Root()

	// Collect referenced DigestValues from SignedInfo (order: SP first, file).
	si := childElem(t, root, "ds:SignedInfo")
	var refs []*etree.Element
	for _, r := range si.FindElements("ds:Reference") {
		refs = append(refs, r)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 references, got %d", len(refs))
	}
	spRefDigest := refs[0].FindElement("ds:DigestValue").Text()
	fileRefDigest := refs[1].FindElement("ds:DigestValue").Text()

	// Locate the FileObject and SignedProperties elements.
	var fileObj, signedProps *etree.Element
	for _, o := range root.FindElements("ds:Object") {
		if id := o.SelectAttrValue("Id", ""); len(id) >= len("FileObject-") && id[:len("FileObject-")] == "FileObject-" {
			fileObj = o
		}
	}
	signedProps = root.FindElement("ds:Object/xades:QualifyingProperties/xades:SignedProperties")
	if fileObj == nil || signedProps == nil {
		t.Fatalf("could not locate FileObject/SignedProperties in oracle")
	}

	gotFile, err := c14nSHA1NoComments(fileObj)
	if err != nil {
		t.Fatalf("c14n FileObject: %v", err)
	}
	if b := base64.StdEncoding.EncodeToString(gotFile); b != fileRefDigest {
		t.Fatalf("ORACLE FAIL (file-ref): C14N-SHA1(Object)=%s want %s", b, fileRefDigest)
	}
	gotSP, err := c14nSHA1NoComments(signedProps)
	if err != nil {
		t.Fatalf("c14n SignedProperties: %v", err)
	}
	if b := base64.StdEncoding.EncodeToString(gotSP); b != spRefDigest {
		t.Fatalf("ORACLE FAIL (sp-ref): C14N-SHA1(SignedProperties)=%s want %s", b, spRefDigest)
	}
	t.Logf("ORACLE OK: file-ref=%s sp-ref=%s", fileRefDigest, spRefDigest)
}

// TestIssuerDNOracle is the go/no-go for the DN renderer: it parses the issuer
// from the real signing cert and asserts renderIssuerDN produces EXACTLY the
// X509IssuerName string inside the vendor's accepted auth.xades (same issuer ⇒
// must match byte-for-byte). Env-guarded so neither the cert nor the sample is
// committed. Set OPENMDSIGN_AUTH_CERT (DER path) and OPENMDSIGN_AUTH_ORACLE
// (auth.xades path) to run it.
func TestIssuerDNOracle(t *testing.T) {
	certPath := os.Getenv("OPENMDSIGN_AUTH_CERT")
	xadesPath := os.Getenv("OPENMDSIGN_AUTH_ORACLE")
	if certPath == "" || xadesPath == "" {
		t.Skip("set OPENMDSIGN_AUTH_CERT and OPENMDSIGN_AUTH_ORACLE to run the DN oracle")
	}
	der, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(xadesPath); err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	want := doc.Root().FindElement("ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
	if want == nil {
		t.Fatalf("vendor X509IssuerName not found")
	}
	got, err := renderIssuerDN(cert)
	if err != nil {
		t.Fatalf("renderIssuerDN: %v", err)
	}
	if got != want.Text() {
		t.Fatalf("DN ORACLE FAIL:\n got=%q\nwant=%q", got, want.Text())
	}
	t.Logf("DN ORACLE OK: %s", got)
}

// ── structural + internal-validity assertion (software key, mock TSA) ───────

func buildSample(t *testing.T) (*etree.Document, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, cert := softwareSigner(t, "OpenMDSign Auth Test")
	tsa := mockTSA(t)
	t.Cleanup(tsa.Close)

	fixed := time.Date(2026, 7, 18, 1, 2, 10, 0, time.FixedZone("MSK", 3*3600))
	xml, err := Build(context.Background(), Params{
		Challenge:   []byte("0123456789abcdef0123"), // 20-byte pre-hash stand-in
		Signer:      key,
		Certificate: cert,
		TSAURL:      tsa.URL,
		SigningTime: fixed,
		InputName:   "authentication-challenge",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xml); err != nil {
		t.Fatalf("reparse output: %v", err)
	}
	return doc, key, cert
}

func TestBuildStructure(t *testing.T) {
	doc, _, cert := buildSample(t)
	root := doc.Root()

	if root.Tag != "Signature" || root.Space != "ds" {
		t.Fatalf("root is %s:%s, want ds:Signature", root.Space, root.Tag)
	}
	if root.SelectAttrValue("xmlns:ds", "") != nsDsig {
		t.Fatalf("xmlns:ds missing on root")
	}
	sigID := root.SelectAttrValue("Id", "")
	if len(sigID) < len("Signature-") || sigID[:len("Signature-")] != "Signature-" {
		t.Fatalf("Signature Id naming: %q", sigID)
	}

	// Child order: SignedInfo, SignatureValue, KeyInfo, Object, Object.
	var order []string
	for _, c := range root.ChildElements() {
		order = append(order, c.Tag)
	}
	wantOrder := []string{"SignedInfo", "SignatureValue", "KeyInfo", "Object", "Object"}
	if len(order) != len(wantOrder) {
		t.Fatalf("child count %v want %v", order, wantOrder)
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Fatalf("child order %v want %v", order, wantOrder)
		}
	}

	si := childElem(t, root, "ds:SignedInfo")
	if got := childElem(t, si, "ds:CanonicalizationMethod").SelectAttrValue("Algorithm", ""); got != c14nWithComments {
		t.Fatalf("SignedInfo C14N method %q", got)
	}
	if got := childElem(t, si, "ds:SignatureMethod").SelectAttrValue("Algorithm", ""); got != sigMethodRSASHA1 {
		t.Fatalf("SignatureMethod %q", got)
	}

	refs := si.FindElements("ds:Reference")
	if len(refs) != 2 {
		t.Fatalf("want 2 references, got %d", len(refs))
	}
	// Reference 1 MUST be SignedProperties (the DSS-impossible order).
	if got := refs[0].SelectAttrValue("Type", ""); got != typeSignedProps {
		t.Fatalf("ref[0] Type %q, want SignedProperties (order wrong?)", got)
	}
	// Reference 2 MUST be the file object: no Type.
	if got := refs[1].SelectAttrValue("Type", ""); got != "" {
		t.Fatalf("ref[1] must have no Type, got %q", got)
	}
	// Neither reference may carry Transforms.
	for i, r := range refs {
		if r.FindElement("ds:Transforms") != nil {
			t.Fatalf("ref[%d] must have NO Transforms", i)
		}
		if got := r.FindElement("ds:DigestMethod").SelectAttrValue("Algorithm", ""); got != digestMethodSHA1 {
			t.Fatalf("ref[%d] DigestMethod %q", i, got)
		}
	}
	// SP ref URI targets the SignedProperties Id; file ref URI targets FileObject.
	sp := root.FindElement("ds:Object/xades:QualifyingProperties/xades:SignedProperties")
	if sp == nil {
		t.Fatalf("SignedProperties not found")
	}
	if refs[0].SelectAttrValue("URI", "") != "#"+sp.SelectAttrValue("Id", "") {
		t.Fatalf("SP ref URI mismatch")
	}

	// QualifyingProperties declares xmlns:xades and Target = #Signature.
	qp := root.FindElement("ds:Object/xades:QualifyingProperties")
	if qp.SelectAttrValue("xmlns:xades", "") != nsXades {
		t.Fatalf("xmlns:xades missing on QualifyingProperties")
	}
	if qp.SelectAttrValue("Target", "") != "#"+sigID {
		t.Fatalf("QualifyingProperties Target %q", qp.SelectAttrValue("Target", ""))
	}

	// SigningCertificate is the v1 form: Cert/CertDigest + IssuerSerial.
	certEl := childElem(t, sp, "xades:SignedSignatureProperties", "xades:SigningCertificate", "xades:Cert")
	if certEl.FindElement("xades:CertDigest/ds:DigestValue") == nil {
		t.Fatalf("CertDigest/DigestValue missing")
	}
	if certEl.FindElement("xades:IssuerSerial/ds:X509IssuerName") == nil ||
		certEl.FindElement("xades:IssuerSerial/ds:X509SerialNumber") == nil {
		t.Fatalf("IssuerSerial incomplete")
	}
	// CertDigest must equal SHA-1(cert DER).
	wantCertDigest := sha1.Sum(cert.Raw)
	if got := certEl.FindElement("xades:CertDigest/ds:DigestValue").Text(); got != base64.StdEncoding.EncodeToString(wantCertDigest[:]) {
		t.Fatalf("CertDigest mismatch")
	}

	// DataObjectFormat: ObjectReference is the file-Reference Id VERBATIM (no
	// leading '#'), children in schema order Description then MimeType, and the
	// Description carries the NEUTRAL basename (never a filesystem path).
	dof := childElem(t, sp, "xades:SignedDataObjectProperties", "xades:DataObjectFormat")
	fileRefID := refs[1].SelectAttrValue("Id", "")
	if got := dof.SelectAttrValue("ObjectReference", ""); got != fileRefID {
		t.Fatalf("DataObjectFormat ObjectReference %q, want file-ref Id %q (no leading #)", got, fileRefID)
	}
	dofChildren := dof.ChildElements()
	if len(dofChildren) != 2 || dofChildren[0].Tag != "Description" || dofChildren[1].Tag != "MimeType" {
		t.Fatalf("DataObjectFormat children must be [Description, MimeType], got %v", dofChildren)
	}
	desc := dof.FindElement("xades:Description").Text()
	if desc != "authentication-challenge" {
		t.Fatalf("Description must be the neutral basename, got %q", desc)
	}
	if strings.ContainsAny(desc, "/\\") || strings.Contains(desc, ":") {
		t.Fatalf("Description must not leak a filesystem path: %q", desc)
	}

	// SignatureTimeStamp with plain C14N + EncapsulatedTimeStamp DER encoding.
	ts := childElem(t, qp, "xades:UnsignedProperties", "xades:UnsignedSignatureProperties", "xades:SignatureTimeStamp")
	if got := ts.FindElement("ds:CanonicalizationMethod").SelectAttrValue("Algorithm", ""); got != c14nPlain {
		t.Fatalf("TS C14N method %q", got)
	}
	ets := ts.FindElement("xades:EncapsulatedTimeStamp")
	if ets.SelectAttrValue("Encoding", "") != tsEncodingDER {
		t.Fatalf("EncapsulatedTimeStamp Encoding %q", ets.SelectAttrValue("Encoding", ""))
	}
	if _, err := base64.StdEncoding.DecodeString(ets.Text()); err != nil {
		t.Fatalf("timestamp token not base64: %v", err)
	}
}

// TestInternalValidity proves the produced signature is self-consistent: the
// SignatureValue verifies over C14N(SignedInfo) with the software public key,
// and each reference DigestValue recomputes from the referenced element.
func TestInternalValidity(t *testing.T) {
	doc, key, cert := buildSample(t)
	root := doc.Root()
	si := childElem(t, root, "ds:SignedInfo")

	// SignatureValue verifies over SHA-1(C14N-with-comments(SignedInfo)).
	siC14N, err := canonWithComments(si)
	if err != nil {
		t.Fatalf("c14n SignedInfo: %v", err)
	}
	h := sha1.Sum(siC14N)
	sigVal, err := base64.StdEncoding.DecodeString(root.FindElement("ds:SignatureValue").Text())
	if err != nil {
		t.Fatalf("decode SignatureValue: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA1, h[:], sigVal); err != nil {
		t.Fatalf("SignatureValue does not verify over C14N(SignedInfo): %v", err)
	}

	// Embedded cert matches the signer.
	embedded, err := base64.StdEncoding.DecodeString(root.FindElement("ds:KeyInfo/ds:X509Data/ds:X509Certificate").Text())
	if err != nil {
		t.Fatalf("decode X509Certificate: %v", err)
	}
	if string(embedded) != string(cert.Raw) {
		t.Fatalf("embedded certificate does not match signer")
	}

	// Each reference DigestValue recomputes from the referenced element.
	refs := si.FindElements("ds:Reference")
	sp := root.FindElement("ds:Object/xades:QualifyingProperties/xades:SignedProperties")
	spDigest, _ := c14nSHA1NoComments(sp)
	if got := refs[0].FindElement("ds:DigestValue").Text(); got != base64.StdEncoding.EncodeToString(spDigest) {
		t.Fatalf("SP ref DigestValue does not recompute")
	}
	var fileObj *etree.Element
	for _, o := range root.FindElements("ds:Object") {
		if id := o.SelectAttrValue("Id", ""); len(id) >= len("FileObject-") && id[:len("FileObject-")] == "FileObject-" {
			fileObj = o
		}
	}
	fileDigest, _ := c14nSHA1NoComments(fileObj)
	if got := refs[1].FindElement("ds:DigestValue").Text(); got != base64.StdEncoding.EncodeToString(fileDigest) {
		t.Fatalf("file ref DigestValue does not recompute")
	}
}

// TestSignerWritesFile exercises the sign.Signer wrapper end to end.
func TestSignerWritesFile(t *testing.T) {
	key, cert := softwareSigner(t, "OpenMDSign Auth Test")
	tsa := mockTSA(t)
	defer tsa.Close()

	out := filepath.Join(t.TempDir(), "auth.xades")
	res, err := New().Sign(context.Background(), sign.Request{
		InputPDF:    []byte("0123456789abcdef0123"),
		InputName:   "authentication-challenge",
		OutputPath:  out,
		Signer:      key,
		Certificate: cert,
		Level:       sign.LevelT,
		TSAURL:      tsa.URL,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.Profile != Profile || !res.TimestampApplied {
		t.Fatalf("unexpected result %+v", res)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("output not written: %v", err)
	}
}

// TestStructuralDiffVsVendor asserts our generated element tree matches the
// vendor's (tag/attr NAMES, reference order, transforms, namespaces, algorithm
// URIs) — value-only differences (SignatureValue, cert, SigningTime, timestamp,
// value-dependent DigestValues) are expected and ignored. Env-guarded so the
// vendor file is never committed.
func TestStructuralDiffVsVendor(t *testing.T) {
	path := os.Getenv("OPENMDSIGN_AUTH_ORACLE")
	if path == "" {
		t.Skip("set OPENMDSIGN_AUTH_ORACLE to structurally diff against the vendor sample")
	}
	vendor := etree.NewDocument()
	if err := vendor.ReadFromFile(path); err != nil {
		t.Fatalf("read vendor: %v", err)
	}
	ours, _, _ := buildSample(t)

	// Compare the shape (tag names + attribute-name sets) of the SignedInfo
	// subtree and the QualifyingProperties subtree, which carry the algorithm
	// URIs and reference structure that must match.
	compareShape(t, "SignedInfo", vendor.Root().FindElement("ds:SignedInfo"), ours.Root().FindElement("ds:SignedInfo"))
}

// compareShape asserts two element subtrees have the same tag names, the same
// attribute-name sets (values ignored), and the same child order/count.
func compareShape(t *testing.T, ctxPath string, a, b *etree.Element) {
	t.Helper()
	if a == nil || b == nil {
		t.Fatalf("%s: nil element (a=%v b=%v)", ctxPath, a != nil, b != nil)
	}
	if a.Space != b.Space || a.Tag != b.Tag {
		t.Fatalf("%s: tag %s:%s vs %s:%s", ctxPath, a.Space, a.Tag, b.Space, b.Tag)
	}
	an := attrNameSet(a)
	bn := attrNameSet(b)
	for k := range an {
		if _, ok := bn[k]; !ok {
			t.Fatalf("%s/%s: attr %q present in vendor, missing in ours", ctxPath, a.Tag, k)
		}
	}
	for k := range bn {
		if _, ok := an[k]; !ok {
			t.Fatalf("%s/%s: attr %q present in ours, missing in vendor", ctxPath, a.Tag, k)
		}
	}
	// Algorithm/URI/Type attribute VALUES must match (these are structural).
	for _, name := range []string{"Algorithm", "Type"} {
		if av, bv := a.SelectAttrValue(name, ""), b.SelectAttrValue(name, ""); av != bv {
			t.Fatalf("%s/%s: %s value %q vs %q", ctxPath, a.Tag, name, av, bv)
		}
	}
	ac, bc := a.ChildElements(), b.ChildElements()
	if len(ac) != len(bc) {
		var at, bt []string
		for _, c := range ac {
			at = append(at, c.Tag)
		}
		for _, c := range bc {
			bt = append(bt, c.Tag)
		}
		t.Fatalf("%s/%s: child count/order %v vs %v", ctxPath, a.Tag, at, bt)
	}
	for i := range ac {
		compareShape(t, ctxPath+"/"+a.Tag, ac[i], bc[i])
	}
}

func attrNameSet(e *etree.Element) map[string]struct{} {
	m := make(map[string]struct{})
	for _, a := range e.Attr {
		key := a.Key
		if a.Space != "" {
			key = a.Space + ":" + a.Key
		}
		// Ignore Id attributes: their VALUES differ and names always present.
		m[key] = struct{}{}
	}
	return m
}
