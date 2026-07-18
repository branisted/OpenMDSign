// Package xadesauth is a dedicated, pure-Go signer for the ONE narrow signature
// EU DSS cannot produce: the mpass.gov.md authentication XAdES-T.
//
// The mpass login flow hands the daemon a short (~20-byte) SHA-1 pre-hash
// challenge and expects an ENVELOPING XAdES-T signed with SHA-1 everywhere. Two
// traits of the vendor's accepted construction are hardwired against DSS's
// signed-SignedInfo builder and cannot be reproduced through DSS:
//
//  1. Reference ORDER: the SignedProperties reference comes FIRST, then the
//     enveloped-file reference. DSS always emits the file reference first.
//  2. The file reference has NO transform and its DigestValue is SHA-1 over the
//     canonical form of the whole <ds:Object> element (NOT a base64 transform
//     over the decoded challenge bytes, which is what DSS produces).
//
// This package hand-builds exactly that structure and nothing else. It is used
// ONLY for the isAuth branch; document XAdES (SHA-256 detached) stays on DSS and
// PAdES is untouched. SHA-1 here is interop-required by the government auth
// protocol; it is never used for document signing.
//
// Canonicalization is delegated to a vetted Canonical XML 1.0 implementation
// (github.com/russellhaering/goxmldsig over github.com/beevik/etree); no C14N is
// hand-rolled. The digest pipeline is proven against the vendor's accepted
// sample in the package tests (the C14N-SHA1 of the vendor's <ds:Object> equals
// the vendor's file-reference DigestValue exactly).
package xadesauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/beevik/etree"
	"github.com/branistedev/openmdsign/internal/sign"
	"github.com/digitorus/timestamp"
	dsig "github.com/russellhaering/goxmldsig"
)

// Algorithm URIs used by the vendor's accepted construction (verified against
// the captured auth.xades).
const (
	c14nWithComments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	c14nPlain        = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	sigMethodRSASHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	digestMethodSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
	nsDsig           = "http://www.w3.org/2000/09/xmldsig#"
	nsXades          = "http://uri.etsi.org/01903/v1.3.2#"
	typeSignedProps  = "http://uri.etsi.org/01903#SignedProperties"
	tsEncodingDER    = "http://uri.etsi.org/01903/v1.2.2#DER"
)

// defaultMimeType labels the enveloped challenge object. The vendor uses
// application/octet-stream (a raw pre-hash has no meaningful media type).
const defaultMimeType = "application/octet-stream"

// Profile is the profile name produced by this Signer.
const Profile = "XAdES"

// Params holds the inputs for building one mpass auth XAdES-T signature.
type Params struct {
	// Challenge is the raw pre-hash challenge bytes handed by mpass. They are
	// base64-encoded into the enveloped <ds:Object>.
	Challenge []byte
	// Signer is the already-authenticated on-token key. It is driven with
	// crypto.SHA1 (RSASSA-PKCS1-v1_5) over SHA-1(C14N(SignedInfo)).
	Signer crypto.Signer
	// Certificate is the signer's leaf certificate (embedded as X509Certificate
	// and hashed for the SigningCertificate CertDigest).
	Certificate *x509.Certificate
	// TSAURL is the RFC 3161 timestamp authority (MoldSign). Required.
	TSAURL string
	// SigningTime is stamped into SignedProperties/SigningTime (RFC3339 with the
	// caller's timezone offset, like the vendor).
	SigningTime time.Time
	// InputName is the neutral basename used to label the file reference Id. It
	// must never carry a local filesystem path (the vendor leaks one; we do not).
	InputName string
	// httpClient is injectable for tests; nil uses http.DefaultClient.
	httpClient *http.Client
}

// Build assembles the standalone mpass auth XAdES-T <ds:Signature> and returns
// the serialized XML bytes. It performs exactly one token signature (over
// SHA-1(C14N(SignedInfo))) and one RFC 3161 timestamp request. It never logs in.
func Build(ctx context.Context, p Params) ([]byte, error) {
	if p.Certificate == nil {
		return nil, fmt.Errorf("xadesauth: signing certificate is required")
	}
	if p.Signer == nil {
		return nil, fmt.Errorf("xadesauth: authenticated crypto.Signer is required")
	}
	if len(p.Challenge) == 0 {
		return nil, fmt.Errorf("xadesauth: empty challenge")
	}
	if p.TSAURL == "" {
		return nil, fmt.Errorf("xadesauth: TSA URL is required for XAdES-T")
	}
	inputName := p.InputName
	if inputName == "" {
		inputName = "authentication-challenge"
	}

	u, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("xadesauth: generate id: %w", err)
	}

	// Element Ids share one UUID, matching the vendor's naming scheme so all
	// URIs / Target lines line up.
	ids := struct {
		sig, signedInfo, spRef, fileRef, sp, sigVal, keyInfo, sdop, ts, fileObj string
	}{
		sig:        "Signature-" + u,
		signedInfo: "SignedInfo-" + u,
		spRef:      "SignedProperties-Reference-" + u,
		fileRef:    "SignedFile-Reference-" + u + "-" + inputName,
		sp:         "SignedProperties-" + u,
		sigVal:     "SignatureValue-" + u,
		keyInfo:    "KeyInfo-" + u,
		sdop:       "SignedDataObjectProperties-" + u,
		ts:         "SignatureTimeStamp-" + u,
		fileObj:    "FileObject-" + u,
	}

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8" standalone="no"`)

	// ── ds:Signature (declares xmlns:ds) ────────────────────────────────────
	sigEl := doc.CreateElement("ds:Signature")
	sigEl.CreateAttr("xmlns:ds", nsDsig)
	sigEl.CreateAttr("Id", ids.sig)

	// Child order matches the vendor exactly:
	//   SignedInfo, SignatureValue, KeyInfo, Object(QualifyingProperties),
	//   Object(FileObject).
	signedInfo := sigEl.CreateElement("ds:SignedInfo")
	signedInfo.CreateAttr("Id", ids.signedInfo)

	cm := signedInfo.CreateElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", c14nWithComments)
	sm := signedInfo.CreateElement("ds:SignatureMethod")
	sm.CreateAttr("Algorithm", sigMethodRSASHA1)

	// Reference 1: SignedProperties (FIRST — the DSS-impossible order).
	spRefEl := signedInfo.CreateElement("ds:Reference")
	spRefEl.CreateAttr("Id", ids.spRef)
	spRefEl.CreateAttr("Type", typeSignedProps)
	spRefEl.CreateAttr("URI", "#"+ids.sp)
	spDM := spRefEl.CreateElement("ds:DigestMethod")
	spDM.CreateAttr("Algorithm", digestMethodSHA1)
	spDV := spRefEl.CreateElement("ds:DigestValue") // filled below

	// Reference 2: the enveloped file Object (no Type, no Transforms).
	fileRefEl := signedInfo.CreateElement("ds:Reference")
	fileRefEl.CreateAttr("Id", ids.fileRef)
	fileRefEl.CreateAttr("URI", "#"+ids.fileObj)
	fileDM := fileRefEl.CreateElement("ds:DigestMethod")
	fileDM.CreateAttr("Algorithm", digestMethodSHA1)
	fileDV := fileRefEl.CreateElement("ds:DigestValue") // filled below

	// SignatureValue (text filled after signing SignedInfo).
	sigValEl := sigEl.CreateElement("ds:SignatureValue")
	sigValEl.CreateAttr("Id", ids.sigVal)

	// KeyInfo / X509Data / X509Certificate.
	keyInfo := sigEl.CreateElement("ds:KeyInfo")
	keyInfo.CreateAttr("Id", ids.keyInfo)
	x509Data := keyInfo.CreateElement("ds:X509Data")
	x509Cert := x509Data.CreateElement("ds:X509Certificate")
	x509Cert.SetText(base64.StdEncoding.EncodeToString(p.Certificate.Raw))

	// ── ds:Object > QualifyingProperties (declares xmlns:xades) ─────────────
	qpObj := sigEl.CreateElement("ds:Object")
	qp := qpObj.CreateElement("xades:QualifyingProperties")
	qp.CreateAttr("xmlns:xades", nsXades)
	qp.CreateAttr("Target", "#"+ids.sig)

	sp := qp.CreateElement("xades:SignedProperties")
	sp.CreateAttr("Id", ids.sp)

	ssp := sp.CreateElement("xades:SignedSignatureProperties")
	st := ssp.CreateElement("xades:SigningTime")
	st.SetText(p.SigningTime.Format(time.RFC3339))

	signingCert := ssp.CreateElement("xades:SigningCertificate")
	cert := signingCert.CreateElement("xades:Cert")
	certDigest := cert.CreateElement("xades:CertDigest")
	cdDM := certDigest.CreateElement("ds:DigestMethod")
	cdDM.CreateAttr("Algorithm", digestMethodSHA1)
	certSHA1 := sha1.Sum(p.Certificate.Raw)
	certDigest.CreateElement("ds:DigestValue").SetText(base64.StdEncoding.EncodeToString(certSHA1[:]))
	issuerSerial := cert.CreateElement("xades:IssuerSerial")
	issuerSerial.CreateElement("ds:X509IssuerName").SetText(p.Certificate.Issuer.String())
	issuerSerial.CreateElement("ds:X509SerialNumber").SetText(p.Certificate.SerialNumber.String())

	sdop := sp.CreateElement("xades:SignedDataObjectProperties")
	sdop.CreateAttr("Id", ids.sdop)
	dof := sdop.CreateElement("xades:DataObjectFormat")
	dof.CreateAttr("ObjectReference", "#"+ids.fileRef)
	// Deliberately NO xades:Description: the vendor leaks a local path there.
	dof.CreateElement("xades:MimeType").SetText(defaultMimeType)

	// ── trailing ds:Object (FileObject) = base64(challenge) ─────────────────
	fileObj := sigEl.CreateElement("ds:Object")
	fileObj.CreateAttr("Encoding", "UTF-8")
	fileObj.CreateAttr("Id", ids.fileObj)
	fileObj.SetText(base64.StdEncoding.EncodeToString(p.Challenge))

	// ── digests: both references are SHA-1 over C14N(element) ────────────────
	spDigest, err := c14nSHA1NoComments(sp)
	if err != nil {
		return nil, fmt.Errorf("xadesauth: canonicalize SignedProperties: %w", err)
	}
	spDV.SetText(base64.StdEncoding.EncodeToString(spDigest))

	fileDigest, err := c14nSHA1NoComments(fileObj)
	if err != nil {
		return nil, fmt.Errorf("xadesauth: canonicalize FileObject: %w", err)
	}
	fileDV.SetText(base64.StdEncoding.EncodeToString(fileDigest))

	// ── SignatureValue = token RSA over SHA-1(C14N(SignedInfo)) ─────────────
	siC14N, err := canonWithComments(signedInfo)
	if err != nil {
		return nil, fmt.Errorf("xadesauth: canonicalize SignedInfo: %w", err)
	}
	siHash := sha1.Sum(siC14N)
	sigBytes, err := p.Signer.Sign(rand.Reader, siHash[:], crypto.SHA1)
	if err != nil {
		return nil, fmt.Errorf("xadesauth: token signature over SignedInfo failed: %w", err)
	}
	sigValEl.SetText(base64.StdEncoding.EncodeToString(sigBytes))

	// ── SignatureTimeStamp: RFC 3161 token over C14N(ds:SignatureValue) ─────
	svC14N, err := canonPlain(sigValEl)
	if err != nil {
		return nil, fmt.Errorf("xadesauth: canonicalize SignatureValue: %w", err)
	}
	tsToken, err := fetchTimestampToken(ctx, p.TSAURL, svC14N, p.httpClient)
	if err != nil {
		return nil, fmt.Errorf("xadesauth: timestamp: %w", err)
	}

	unsigned := qp.CreateElement("xades:UnsignedProperties")
	usp := unsigned.CreateElement("xades:UnsignedSignatureProperties")
	tsEl := usp.CreateElement("xades:SignatureTimeStamp")
	tsEl.CreateAttr("Id", ids.ts)
	tsCM := tsEl.CreateElement("ds:CanonicalizationMethod")
	tsCM.CreateAttr("Algorithm", c14nPlain)
	ets := tsEl.CreateElement("xades:EncapsulatedTimeStamp")
	ets.CreateAttr("Encoding", tsEncodingDER)
	ets.SetText(base64.StdEncoding.EncodeToString(tsToken))

	doc.WriteSettings = etree.WriteSettings{CanonicalEndTags: false}
	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("xadesauth: serialize: %w", err)
	}
	return out, nil
}

// c14nSHA1NoComments canonicalizes el with Canonical XML 1.0 (no comments — the
// implicit transform for a same-document reference without an explicit one) and
// returns its SHA-1 digest. This is the pipeline proven against the vendor
// sample in the tests.
func c14nSHA1NoComments(el *etree.Element) ([]byte, error) {
	b, err := dsig.MakeC14N10RecCanonicalizer().Canonicalize(el)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(b)
	return sum[:], nil
}

// canonWithComments canonicalizes el with Canonical XML 1.0 WITH comments (the
// SignedInfo CanonicalizationMethod the vendor declares).
func canonWithComments(el *etree.Element) ([]byte, error) {
	return dsig.MakeC14N10WithCommentsCanonicalizer().Canonicalize(el)
}

// canonPlain canonicalizes el with plain Canonical XML 1.0 (no comments — the
// SignatureTimeStamp CanonicalizationMethod).
func canonPlain(el *etree.Element) ([]byte, error) {
	return dsig.MakeC14N10RecCanonicalizer().Canonicalize(el)
}

// fetchTimestampToken requests an RFC 3161 timestamp over data from the TSA and
// returns the raw TimeStampToken DER. The TSA request digest is SHA-256:
// MoldSign's MDQTSA rejects SHA-1/SHA-512 requests (established fact).
func fetchTimestampToken(ctx context.Context, tsaURL string, data []byte, client *http.Client) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	reqDER, err := timestamp.CreateRequest(bytes.NewReader(data), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tsaURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("prepare request (%s): %w", tsaURL, err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Content-Transfer-Encoding", "binary")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post to TSA (%s): %w", tsaURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("TSA non-success response (%d)", resp.StatusCode)
	}
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("parse TSA response: %w", err)
	}
	if len(ts.RawToken) == 0 {
		return nil, fmt.Errorf("TSA returned an empty token")
	}
	return ts.RawToken, nil
}

// writeOutput writes the signed XAdES to path, creating parent dirs.
func writeOutput(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("xadesauth: empty output path")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("xadesauth: create out dir for %q: %w", path, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("xadesauth: write signed XAdES %q: %w", path, err)
	}
	return nil
}

// newUUID returns a random RFC 4122 v4 UUID string, matching the vendor's Id
// naming scheme.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// Signer adapts Build to the sign.Signer interface so the daemon can route the
// isAuth branch through it exactly like the other profile signers.
type Signer struct {
	// Now supplies the signing time; nil uses time.Now (local timezone, so the
	// SigningTime carries an offset like the vendor's).
	Now func() time.Time
	// httpClient is injectable for tests; nil uses http.DefaultClient.
	httpClient *http.Client
}

// New returns an mpass auth XAdES-T Signer.
func New() *Signer { return &Signer{} }

// Profile returns the container profile name.
func (*Signer) Profile() string { return Profile }

// Sign builds the mpass auth XAdES-T signature over req.InputPDF (the challenge
// bytes) and writes it to req.OutputPath. It never logs in: req.Signer must
// already be authenticated.
func (s *Signer) Sign(ctx context.Context, req sign.Request) (sign.Result, error) {
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	xml, err := Build(ctx, Params{
		Challenge:   req.InputPDF,
		Signer:      req.Signer,
		Certificate: req.Certificate,
		TSAURL:      req.TSAURL,
		SigningTime: now,
		InputName:   req.InputName,
		httpClient:  s.httpClient,
	})
	if err != nil {
		return sign.Result{}, err
	}
	if err := writeOutput(req.OutputPath, xml); err != nil {
		return sign.Result{}, err
	}
	return sign.Result{
		OutputPath:       req.OutputPath,
		Profile:          Profile,
		Level:            sign.LevelT,
		TimestampApplied: true,
		Bytes:            len(xml),
	}, nil
}
