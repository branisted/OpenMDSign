// Package xades implements the standalone XAdES signer profile for openmdsign.
//
// It produces a standalone XAdES signature (ETSI TS 101 903 v1.3.2, root
// ds:Signature, NOT ASiC-E) matching docs/profile-spec.md §1:
//
//   - RSA + SHA-256 (default; the digest is a parameter), SignatureMethod
//     rsa-sha256, every DigestMethod sha256.
//   - detached (primary): reference URI="file:/<basename>", no transforms,
//     digest over the raw file bytes; SignedInfo canonicalized with plain
//     C14N 1.0. enveloping (secondary): base64 file in a trailing ds:Object.
//   - SignedProperties: SigningTime + SigningCertificate (XAdES v1 form, NOT
//     SigningCertificateV2) + DataObjectFormat.
//   - level t adds UnsignedProperties/SignatureTimeStamp/EncapsulatedTimeStamp
//     (an RFC 3161 token over the C14N'd SignatureValue).
//
// XAdES/C14N are notoriously error-prone to hand-roll, so assembly is delegated
// to EU DSS (Java) via a two-step external-signing exchange with a helper
// subprocess (see helper.go and java/dss-helper). This process keeps the token:
// DSS returns the data-to-be-signed, Go signs it with the already-authenticated
// crypto.Signer (internal/token.Signer over the hardware token), and DSS
// assembles the XAdES around the returned value. This Signer NEVER performs a
// C_Login and NEVER sees a PIN. See docs/decisions.md.
package xades

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/branistedev/openmdsign/internal/sign"
)

// Profile is the profile name produced by this Signer.
const Profile = "XAdES"

// Signer implements sign.Signer for the standalone XAdES-B/T profile.
//
// JavaPath optionally pins the Java launcher; when empty it is resolved from
// the environment (OPENMDSIGN_JAVA, JAVA_HOME, then PATH). It never logs in.
type Signer struct {
	JavaPath string
}

// New returns a XAdES Signer. javaPath may be empty to auto-resolve Java.
func New(javaPath string) *Signer { return &Signer{JavaPath: javaPath} }

// Profile returns the container profile name.
func (*Signer) Profile() string { return Profile }

// Sign produces a standalone XAdES-B (level b) or XAdES-T (level t) signature
// over req.InputPDF (the raw input bytes) and writes it to req.OutputPath. It
// never logs in: req.Signer must already be authenticated.
func (s *Signer) Sign(ctx context.Context, req sign.Request) (sign.Result, error) {
	if req.Certificate == nil {
		return sign.Result{}, fmt.Errorf("xades: signing certificate is required")
	}
	if req.Signer == nil {
		return sign.Result{}, fmt.Errorf("xades: authenticated crypto.Signer is required")
	}
	if len(req.InputPDF) == 0 {
		return sign.Result{}, fmt.Errorf("xades: empty input")
	}

	packaging, dssPackaging, err := resolvePackaging(req.Packaging)
	if err != nil {
		return sign.Result{}, err
	}
	hash, dssDigest, err := resolveDigest(req.Digest)
	if err != nil {
		return sign.Result{}, err
	}
	dssLevel, timestamp, err := resolveLevel(req.Level)
	if err != nil {
		return sign.Result{}, err
	}
	if timestamp && req.TSAURL == "" {
		return sign.Result{}, fmt.Errorf("xades: level t requires a TSA URL")
	}

	basename := filepath.Base(req.InputName)
	// Detached: the reference URI is the document name; use file:/<basename> so
	// the output is URI="file:/<basename>" exactly (matches the vendor sample).
	// Enveloping: the name only labels the embedded object.
	referencedName := basename
	if packaging == sign.PackagingDetached {
		referencedName = "file:/" + basename
	}

	// One fixed signing time is passed into both steps of the exchange.
	signingTime := time.Now().UTC().Format(time.RFC3339)

	h, err := startHelper(ctx, s.JavaPath, req.HelperJar)
	if err != nil {
		return sign.Result{}, err
	}
	defer h.close()

	// Step 1: DSS builds the SignedInfo and returns the data-to-be-signed.
	dtbs, err := h.getDataToSign(getDataToSignReq{
		Level:          dssLevel,
		Packaging:      dssPackaging,
		DigestAlgo:     dssDigest,
		SigningCertB64: base64.StdEncoding.EncodeToString(req.Certificate.Raw),
		FileB64:        base64.StdEncoding.EncodeToString(req.InputPDF),
		ReferencedName: referencedName,
		MimeType:       mimeTypeFor(basename),
		SigningTime:    signingTime,
		TSAURL:         req.TSAURL,
		En319132:       false, // emit the v1.3.2 SigningCertificate (v1), not V2
	})
	if err != nil {
		return sign.Result{}, err
	}

	// Step 2: sign the DTBS on the token. DSS expects the value of
	// <digest>withRSA over the DTBS bytes, i.e. RSASSA-PKCS1-v1_5 over
	// hash(DTBS) -- exactly what crypto.Signer.Sign does with the matching hash.
	digest := hashSum(hash, dtbs)
	sigValue, err := req.Signer.Sign(rand.Reader, digest, hash)
	if err != nil {
		return sign.Result{}, fmt.Errorf("xades: token signature over DTBS failed: %w", err)
	}

	// Step 3: DSS assembles the final XAdES (and calls the TSA for -T).
	xml, err := h.signDocument(sigValue)
	if err != nil {
		return sign.Result{}, err
	}

	if err := writeOutput(req.OutputPath, xml); err != nil {
		return sign.Result{}, err
	}

	return sign.Result{
		OutputPath:       req.OutputPath,
		Profile:          Profile,
		Level:            req.Level,
		TimestampApplied: timestamp,
		Bytes:            len(xml),
	}, nil
}

// resolvePackaging maps the sign.Packaging to the DSS SignaturePackaging name.
func resolvePackaging(p sign.Packaging) (sign.Packaging, string, error) {
	switch p {
	case sign.PackagingDetached, "":
		return sign.PackagingDetached, "DETACHED", nil
	case sign.PackagingEnveloping:
		return sign.PackagingEnveloping, "ENVELOPING", nil
	default:
		return "", "", fmt.Errorf("xades: invalid packaging %q (expected detached or enveloping)", p)
	}
}

// resolveDigest maps the digest name to a crypto.Hash and the DSS enum name.
func resolveDigest(d string) (crypto.Hash, string, error) {
	switch d {
	case "sha256", "":
		return crypto.SHA256, "SHA256", nil
	case "sha1":
		return crypto.SHA1, "SHA1", nil
	default:
		return 0, "", fmt.Errorf("xades: unsupported digest %q (expected sha256 or sha1)", d)
	}
}

// resolveLevel maps the AdES level to the DSS baseline SignatureLevel name.
// BASELINE with en319132=false emits the v1 SigningCertificate (verified against
// the vendor sample); no legacy XAdES_BES/XAdES_T fallback is needed.
func resolveLevel(l sign.Level) (name string, timestamp bool, err error) {
	switch l {
	case sign.LevelB:
		return "XAdES_BASELINE_B", false, nil
	case sign.LevelT:
		return "XAdES_BASELINE_T", true, nil
	default:
		return "", false, fmt.Errorf("xades: invalid level %q (expected b or t)", l)
	}
}

// hashSum returns h(data). h must be a linked hash (SHA-256/SHA-1).
func hashSum(h crypto.Hash, data []byte) []byte {
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

// mimeTypeFor returns a MIME type label for a filename by extension. It never
// inspects a local path -- only the basename extension.
func mimeTypeFor(name string) string {
	switch filepath.Ext(name) {
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain"
	case ".xml":
		return "text/xml"
	case ".json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

func b64encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func b64decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// writeOutput writes the signed XAdES to path, creating parent dirs.
func writeOutput(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("xades: empty output path")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("xades: create out dir for %q: %w", path, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("xades: write signed XAdES %q: %w", path, err)
	}
	return nil
}
