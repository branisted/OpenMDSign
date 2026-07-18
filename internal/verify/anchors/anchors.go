// Package anchors embeds the STISC (Serviciul Tehnologia Informaţiei şi
// Securitate Cibernetică) public CA certificates used as trust anchors when
// verifying MoldSign-family signatures offline.
//
// These are PUBLIC certificate-authority certificates fetched from the public
// Moldovan PKI distribution points (see README.md for the source URL and
// SHA-256 fingerprint of each). They are NOT sourced from the proprietary
// vendor keystore and contain no personal data — they are the same public CA
// certs any relying party downloads to validate a chain.
package anchors

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.pem
var files embed.FS

// Anchor is one embedded trust-anchor certificate together with provenance.
type Anchor struct {
	// File is the embedded PEM file name (e.g. "mdtrustca.pem").
	File string
	// Certificate is the parsed certificate.
	Certificate *x509.Certificate
	// SHA256 is the lowercase hex SHA-256 fingerprint of the DER bytes.
	SHA256 string
	// SelfSigned reports whether subject == issuer (i.e. a root suitable as an
	// x509 verification root rather than an intermediate).
	SelfSigned bool
}

// Load parses every embedded anchor PEM. It returns an error if any file fails
// to parse, so a corrupt bundle is caught at startup rather than silently
// dropping a trust anchor.
func Load() ([]Anchor, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("anchors: read embedded dir: %w", err)
	}
	var out []Anchor
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".pem") {
			continue
		}
		raw, err := files.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("anchors: read %s: %w", name, err)
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("anchors: %s: no PEM CERTIFICATE block", name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("anchors: %s: parse certificate: %w", name, err)
		}
		sum := sha256.Sum256(cert.Raw)
		out = append(out, Anchor{
			File:        name,
			Certificate: cert,
			SHA256:      hex.EncodeToString(sum[:]),
			SelfSigned:  cert.Subject.String() == cert.Issuer.String(),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("anchors: no embedded certificates found")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}

// Pools splits the loaded anchors into an x509 roots pool (self-signed anchors)
// and an intermediates pool (non-self-signed anchors, e.g. the issuing CA).
// Both are non-nil. Extra certificates may be added to either by the caller.
func Pools(anchors []Anchor) (roots, intermediates *x509.CertPool) {
	roots = x509.NewCertPool()
	intermediates = x509.NewCertPool()
	for _, a := range anchors {
		if a.SelfSigned {
			roots.AddCert(a.Certificate)
		} else {
			intermediates.AddCert(a.Certificate)
		}
	}
	return roots, intermediates
}
