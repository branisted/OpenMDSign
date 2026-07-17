// Package x509util parses and renders X.509 certificates read off a PKCS#11
// token, with particular attention to the extensions that matter for
// interoperating with a smartcard/eID PKI: Authority Information Access (OCSP +
// caIssuers), CRL distribution points, certificate policies, and the ETSI
// qcStatements extension (OID 1.3.6.1.5.5.7.1.3).
package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
)

// oidQCStatements is the extension OID carrying ETSI EN 319 412-5 qualified
// certificate statements.
var oidQCStatements = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

// Known ETSI qcStatement statement identifiers.
var (
	oidQcCompliance      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	oidQcLimitValue      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 2}
	oidQcRetentionPeriod = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3}
	oidQcSSCD            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	oidQcPDS             = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}
	oidQcType            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}

	oidQctEsign = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}
	oidQctEseal = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}
	oidQctWeb   = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}
)

// CertInfo is a machine- and human-friendly view of a parsed certificate.
type CertInfo struct {
	Subject            string        `json:"subject"`
	Issuer             string        `json:"issuer"`
	SerialNumber       string        `json:"serial_number"`
	NotBefore          string        `json:"not_before"`
	NotAfter           string        `json:"not_after"`
	SignatureAlgorithm string        `json:"signature_algorithm"`
	PublicKeyAlgorithm string        `json:"public_key_algorithm"`
	PublicKeyBits      int           `json:"public_key_bits"`
	KeyUsage           []string      `json:"key_usage"`
	ExtKeyUsage        []string      `json:"ext_key_usage"`
	OCSPServers        []string      `json:"ocsp_servers"`
	CAIssuers          []string      `json:"ca_issuers"`
	CRLDistribution    []string      `json:"crl_distribution_points"`
	PolicyOIDs         []string      `json:"policy_oids"`
	QCStatements       []QCStatement `json:"qc_statements"`
}

// QCStatement is one parsed ETSI qcStatement.
type QCStatement struct {
	OID  string `json:"oid"`
	Name string `json:"name"`
	// Detail carries a human-readable rendering of statementInfo when we
	// recognize it (e.g. the QcType sub-OIDs). Empty otherwise.
	Detail string `json:"detail,omitempty"`
}

// Parse turns a DER-encoded certificate into a CertInfo.
func Parse(der []byte) (*CertInfo, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return FromCertificate(cert), nil
}

// FromCertificate builds a CertInfo from an already-parsed certificate.
func FromCertificate(cert *x509.Certificate) *CertInfo {
	ci := &CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       formatSerial(cert.SerialNumber),
		NotBefore:          cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:           cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:      publicKeyBits(cert),
		KeyUsage:           keyUsageStrings(cert.KeyUsage),
		ExtKeyUsage:        extKeyUsageStrings(cert),
		OCSPServers:        cert.OCSPServer,
		CAIssuers:          cert.IssuingCertificateURL,
		CRLDistribution:    cert.CRLDistributionPoints,
		PolicyOIDs:         policyStrings(cert),
	}
	if qcs, err := parseQCStatements(cert); err == nil {
		ci.QCStatements = qcs
	}
	return ci
}

func formatSerial(n *big.Int) string {
	if n == nil {
		return ""
	}
	b := n.Bytes()
	if len(b) == 0 {
		return "00"
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func publicKeyBits(cert *x509.Certificate) int {
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pk.N.BitLen()
	case *ecdsa.PublicKey:
		if pk.Curve != nil {
			return pk.Curve.Params().BitSize
		}
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

func keyUsageStrings(ku x509.KeyUsage) []string {
	var out []string
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment(NonRepudiation)"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	for _, p := range pairs {
		if ku&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return out
}

func extKeyUsageStrings(cert *x509.Certificate) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "ServerAuth",
		x509.ExtKeyUsageClientAuth:                     "ClientAuth",
		x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
		x509.ExtKeyUsageEmailProtection:                "EmailProtection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
		x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
	}
	var out []string
	for _, e := range cert.ExtKeyUsage {
		if n, ok := names[e]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("Unknown(%d)", e))
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return out
}

func policyStrings(cert *x509.Certificate) []string {
	var out []string
	// PolicyIdentifiers is the long-standing field; Policies (crypto/x509
	// OID type) is newer. Prefer whichever is populated, de-duplicating.
	seen := map[string]bool{}
	for _, oid := range cert.PolicyIdentifiers {
		s := oid.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, oid := range cert.Policies {
		s := oid.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// parseQCStatements decodes the qcStatements extension (1.3.6.1.5.5.7.1.3).
func parseQCStatements(cert *x509.Certificate) ([]QCStatement, error) {
	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidQCStatements) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return nil, nil
	}

	// qcStatements ::= SEQUENCE OF QCStatement
	// QCStatement  ::= SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }
	var statements []asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &statements); err != nil {
		return nil, fmt.Errorf("qcStatements outer SEQUENCE: %w", err)
	}

	var out []QCStatement
	for _, s := range statements {
		var inner struct {
			ID   asn1.ObjectIdentifier
			Info asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(s.FullBytes, &inner); err != nil {
			// Skip malformed statement rather than failing the whole cert.
			continue
		}
		out = append(out, describeQCStatement(inner.ID, inner.Info))
	}
	return out, nil
}

func describeQCStatement(id asn1.ObjectIdentifier, info asn1.RawValue) QCStatement {
	qs := QCStatement{OID: id.String()}
	switch {
	case id.Equal(oidQcCompliance):
		qs.Name = "QcCompliance (EU qualified certificate)"
	case id.Equal(oidQcLimitValue):
		qs.Name = "QcLimitValue (transaction value limit)"
	case id.Equal(oidQcRetentionPeriod):
		qs.Name = "QcRetentionPeriod"
	case id.Equal(oidQcSSCD):
		qs.Name = "QcSSCD (key on qualified signature-creation device)"
	case id.Equal(oidQcPDS):
		qs.Name = "QcPDS (PKI disclosure statements)"
	case id.Equal(oidQcType):
		qs.Name = "QcType"
		qs.Detail = describeQcType(info)
	default:
		qs.Name = "Unknown qcStatement"
	}
	return qs
}

// describeQcType decodes QcType ::= SEQUENCE OF OBJECT IDENTIFIER.
func describeQcType(info asn1.RawValue) string {
	if len(info.FullBytes) == 0 {
		return ""
	}
	var types []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info.FullBytes, &types); err != nil {
		return ""
	}
	var names []string
	for _, t := range types {
		switch {
		case t.Equal(oidQctEsign):
			names = append(names, "esign (electronic signature)")
		case t.Equal(oidQctEseal):
			names = append(names, "eseal (electronic seal)")
		case t.Equal(oidQctWeb):
			names = append(names, "web (website authentication)")
		default:
			names = append(names, t.String())
		}
	}
	return strings.Join(names, ", ")
}
