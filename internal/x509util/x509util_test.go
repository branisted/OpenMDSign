package x509util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// buildQCStatementsExt builds a qcStatements extension containing QcCompliance,
// QcSSCD and QcType(esign), matching what a qualified eID certificate carries.
func buildQCStatementsExt(t *testing.T) pkix.Extension {
	t.Helper()

	marshal := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatalf("marshal qc statement: %v", err)
		}
		return b
	}

	// QcCompliance: SEQUENCE { OID }
	compliance := marshal(struct{ ID asn1.ObjectIdentifier }{oidQcCompliance})
	// QcSSCD: SEQUENCE { OID }
	sscd := marshal(struct{ ID asn1.ObjectIdentifier }{oidQcSSCD})
	// QcType: SEQUENCE { OID, SEQUENCE OF OID }
	qctype := marshal(struct {
		ID    asn1.ObjectIdentifier
		Types []asn1.ObjectIdentifier
	}{oidQcType, []asn1.ObjectIdentifier{oidQctEsign}})

	outer := []asn1.RawValue{
		{FullBytes: compliance},
		{FullBytes: sscd},
		{FullBytes: qctype},
	}
	val, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("marshal qcStatements outer: %v", err)
	}
	return pkix.Extension{Id: oidQCStatements, Critical: false, Value: val}
}

func mustOID(t *testing.T, arc ...uint64) x509.OID {
	t.Helper()
	oid, err := x509.OIDFromInts(arc)
	if err != nil {
		t.Fatalf("OIDFromInts: %v", err)
	}
	return oid
}

func makeFixtureCert(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0abc),
		Subject: pkix.Name{
			CommonName:   "TEST SIGNER 1234567890",
			Organization: []string{"OpenMDSign Test"},
			Country:      []string{"MD"},
		},
		Issuer: pkix.Name{
			CommonName: "OpenMDSign Test CA",
			Country:    []string{"MD"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth},
		OCSPServer:            []string{"http://ocsp.example.md/ocsp"},
		IssuingCertificateURL: []string{"http://ca.example.md/ca.crt"},
		CRLDistributionPoints: []string{"http://crl.example.md/ca.crl"},
		Policies:              []x509.OID{mustOID(t, 1, 3, 6, 1, 4, 1, 99999, 1, 1)},
		ExtraExtensions:       []pkix.Extension{buildQCStatementsExt(t)},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

func TestParseFixtureCert(t *testing.T) {
	der := makeFixtureCert(t)
	ci, err := Parse(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !strings.Contains(ci.Subject, "TEST SIGNER 1234567890") {
		t.Errorf("subject missing CN: %q", ci.Subject)
	}
	if ci.PublicKeyAlgorithm != "RSA" {
		t.Errorf("pubkey alg = %q, want RSA", ci.PublicKeyAlgorithm)
	}
	if ci.PublicKeyBits != 2048 {
		t.Errorf("pubkey bits = %d, want 2048", ci.PublicKeyBits)
	}
	if ci.SerialNumber != "0a:bc" {
		t.Errorf("serial = %q, want 0a:bc", ci.SerialNumber)
	}

	if !containsSub(ci.KeyUsage, "ContentCommitment") {
		t.Errorf("key usage missing ContentCommitment: %v", ci.KeyUsage)
	}
	if !contains(ci.ExtKeyUsage, "EmailProtection") {
		t.Errorf("ext key usage missing EmailProtection: %v", ci.ExtKeyUsage)
	}

	if !contains(ci.OCSPServers, "http://ocsp.example.md/ocsp") {
		t.Errorf("OCSP AIA missing: %v", ci.OCSPServers)
	}
	if !contains(ci.CAIssuers, "http://ca.example.md/ca.crt") {
		t.Errorf("caIssuers AIA missing: %v", ci.CAIssuers)
	}
	if !contains(ci.CRLDistribution, "http://crl.example.md/ca.crl") {
		t.Errorf("CRLDP missing: %v", ci.CRLDistribution)
	}
	if !contains(ci.PolicyOIDs, "1.3.6.1.4.1.99999.1.1") {
		t.Errorf("policy OID missing: %v", ci.PolicyOIDs)
	}

	// qcStatements
	var haveCompliance, haveSSCD, haveType bool
	for _, qc := range ci.QCStatements {
		switch qc.OID {
		case "0.4.0.1862.1.1":
			haveCompliance = true
		case "0.4.0.1862.1.4":
			haveSSCD = true
		case "0.4.0.1862.1.6":
			haveType = true
			if !strings.Contains(qc.Detail, "esign") {
				t.Errorf("QcType detail missing esign: %q", qc.Detail)
			}
		}
	}
	if !haveCompliance {
		t.Errorf("QcCompliance not parsed: %+v", ci.QCStatements)
	}
	if !haveSSCD {
		t.Errorf("QcSSCD not parsed: %+v", ci.QCStatements)
	}
	if !haveType {
		t.Errorf("QcType not parsed: %+v", ci.QCStatements)
	}
}

func TestParseUnknownQCStatementOIDRaw(t *testing.T) {
	// A statement with an unknown OID should still be surfaced with its raw OID.
	unknown := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	inner, err := asn1.Marshal(struct{ ID asn1.ObjectIdentifier }{unknown})
	if err != nil {
		t.Fatal(err)
	}
	qs := describeQCStatement(unknown, asn1.RawValue{})
	if qs.OID != "1.2.3.4.5.6.7" {
		t.Errorf("unknown OID = %q", qs.OID)
	}
	if qs.Name != "Unknown qcStatement" {
		t.Errorf("unknown name = %q", qs.Name)
	}
	_ = inner
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func containsSub(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}
