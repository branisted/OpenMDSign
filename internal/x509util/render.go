package x509util

import (
	"fmt"
	"io"
	"strings"
)

// Render writes a human-readable, indented view of the certificate to w.
// indent is prefixed to every line so callers can nest it under a heading.
func (ci *CertInfo) Render(w io.Writer, indent string) {
	p := func(format string, args ...any) {
		fmt.Fprintf(w, indent+format+"\n", args...)
	}
	p("Subject:            %s", ci.Subject)
	p("Issuer:             %s", ci.Issuer)
	p("Serial:             %s", ci.SerialNumber)
	p("Validity:           %s  ..  %s", ci.NotBefore, ci.NotAfter)
	p("Signature Alg:      %s", ci.SignatureAlgorithm)
	p("Public Key:         %s (%d bits)", ci.PublicKeyAlgorithm, ci.PublicKeyBits)
	if len(ci.KeyUsage) > 0 {
		p("Key Usage:          %s", strings.Join(ci.KeyUsage, ", "))
	}
	if len(ci.ExtKeyUsage) > 0 {
		p("Ext Key Usage:      %s", strings.Join(ci.ExtKeyUsage, ", "))
	}
	for _, u := range ci.OCSPServers {
		p("AIA OCSP:           %s", u)
	}
	for _, u := range ci.CAIssuers {
		p("AIA caIssuers:      %s", u)
	}
	for _, u := range ci.CRLDistribution {
		p("CRL Dist Point:     %s", u)
	}
	if len(ci.PolicyOIDs) > 0 {
		p("Certificate Policy: %s", strings.Join(ci.PolicyOIDs, ", "))
	}
	for _, qc := range ci.QCStatements {
		line := fmt.Sprintf("%s (%s)", qc.Name, qc.OID)
		if qc.Detail != "" {
			line += ": " + qc.Detail
		}
		p("QC Statement:       %s", line)
	}
}
