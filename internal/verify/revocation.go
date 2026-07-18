package verify

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/branistedev/openmdsign/internal/verify/anchors"
)

type revResult struct {
	revoked bool
	detail  string
}

// checkRevocation performs an online OCSP check of leaf against its issuer,
// falling back to the CRL distribution point when OCSP is unavailable. It is a
// best-effort network check: any failure is reported in detail but does not by
// itself mark the certificate revoked (that stays an INDETERMINATE concern).
func checkRevocation(leaf *x509.Certificate, embedded []*x509.Certificate, anchorList []anchors.Anchor) revResult {
	issuer := findIssuer(leaf, embedded, anchorList)
	if issuer == nil {
		return revResult{detail: "issuer certificate not found; cannot build OCSP/CRL request"}
	}

	client := &http.Client{Timeout: 15 * time.Second}

	// OCSP first (AIA).
	if len(leaf.OCSPServer) > 0 {
		revoked, detail, ok := ocspCheck(client, leaf, issuer, leaf.OCSPServer[0])
		if ok {
			return revResult{revoked: revoked, detail: detail}
		}
		// fall through to CRL on OCSP failure
	}

	// CRL fallback (CRLDP).
	if len(leaf.CRLDistributionPoints) > 0 {
		revoked, detail, ok := crlCheck(client, leaf, issuer, leaf.CRLDistributionPoints[0])
		if ok {
			return revResult{revoked: revoked, detail: detail}
		}
		return revResult{detail: detail}
	}
	return revResult{detail: "no OCSP or CRL distribution point in the certificate"}
}

func ocspCheck(client *http.Client, leaf, issuer *x509.Certificate, url string) (revoked bool, detail string, ok bool) {
	reqDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return false, "OCSP request build: " + err.Error(), false
	}
	httpResp, err := client.Post(url, "application/ocsp-request", bytes.NewReader(reqDER))
	if err != nil {
		return false, "OCSP POST " + url + ": " + err.Error(), false
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return false, "OCSP read: " + err.Error(), false
	}
	resp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return false, "OCSP parse: " + err.Error(), false
	}
	switch resp.Status {
	case ocsp.Revoked:
		return true, fmt.Sprintf("OCSP: REVOKED at %s", resp.RevokedAt.UTC().Format(time.RFC3339)), true
	case ocsp.Good:
		return false, "OCSP: good", true
	default:
		return false, "OCSP: unknown status", true
	}
}

func crlCheck(client *http.Client, leaf, issuer *x509.Certificate, url string) (revoked bool, detail string, ok bool) {
	httpResp, err := client.Get(url)
	if err != nil {
		return false, "CRL GET " + url + ": " + err.Error(), false
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 8<<20))
	if err != nil {
		return false, "CRL read: " + err.Error(), false
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return false, "CRL parse: " + err.Error(), false
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return false, "CRL signature: " + err.Error(), false
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return true, fmt.Sprintf("CRL: REVOKED at %s", e.RevocationTime.UTC().Format(time.RFC3339)), true
		}
	}
	return false, "CRL: not listed", true
}

// findIssuer locates the certificate that issued leaf among the embedded certs
// and the trust anchors.
func findIssuer(leaf *x509.Certificate, embedded []*x509.Certificate, anchorList []anchors.Anchor) *x509.Certificate {
	for _, c := range embedded {
		if bytes.Equal(c.RawSubject, leaf.RawIssuer) {
			if err := leaf.CheckSignatureFrom(c); err == nil {
				return c
			}
		}
	}
	for _, a := range anchorList {
		if bytes.Equal(a.Certificate.RawSubject, leaf.RawIssuer) {
			if err := leaf.CheckSignatureFrom(a.Certificate); err == nil {
				return a.Certificate
			}
		}
	}
	return nil
}
