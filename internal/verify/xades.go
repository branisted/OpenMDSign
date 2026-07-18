package verify

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/branistedev/openmdsign/internal/sign/xades"
)

// fileRefRe matches a detached signed-file reference URI="file:/<name>".
var fileRefRe = regexp.MustCompile(`URI\s*=\s*"file:/+([^"]+)"`)

// verifyXAdES validates a standalone XAdES signature via the EU DSS helper,
// seeded with the embedded STISC trust anchors.
func verifyXAdES(ctx context.Context, xml []byte, opts Options) (*Result, error) {
	anchorList, err := trustAnchors(opts.ExtraAnchorsPEM)
	if err != nil {
		return nil, err
	}
	var anchorsDER [][]byte
	for _, a := range anchorList {
		anchorsDER = append(anchorsDER, a.Certificate.Raw)
	}

	detachedContent, detachedName, err := resolveDetached(xml, opts)
	if err != nil {
		return nil, err
	}

	vr, err := xades.Validate(ctx, xades.ValidateInput{
		XML:             xml,
		DetachedContent: detachedContent,
		DetachedName:    detachedName,
		Anchors:         anchorsDER,
		CheckRevocation: opts.CheckRevocation,
		JavaPath:        opts.JavaPath,
		JarPath:         opts.JarPath,
	})
	if err != nil {
		return nil, err
	}

	res := &Result{
		Profile:       "xades",
		Indication:    vr.Indication,
		SubIndication: vr.SubIndication,
		Signer: SignerInfo{
			Subject:     vr.SignedBy,
			SigningTime: vr.SigningTime,
		},
	}
	if vr.TimestampTime != "" || vr.TimestampProducedBy != "" {
		res.Timestamp = &TimestampInfo{
			Time: vr.TimestampTime,
			TSA:  vr.TimestampProducedBy,
		}
	}

	switch vr.Indication {
	case "TOTAL_PASSED", "PASSED":
		res.Overall = Valid
		res.Chain = ChainInfo{Status: "trusted"}
	case "TOTAL_FAILED", "FAILED":
		res.Overall = Invalid
		res.Reason = "DSS reported " + vr.Indication + subDetail(vr.SubIndication)
		res.Chain = ChainInfo{Status: "indeterminate"}
	default: // INDETERMINATE and anything unexpected
		res.Overall = Indeterminate
		res.Reason = "DSS reported " + nz(vr.Indication, "no indication") + subDetail(vr.SubIndication)
		res.Chain = ChainInfo{Status: "indeterminate", Detail: vr.SubIndication}
	}
	return res, nil
}

// resolveDetached decides whether the XAdES is detached and, if so, supplies
// the original document bytes: --original if given, else a sibling file named
// after the file:/<name> reference next to the signature.
func resolveDetached(xml []byte, opts Options) (content []byte, name string, err error) {
	if opts.OriginalPath != "" {
		b, err := os.ReadFile(opts.OriginalPath)
		if err != nil {
			return nil, "", fmt.Errorf("read --original %q: %w", opts.OriginalPath, err)
		}
		return b, filepath.Base(opts.OriginalPath), nil
	}

	m := fileRefRe.FindSubmatch(xml)
	if m == nil {
		// No detached file:/ reference: enveloping/enveloped, self-contained.
		return nil, "", nil
	}
	ref := string(m[1])
	base := filepath.Base(ref)
	sibling := base
	if opts.FilePath != "" {
		sibling = filepath.Join(filepath.Dir(opts.FilePath), base)
	}
	b, readErr := os.ReadFile(sibling)
	if readErr != nil {
		return nil, "", fmt.Errorf("detached XAdES references file:/%s but the original was not supplied and no sibling %q was found: pass --original <file>",
			ref, sibling)
	}
	return b, base, nil
}

func subDetail(sub string) string {
	if sub == "" {
		return ""
	}
	return " (" + sub + ")"
}

func nz(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}
