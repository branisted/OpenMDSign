package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/branistedev/openmdsign/internal/verify"
)

// Exit codes for `verify`. 0 = VALID; INVALID/INDETERMINATE are non-zero and
// distinct from a usage error so scripts can tell them apart.
const (
	exitVerifyInvalid       = 1
	exitVerifyUsage         = 2
	exitVerifyIndeterminate = 3
)

// exitError carries an explicit process exit code up to main().
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

type verifyFlags struct {
	file            string
	original        string
	profile         string
	checkRevocation bool
	json            bool
	anchors         string
	dssHelper       string
	javaPath        string
}

func newVerifyCmd(gf *globalFlags) *cobra.Command {
	f := &verifyFlags{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a PAdES or XAdES signature offline against the embedded STISC trust anchors",
		Long: "verify checks an AdES signature produced by this tool or the MoldSign\n" +
			"vendor, entirely offline by default.\n\n" +
			"Profile is autodetected (--profile auto): a %PDF header selects PAdES; an\n" +
			"XML ds:Signature selects XAdES. PAdES is verified in pure Go: the embedded\n" +
			"CMS is checked over the /ByteRange, the certificate chain is built to the\n" +
			"embedded public STISC anchors, and the RFC 3161 signature timestamp is\n" +
			"validated. XAdES is validated by the EU DSS (Java) helper, seeded with the\n" +
			"same anchors so it returns a real indication instead of\n" +
			"NO_CERTIFICATE_CHAIN_FOUND (needs Java 21 + the helper jar).\n\n" +
			"Detached XAdES needs the original document: pass --original, or place a\n" +
			"sibling file named after the file:/<name> reference next to the signature.\n\n" +
			"--check-revocation additionally performs online OCSP/CRL checks (network).\n" +
			"It is off by default so verification stays offline.\n\n" +
			"Exit codes: 0 VALID, 1 INVALID, 3 INDETERMINATE, 2 usage error.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd, gf, f)
		},
	}
	cmd.Flags().StringVar(&f.file, "file", "", "path to the signed file to verify (required)")
	cmd.Flags().StringVar(&f.original, "original", "", "the original document for a detached XAdES signature")
	cmd.Flags().StringVar(&f.profile, "profile", "auto", "profile: auto | pades | xades")
	cmd.Flags().BoolVar(&f.checkRevocation, "check-revocation", false, "also check OCSP/CRL online (needs network)")
	cmd.Flags().BoolVar(&f.json, "json", false, "emit machine-readable JSON instead of text")
	cmd.Flags().StringVar(&f.anchors, "anchors", "", "path to an extra PEM bundle of trust anchors to add")
	cmd.Flags().StringVar(&f.dssHelper, "dss-helper", "", "path to the EU DSS helper jar (XAdES). Default: "+defaultDSSHelperJar+" or $OPENMDSIGN_DSS_HELPER")
	cmd.Flags().StringVar(&f.javaPath, "java", "", "path to the Java 21 launcher (XAdES). Default: $OPENMDSIGN_JAVA / $JAVA_HOME / PATH")
	return cmd
}

func runVerify(_ *cobra.Command, _ *globalFlags, f *verifyFlags) error {
	if f.file == "" {
		return &exitError{code: exitVerifyUsage, msg: "--file is required"}
	}

	var extraAnchors []byte
	if f.anchors != "" {
		b, err := os.ReadFile(f.anchors)
		if err != nil {
			return &exitError{code: exitVerifyUsage, msg: fmt.Sprintf("read --anchors %q: %v", f.anchors, err)}
		}
		extraAnchors = b
	}

	helperJar := f.dssHelper
	if helperJar == "" {
		helperJar = os.Getenv("OPENMDSIGN_DSS_HELPER")
	}
	if helperJar == "" {
		helperJar = defaultDSSHelperJar
	}

	res, err := verify.Run(context.Background(), verify.Options{
		Profile:         f.profile,
		OriginalPath:    f.original,
		CheckRevocation: f.checkRevocation,
		ExtraAnchorsPEM: extraAnchors,
		JavaPath:        f.javaPath,
		JarPath:         helperJar,
		FilePath:        f.file,
	})
	if err != nil {
		return &exitError{code: exitVerifyUsage, msg: err.Error()}
	}

	if f.json {
		if err := emitVerifyJSON(res); err != nil {
			return err
		}
	} else {
		printVerifyText(res)
	}

	switch res.Overall {
	case verify.Valid:
		return nil
	case verify.Invalid:
		return &exitError{code: exitVerifyInvalid, msg: ""}
	default:
		return &exitError{code: exitVerifyIndeterminate, msg: ""}
	}
}

func emitVerifyJSON(res *verify.Result) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func printVerifyText(res *verify.Result) {
	w := os.Stdout
	fmt.Fprintln(w, "=== openmdsign verify ===")
	fmt.Fprintf(w, "  Profile:         %s\n", res.Profile)
	fmt.Fprintf(w, "  Result:          %s\n", res.Overall)
	if res.Reason != "" {
		fmt.Fprintf(w, "  Reason:          %s\n", res.Reason)
	}
	if res.Indication != "" {
		line := res.Indication
		if res.SubIndication != "" {
			line += " / " + res.SubIndication
		}
		fmt.Fprintf(w, "  DSS indication:  %s\n", line)
	}
	fmt.Fprintln(w, "  --- Signer ---")
	fmt.Fprintf(w, "  Subject:         %s\n", nzText(res.Signer.Subject))
	if res.Signer.Issuer != "" {
		fmt.Fprintf(w, "  Issuer:          %s\n", res.Signer.Issuer)
	}
	if res.Signer.IDNP != "" {
		fmt.Fprintf(w, "  IDNP/serialNo:   %s\n", res.Signer.IDNP)
	}
	if res.Signer.SerialNumber != "" {
		fmt.Fprintf(w, "  Cert serial:     %s\n", res.Signer.SerialNumber)
	}
	if res.Signer.SigningTime != "" {
		fmt.Fprintf(w, "  Signing time:    %s\n", res.Signer.SigningTime)
	}
	if res.Signer.SignatureValid != nil {
		fmt.Fprintf(w, "  Signature crypto: %s\n", yesNo(*res.Signer.SignatureValid))
	}
	if res.Timestamp != nil {
		fmt.Fprintln(w, "  --- Timestamp ---")
		fmt.Fprintf(w, "  Time:            %s\n", nzText(res.Timestamp.Time))
		if res.Timestamp.TSA != "" {
			fmt.Fprintf(w, "  TSA:             %s\n", res.Timestamp.TSA)
		}
		if res.Timestamp.HashAlgorithm != "" {
			fmt.Fprintf(w, "  Hash algorithm:  %s\n", res.Timestamp.HashAlgorithm)
		}
		if res.Timestamp.Valid != nil {
			fmt.Fprintf(w, "  Token valid:     %s\n", yesNo(*res.Timestamp.Valid))
		}
	}
	fmt.Fprintln(w, "  --- Chain ---")
	fmt.Fprintf(w, "  Status:          %s\n", res.Chain.Status)
	if res.Chain.Anchor != "" {
		fmt.Fprintf(w, "  Trust anchor:    %s\n", res.Chain.Anchor)
	}
	if res.Chain.Detail != "" {
		fmt.Fprintf(w, "  Detail:          %s\n", res.Chain.Detail)
	}
	for _, warn := range res.Warnings {
		fmt.Fprintf(w, "  warning:         %s\n", warn)
	}
}

func nzText(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}
