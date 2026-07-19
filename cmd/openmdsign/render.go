package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/branisted/openmdsign/internal/token"
	"github.com/branisted/openmdsign/internal/x509util"
)

func emitText(rep *token.Report, outdir string) {
	w := os.Stdout
	fmt.Fprintf(w, "PKCS#11 module: %s\n", rep.Module)
	fmt.Fprintln(w, "=== Library (C_GetInfo) ===")
	fmt.Fprintf(w, "  Manufacturer:     %s\n", rep.Library.Manufacturer)
	fmt.Fprintf(w, "  Description:      %s\n", rep.Library.Description)
	fmt.Fprintf(w, "  Cryptoki version: %s\n", rep.Library.CryptokiVersion)
	fmt.Fprintf(w, "  Library version:  %s\n", rep.Library.LibraryVersion)

	if rep.Note != "" {
		fmt.Fprintf(w, "\nNote: %s\n", rep.Note)
	}
	if len(rep.Slots) == 0 {
		fmt.Fprintln(w, "\nNo slots to report.")
		return
	}

	for _, s := range rep.Slots {
		fmt.Fprintf(w, "\n=== Slot %d ===\n", s.ID)
		fmt.Fprintf(w, "  Description:  %s\n", s.Description)
		fmt.Fprintf(w, "  Manufacturer: %s\n", s.Manufacturer)
		fmt.Fprintf(w, "  Flags:        %s\n", strings.Join(s.Flags, ", "))
		fmt.Fprintf(w, "  Token present: %t\n", s.TokenPresent)

		for _, warn := range s.Warnings {
			fmt.Fprintf(w, "  !! WARNING: %s\n", warn)
		}

		if s.Token != nil {
			fmt.Fprintln(w, "  --- Token ---")
			fmt.Fprintf(w, "    Label:        %s\n", s.Token.Label)
			fmt.Fprintf(w, "    Manufacturer: %s\n", s.Token.Manufacturer)
			fmt.Fprintf(w, "    Model:        %s\n", s.Token.Model)
			fmt.Fprintf(w, "    Serial:       %s\n", s.Token.SerialNumber)
			fmt.Fprintf(w, "    Flags:        %s\n", strings.Join(s.Token.Flags, ", "))
		}

		if s.SignatureMechs != nil {
			m := s.SignatureMechs
			fmt.Fprintln(w, "  --- Signing mechanism summary ---")
			fmt.Fprintf(w, "    CKM_SHA256_RSA_PKCS (on-token hash+sign): %s\n", yesNo(m.HasSHA256RSAPKCS))
			fmt.Fprintf(w, "    CKM_RSA_PKCS (raw sign):                  %s\n", yesNo(m.HasRSAPKCS))
			fmt.Fprintf(w, "    CKM_RSA_PKCS_PSS:                         %s\n", yesNo(m.HasRSAPKCSPSS))
			fmt.Fprintf(w, "    CKM_SHA256_RSA_PKCS_PSS:                  %s\n", yesNo(m.HasSHA256RSAPKCSPSS))
			fmt.Fprintf(w, "    CKM_SHA256 (standalone digest):           %s\n", yesNo(m.HasSHA256))
		}

		if len(s.Mechanisms) > 0 {
			fmt.Fprintf(w, "  --- Mechanisms (%d) ---\n", len(s.Mechanisms))
			for _, m := range s.Mechanisms {
				if isKeyMech(m.Code) {
					fmt.Fprintf(w, "    0x%08X %-28s keysize %d..%d flags[%s]\n",
						m.Code, m.Name, m.MinKeySize, m.MaxKeySize, strings.Join(m.Flags, ","))
				} else {
					fmt.Fprintf(w, "    0x%08X %s\n", m.Code, m.Name)
				}
			}
		}

		certN := 0
		if len(s.Objects) > 0 {
			fmt.Fprintf(w, "  --- Objects (%d) ---\n", len(s.Objects))
			for _, o := range s.Objects {
				line := "    " + o.Class
				if o.IDHex != "" {
					line += "  id=" + o.IDHex
				}
				if o.Label != "" {
					line += "  label=" + o.Label
				}
				if o.KeyType != "" {
					line += "  keytype=" + o.KeyType
				}
				if o.ModulusBits > 0 {
					line += fmt.Sprintf("  modulusBits=%d", o.ModulusBits)
				}
				if o.CanSign != nil {
					line += fmt.Sprintf("  canSign=%t", *o.CanSign)
				}
				fmt.Fprintln(w, line)
				if len(o.CertDER) > 0 {
					certN++
					if ci, err := x509util.Parse(o.CertDER); err == nil {
						ci.Render(w, "        ")
					} else {
						fmt.Fprintf(w, "        (failed to parse certificate: %v)\n", err)
					}
					id := o.IDHex
					if id == "" {
						id = "noid"
					}
					fmt.Fprintf(w, "        Exported DER: %s\n", filepath.Join(outdir, "cert-"+id+".der"))
				}
			}
		}

		if s.Login != nil {
			fmt.Fprintln(w, "  --- Login ---")
			fmt.Fprintf(w, "    Attempted: %t  Succeeded: %t\n", s.Login.Attempted, s.Login.Succeeded)
			if s.Login.Error != "" {
				fmt.Fprintf(w, "    Error: %s\n", s.Login.Error)
			}
		}
		_ = certN
	}
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "no"
}

func isKeyMech(code uint) bool {
	switch code {
	case token.CKM_RSA_PKCS, token.CKM_SHA256_RSA_PKCS, token.CKM_RSA_PKCS_PSS,
		token.CKM_SHA256_RSA_PKCS_PSS:
		return true
	}
	return false
}

// fileHint runs `file` on the module path to help diagnose a load failure
// (e.g. an x86_64-only dylib against an arm64 binary).
func fileHint(path string) string {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Sprintf("file does not exist: %s", path)
		}
		return err.Error()
	}
	out, err := exec.Command("file", path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
