package xades

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// helper drives the long-running EU DSS helper subprocess over line-delimited
// JSON on stdin/stdout. One helper instance serves exactly one signing session
// (getDataToSign -> signDocument), keeping the SignedInfo consistent across the
// two-step external-signing exchange. The PKCS#11 PIN and private key never
// reach this process: it only ever sees the data-to-be-signed and the returned
// signature value.
type helper struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *strings.Builder
}

// getDataToSignReq is the first request of the two-step exchange.
type getDataToSignReq struct {
	Op             string `json:"op"`
	Level          string `json:"level"`          // DSS SignatureLevel enum name
	Packaging      string `json:"packaging"`      // DSS SignaturePackaging enum name
	DigestAlgo     string `json:"digestAlgo"`     // DSS DigestAlgorithm enum name
	SigningCertB64 string `json:"signingCertB64"` // DER, base64
	FileB64        string `json:"fileB64"`        // raw file bytes, base64
	ReferencedName string `json:"referencedName"` // detached: file:/<basename>
	MimeType       string `json:"mimeType"`
	SigningTime    string `json:"signingTime"` // RFC 3339 / ISO-8601 instant
	TSAURL         string `json:"tsaUrl,omitempty"`
	En319132       bool   `json:"en319132"`
}

// signDocumentReq is the second request, carrying the token-produced signature.
type signDocumentReq struct {
	Op             string `json:"op"`
	SignatureValue string `json:"signatureValue"` // base64
}

// resp is the shared response envelope.
type resp struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error"`
	DTBS          string `json:"dtbs"`
	XML           string `json:"xml"`
	Indication    string `json:"indication"`
	SubIndication string `json:"subIndication"`
	SignatureID   string `json:"signatureId"`
	// validate-only enrichment fields (from the DSS simple report).
	SignedBy            string `json:"signedBy"`
	SigningTime         string `json:"signingTime"`
	TimestampTime       string `json:"timestampTime"`
	TimestampProducedBy string `json:"timestampProducedBy"`
}

// startHelper spawns the DSS helper jar. javaPath may be empty (resolved from
// the environment). jarPath must point at a readable dss-helper.jar.
func startHelper(ctx context.Context, javaPath, jarPath string) (*helper, error) {
	if jarPath == "" {
		return nil, fmt.Errorf("xades: no DSS helper jar configured (pass --dss-helper or set OPENMDSIGN_DSS_HELPER)")
	}
	if _, err := os.Stat(jarPath); err != nil {
		return nil, fmt.Errorf("xades: DSS helper jar not found at %q: %w "+
			"(build it with `mvn -q package` in java/dss-helper, or pass --dss-helper)", jarPath, err)
	}
	java, err := resolveJava(javaPath)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, java, "-jar", jarPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("xades: helper stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("xades: helper stdout pipe: %w", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("xades: start DSS helper (%s -jar %s): %w", java, jarPath, err)
	}
	return &helper{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 1<<20),
		stderr: &stderr,
	}, nil
}

// call writes one JSON request line and reads exactly one JSON response line.
func (h *helper) call(req any) (*resp, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("xades: marshal helper request: %w", err)
	}
	if _, err := h.stdin.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("xades: write to helper: %w (stderr: %s)", err, h.stderrTail())
	}
	respLine, err := h.stdout.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("xades: read helper response: %w (stderr: %s)", err, h.stderrTail())
	}
	var r resp
	if err := json.Unmarshal(respLine, &r); err != nil {
		return nil, fmt.Errorf("xades: decode helper response %q: %w", strings.TrimSpace(string(respLine)), err)
	}
	if !r.OK {
		return nil, fmt.Errorf("xades: DSS helper error: %s", r.Error)
	}
	return &r, nil
}

// getDataToSign performs step 1: DSS builds the SignedInfo and returns the DTBS.
func (h *helper) getDataToSign(req getDataToSignReq) ([]byte, error) {
	req.Op = "getDataToSign"
	r, err := h.call(req)
	if err != nil {
		return nil, err
	}
	dtbs, err := b64decode(r.DTBS)
	if err != nil {
		return nil, fmt.Errorf("xades: decode DTBS: %w", err)
	}
	return dtbs, nil
}

// signDocument performs step 2: DSS assembles the final XAdES around sigValue
// (and, for -T, calls the TSA). It returns the finished XAdES bytes.
func (h *helper) signDocument(sigValue []byte) ([]byte, error) {
	r, err := h.call(signDocumentReq{Op: "signDocument", SignatureValue: b64encode(sigValue)})
	if err != nil {
		return nil, err
	}
	xml, err := b64decode(r.XML)
	if err != nil {
		return nil, fmt.Errorf("xades: decode signed XML: %w", err)
	}
	return xml, nil
}

// close shuts the helper down (closing stdin makes it exit its read loop).
func (h *helper) close() {
	if h == nil {
		return
	}
	if h.stdin != nil {
		_ = h.stdin.Close()
	}
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Wait()
	}
}

func (h *helper) stderrTail() string {
	s := strings.TrimSpace(h.stderr.String())
	const max = 500
	if len(s) > max {
		return "..." + s[len(s)-max:]
	}
	return s
}

// resolveJava finds a Java launcher. Precedence: explicit path, then
// OPENMDSIGN_JAVA, then $JAVA_HOME/bin/java, then "java" on PATH.
//
// Note: a bare mise shim ("java") can fail when spawned outside an activated
// mise shell; prefer JAVA_HOME or OPENMDSIGN_JAVA in that setup.
func resolveJava(explicit string) (string, error) {
	candidates := []string{explicit, os.Getenv("OPENMDSIGN_JAVA")}
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		candidates = append(candidates, filepath.Join(jh, "bin", "java"))
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, nil
		}
	}
	if p, err := exec.LookPath("java"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("xades: no Java runtime found: set JAVA_HOME or OPENMDSIGN_JAVA, " +
		"or put java (temurin-21) on PATH (the XAdES profile needs the JVM for EU DSS)")
}
