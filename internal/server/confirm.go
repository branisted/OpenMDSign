package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrConfirmUnavailable is returned when the confirmation dialog could not be
// shown at all (osascript missing, no GUI session, TCC denial, …) — as opposed
// to the user actively cancelling. The caller logs the reason and maps it to a
// 500 so the failure is visible, never silently treated as a user cancel.
var ErrConfirmUnavailable = errors.New("openmdsignd: confirmation dialog unavailable")

// osascriptConfirmer is the production Confirmer: a native macOS dialog driven by
// osascript. It presents WHAT is being signed — the requesting Origin, the
// content type / filename, and the signFormat — and collects the PIN behind a
// hidden-answer field. This is the only place a real dialog is invoked; it is
// never reached in `go test` because tests inject a fake Confirmer.
type osascriptConfirmer struct{}

// NewOSAScriptConfirmer returns the production macOS Confirmer.
func NewOSAScriptConfirmer() Confirmer { return osascriptConfirmer{} }

// Confirm shows the confirmation dialog and returns the entered PIN. The dialog
// text is passed as an AppleScript argv item (via `on run argv`), NOT
// interpolated into the script source, so an attacker-controlled Origin cannot
// inject AppleScript. A Cancel (or any user-declined dialog) is reported as
// ErrUserCancelled so the caller performs no token access.
func (osascriptConfirmer) Confirm(ctx context.Context, req ConfirmRequest) (string, error) {
	origin := req.Origin
	if origin == "" {
		origin = "(unknown site)"
	}
	var message string
	if req.IsAuth {
		// mpass authentication/login challenge — make clear this authorizes a
		// LOGIN to the requesting site, not a document signature.
		message = fmt.Sprintf(
			"%s is requesting to LOG YOU IN (authentication).\n\n"+
				"Signing this challenge proves your identity to that site.\n\n"+
				"Enter your token PIN to authorize THIS login, or Cancel to deny.",
			origin)
	} else {
		message = fmt.Sprintf(
			"%s is requesting a signature.\n\nFormat: %s\nContent: %s (%s)\n\n"+
				"Enter your token PIN to authorize THIS operation, or Cancel to deny.",
			origin, req.SignFormat, req.Filename, req.ContentType)
	}

	// `on run argv` keeps the untrusted message out of the script body. The PIN
	// field uses `with hidden answer` so the PIN is never echoed on screen.
	const script = `on run argv
set msg to item 1 of argv
display dialog msg with title "OpenMDSign — confirm signature" default answer "" with hidden answer buttons {"Cancel", "Sign"} default button "Sign" with icon caution
return text returned of result
end run`

	cmd := exec.CommandContext(ctx, "osascript", "-e", script, "--", message)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		// Distinguish an actual user Cancel from a dialog that could not run at
		// all. On Cancel, `display dialog` raises AppleScript error -128 ("User
		// canceled"); osascript prints that to stderr and exits non-zero. Any
		// OTHER stderr (osascript missing, no window server / not run in the
		// user's GUI session, TCC denial, timeout) means the dialog never gave the
		// user a choice — surface that distinctly so it is logged, not silently
		// swallowed as a cancel. Stderr never contains a PIN (hidden-answer output
		// goes to stdout only, and only on success).
		msg := strings.ToLower(stderr.String())
		if strings.Contains(msg, "-128") || strings.Contains(msg, "user canceled") || strings.Contains(msg, "user cancelled") {
			return "", ErrUserCancelled
		}
		return "", fmt.Errorf("%w: %s", ErrConfirmUnavailable, strings.TrimSpace(stderr.String()))
	}
	pin := strings.TrimRight(string(out), "\r\n")
	if pin == "" {
		// An empty PIN can never satisfy C_Login; treat it as a cancel rather
		// than burning the single (lockout-risking) login attempt.
		return "", ErrUserCancelled
	}
	return pin, nil
}
