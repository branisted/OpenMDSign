package server

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

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
	out, err := cmd.Output()
	if err != nil {
		// osascript exits non-zero when the user presses Cancel (error -128) or
		// closes the dialog. Treat every declined/aborted dialog as a cancel so
		// no token access is attempted. Never include the PIN (there is none on
		// this path) and never echo stderr verbatim to the client.
		return "", ErrUserCancelled
	}
	pin := strings.TrimRight(string(out), "\r\n")
	if pin == "" {
		// An empty PIN can never satisfy C_Login; treat it as a cancel rather
		// than burning the single (lockout-risking) login attempt.
		return "", ErrUserCancelled
	}
	return pin, nil
}
