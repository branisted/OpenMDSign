package pades

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeOutput writes the signed container to path, creating parent dirs.
func writeOutput(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("pades: empty output path")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("pades: create out dir for %q: %w", path, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("pades: write signed PDF %q: %w", path, err)
	}
	return nil
}
