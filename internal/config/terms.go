package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxTermsTextLen is the largest terms of use file (oauth.page.terms_file), in bytes.
const MaxTermsTextLen = 32 << 10

// resolveTermsPath makes a relative terms_file path absolute against baseDir.
func (p *Page) resolveTermsPath(baseDir string) {
	p.TermsFile = strings.TrimSpace(p.TermsFile)
	if p.TermsFile != "" && !filepath.IsAbs(p.TermsFile) {
		p.TermsFile = filepath.Join(baseDir, p.TermsFile)
	}
}

// loadTerms reads and checks the terms file, when one is configured. An error
// names the field and the OS error (which carries the path, not content); the
// content is never echoed.
func (p *Page) loadTerms() []error {
	if p.TermsFile == "" {
		return nil
	}
	text, err := readTermsFile(p.TermsFile)
	if err != nil {
		return []error{fmt.Errorf("oauth.page.terms_file: %w", err)}
	}
	p.TermsText = text
	return nil
}

// readTermsFile reads one terms file: at most MaxTermsTextLen bytes of valid
// UTF-8 text with no control or format characters but newline and tab; CRLF is
// normalized to LF.
func readTermsFile(path string) (string, error) {
	// Stat follows symlinks; a FIFO or device would block or never end.
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxTermsTextLen+1))
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	if len(raw) > MaxTermsTextLen {
		return "", fmt.Errorf("file is longer than %d bytes", MaxTermsTextLen)
	}
	text := strings.TrimSpace(strings.ReplaceAll(string(raw), "\r\n", "\n"))
	switch {
	case text == "":
		return "", errors.New("file must not be empty")
	case badText(text, true):
		return "", errors.New("file must be valid UTF-8 text without control or format characters (newline and tab are allowed)")
	}
	return text, nil
}
