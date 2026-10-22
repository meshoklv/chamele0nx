package main

import (
	"fmt"
	"os"
	"strings"
)

// resolveSecret returns the hex-encoded user secret, taking it from the
// first source that provides one:
//
//  1. -secret-file             (path given on the command line)
//  2. -secret                  (value given on the command line)
//  3. $CHAMELE0NX_SECRET_FILE   (path; handy when a supervisor decrypts
//     a credential into a file at start time)
//  4. $CHAMELE0NX_SECRET        (value)
//
// Command line arguments win over the environment, so an inherited
// variable can never quietly override what an operator typed.
//
// It returns an empty string when no source provides a secret; the
// caller decides whether that is fatal or means "generate one".
//
// File-based sources are preferred: anything passed as a command line
// argument is visible to every user on the machine through `ps`.
func resolveSecret(secretFile, secretValue string) (string, error) {
	readFile := func(path string) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read secret file %q: %w", path, err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "", fmt.Errorf("secret file %q is empty", path)
		}
		return s, nil
	}

	if secretFile != "" {
		return readFile(secretFile)
	}
	if secretValue != "" {
		return secretValue, nil
	}
	if envFile := os.Getenv("CHAMELE0NX_SECRET_FILE"); envFile != "" {
		return readFile(envFile)
	}
	return strings.TrimSpace(os.Getenv("CHAMELE0NX_SECRET")), nil
}
