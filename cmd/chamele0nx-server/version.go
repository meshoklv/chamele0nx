package main

import (
	"flag"
	"fmt"
	"os"
)

// Populated at build time via -ldflags "-X main.version=... ".
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

var flagVersion = flag.Bool("version", false, "print version information and exit")

// exitIfVersionRequested prints build metadata and exits when -version was
// passed. Call it immediately after flag.Parse().
func exitIfVersionRequested(binary string) {
	if !*flagVersion {
		return
	}
	fmt.Printf("%s %s (commit %s, built %s)\n", binary, version, commit, buildDate)
	os.Exit(0)
}
