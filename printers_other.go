//go:build !windows && !darwin

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

/*
Other platforms (Linux and friends)
───────────────────────────────────

Not a shipped target — Sally's users are on Windows and macOS. This file exists
so the agent still builds and its tests still run on a Linux CI box, and it uses
CUPS exactly as macOS does, so a developer on Linux gets a working agent for
free rather than a compile error.
*/

const commandTimeout = 60 * time.Second

func isWindows() bool { return false }

func hidden(cmd *exec.Cmd) *exec.Cmd { return cmd }

func listPrintersOS() ([]Printer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "lpstat", "-e").Output()
	if err != nil {
		return nil, fmt.Errorf("listing printers: %w", err)
	}

	def := ""
	if dout, derr := exec.CommandContext(ctx, "lpstat", "-d").Output(); derr == nil {
		if _, after, found := strings.Cut(string(dout), ":"); found {
			def = strings.TrimSpace(after)
		}
	}

	var list []Printer
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		list = append(list, Printer{Name: name, IsDefault: name == def})
	}
	return list, nil
}

// canPrintOS reports whether this machine can spool a PDF. CUPS takes PDF
// natively, so the only question is whether lp is on the box at all.
func canPrintOS(_ *Config) bool {
	_, err := exec.LookPath("lp")
	return err == nil
}

func printPDFOS(_ *Config, path, printer, jobName string, copies int) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	args := []string{"-d", printer, "-n", strconv.Itoa(copies)}
	if jobName != "" {
		args = append(args, "-t", jobName)
	}
	args = append(args, path)

	if out, err := exec.CommandContext(ctx, "lp", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("lp failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copiesNote() string {
	return "Copies are passed to CUPS."
}
