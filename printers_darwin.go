//go:build darwin

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
macOS printing
──────────────

Far simpler than Windows: macOS is CUPS, and PDF is CUPS's native spool format.
`lp` accepts a PDF directly, so there is no helper to bundle and no rasterising
to do — which is why there is no equivalent of errNoPdfHelper on this platform.

  lpstat -e            queue names, one per line
  lpstat -d            the system default destination
  lp -d NAME -n N -t T sends the file
*/

const commandTimeout = 60 * time.Second

func isWindows() bool { return false }

// hidden exists so the shared code can call it on both platforms; there is no
// console window to suppress here.
func hidden(cmd *exec.Cmd) *exec.Cmd { return cmd }

func listPrintersOS() ([]Printer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// `lpstat -e` prints the queue names `lp -d` expects, one per line. It is
	// preferred over `-p` because `-p` wraps the name in a status sentence that
	// varies by locale.
	out, err := exec.CommandContext(ctx, "lpstat", "-e").Output()
	if err != nil {
		return nil, fmt.Errorf("listing printers: %w", err)
	}

	def := defaultPrinter(ctx)

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

// defaultPrinter reads the system default destination, or "" when none is set.
func defaultPrinter(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "lpstat", "-d").Output()
	if err != nil {
		return ""
	}
	// "system default destination: Office_Laser" — take everything after the
	// colon. A machine with no default prints a sentence with no colon at all.
	_, after, found := strings.Cut(string(out), ":")
	if !found {
		return ""
	}
	return strings.TrimSpace(after)
}

// canPrintOS reports whether this machine can spool a PDF. CUPS takes PDF
// natively, so the only question is whether lp is on the box at all.
func canPrintOS(_ *Config) bool {
	_, err := exec.LookPath("lp")
	return err == nil
}

// printPDFOS hands the file to CUPS. printer is always a name lpstat reported.
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
	return "Copies are passed to CUPS; Sally also renders labelled copies into invoice PDFs itself."
}
