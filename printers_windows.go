//go:build windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

/*
Windows printing
────────────────

Enumeration is easy: Win32_Printer via PowerShell.

Printing is not. Windows has no supported way to send a PDF to a *named* printer
from the command line — the shell's "print" verb targets only the default
printer, and the spooler will not accept raw PDF unless the device happens to
speak PostScript or PDF, which most desk lasers and inkjets do not.

So the agent uses a helper that can rasterise a PDF and drive the spooler, tried
in this order:

 1. SumatraPDF beside the binary (what the installer ships) or at a configured
    path. `-print-to` targets a queue by name and `-silent` suppresses its UI.
 2. The shell's `printto` verb, which works when a PDF reader that registers it
    is installed (Acrobat and Foxit do; Edge does not).
 3. Nothing — return errNoPdfHelper, and Sally quietly falls back to the
    browser's print dialog rather than failing the user's print.
*/

// commandTimeout bounds every shell-out. A wedged helper must not hold a
// request open forever.
const commandTimeout = 60 * time.Second

func isWindows() bool { return true }

// hidden keeps PowerShell and the print helper from flashing a console window
// on a machine where the agent runs windowless at login.
func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

// listPrintersOS enumerates installed queues.
//
// The output is one printer per line as "<default>\t<name>" rather than JSON:
// ConvertTo-Json unwraps a single-element array in Windows PowerShell 5.1, so a
// machine with exactly one printer would return an object where every other
// machine returns a list. A delimited line avoids the special case entirely.
func listPrintersOS() ([]Printer, error) {
	const script = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop |
  ForEach-Object { "$($_.Default)` + "`t" + `$($_.Name)" }
`
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := hidden(exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listing printers: %w", err)
	}

	var list []Printer
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		isDefault, name, found := strings.Cut(line, "\t")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		list = append(list, Printer{
			Name:      name,
			IsDefault: strings.EqualFold(strings.TrimSpace(isDefault), "true"),
		})
	}
	return list, nil
}

// findHelper locates the PDF print helper, preferring the copy the installer
// placed beside the agent so behaviour does not depend on what else the user
// happens to have installed.
func findHelper(configured string) string {
	return firstExisting(
		configured,
		besideExecutable("SumatraPDF.exe"),
		besideExecutable(`helper\SumatraPDF.exe`),
		`C:\Program Files\SumatraPDF\SumatraPDF.exe`,
		`C:\Program Files (x86)\SumatraPDF\SumatraPDF.exe`,
	)
}

// canPrintOS reports whether this machine can actually spool a PDF.
//
// Sally asks before offering a printer picker: without a helper the agent can
// enumerate printers but not print to them, and a dropdown that is silently
// ignored is worse than no dropdown. The `printto` verb may still work at print
// time even when this says no, so this deliberately under-promises.
func canPrintOS(cfg *Config) bool {
	return findHelper(cfg.HelperPath) != ""
}

// printPDFOS sends path to the named printer. printer is always a name the OS
// itself reported (resolvePrinter guarantees it), never caller-supplied text.
func printPDFOS(cfg *Config, path, printer, jobName string, copies int) error {
	if helper := findHelper(cfg.HelperPath); helper != "" {
		return printViaHelper(helper, path, printer, copies)
	}
	if err := printViaShellVerb(path, printer); err == nil {
		return nil
	} else if !isVerbUnavailable(err) {
		return err
	}
	return errNoPdfHelper
}

func printViaHelper(helper, path, printer string, copies int) error {
	args := []string{"-print-to", printer, "-silent", "-exit-when-done"}
	if copies > 1 {
		// SumatraPDF spells a copy count as "<n>x" in its print settings.
		args = append(args, "-print-settings", strconv.Itoa(copies)+"x")
	}
	args = append(args, path)

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := hidden(exec.CommandContext(ctx, helper, args...))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("print helper failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// printViaShellVerb asks the registered PDF handler to print to a named queue.
// Only some readers implement the verb, so a failure here is not fatal.
func printViaShellVerb(path, printer string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// Arguments are passed as PowerShell parameters rather than interpolated
	// into a command string, so a printer name with quotes cannot break out.
	const script = `
param([string]$File, [string]$Printer)
Start-Process -FilePath $File -Verb PrintTo -ArgumentList $Printer -PassThru -ErrorAction Stop | Out-Null
`
	cmd := hidden(exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script, "-File", path, "-Printer", printer))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("printto verb failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isVerbUnavailable distinguishes "no PDF reader registered the verb" (try the
// next strategy) from a real printing failure (report it).
func isVerbUnavailable(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "printto") ||
		strings.Contains(msg, "no application is associated") ||
		strings.Contains(msg, "cannot find the file")
}

// copiesNote explains, for the status page, how copies are handled here.
func copiesNote() string {
	return "Copies are sent to the print helper; Sally also renders labelled copies into invoice PDFs itself."
}
