# Third-party notices — Sally Print Agent

The agent itself has **no third-party Go dependencies**; everything it compiles
is the Go standard library.

It does, on Windows, ship and invoke one third-party program.

---

## SumatraPDF

- **Version shipped:** 3.5.2 (64-bit)
- **Upstream:** https://www.sumatrapdfreader.org/
- **Source:** https://github.com/sumatrapdfreader/sumatrapdf
- **Licence:** GNU General Public License, version 3

### Why it is here

Windows offers no supported way to send a PDF to a *named* printer from the
command line. The shell's `print` verb targets only the default printer, and
the spooler rejects raw PDF unless the device itself speaks PostScript or PDF —
which most desk lasers and inkjets do not. SumatraPDF's `-print-to` does
exactly this job and does it well.

macOS needs nothing equivalent: CUPS takes PDF natively via `lp`.

### How it is used

The agent runs SumatraPDF as a **separate program** via `CreateProcess`
(Go's `os/exec`), passing a file path and a printer name:

```
SumatraPDF.exe -print-to "<printer>" -silent -exit-when-done <file.pdf>
```

There is no linking, no shared address space, and no derived code. Under the
GPL's own terms this is aggregation, so distributing the agent alongside
SumatraPDF does not place the agent under the GPL.

### Obligations that DO apply

Because a GPLv3 binary is redistributed, whoever ships the installer must:

1. **Include the full GPLv3 licence text** with the distribution. Ship
   `COPYING` from the SumatraPDF source tree next to the executable.
2. **Offer the corresponding source.** Either ship it, or include a written
   offer valid for three years. The practical form is a line in the installer
   and in this file naming the exact upstream tag —
   `https://github.com/sumatrapdfreader/sumatrapdf/releases/tag/3.5.2` — plus
   an address where a copy can be requested.
3. **Not restrict** the recipient's GPL rights in the Sally EULA. The EULA
   must carve SumatraPDF out of any "no reverse engineering / no
   redistribution" clause.
4. **Keep attribution intact.** Do not rename the binary in a way that
   misrepresents its origin, and do not strip its version information.

> **Open question for the release build.** Points 1–3 are the licence review
> item flagged in the README. They are routine, but they are legal obligations
> and should be signed off before the first public installer, not after.

### Avoiding the obligation entirely

If bundling GPL code turns out to be unacceptable, there is one alternative
that keeps the agent dependency-free: have the PDF renderer emit page rasters
and print them through GDI (`winspool.drv` + `gdi32`) via `x/sys/windows`. That
is pure Go with no cgo, so it preserves the single-machine cross-compile — but
it is a few hundred lines of Win32 interop and puts page scaling, DPI and the
printer safe-area margins on us rather than on a proven renderer. It was not
chosen for v1 because fidelity of the printed invoice matters more than
avoiding a well-understood licence obligation.

### Fetching it

`./fetch-helper.sh` downloads the pinned version and verifies both the archive
and the executable against recorded SHA-256 hashes. The binary is deliberately
**not committed** to this repository.
