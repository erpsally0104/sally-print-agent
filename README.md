# Sally Print Agent

A small service users install on their own machine so Sally can print to a
**chosen printer** with no browser print dialog.

Its own repository, separate from the `erp-sally` monorepo, because it ships as
a signed downloadable binary on its own release cadence — the same arrangement
as `sally-tally-connector`, whose release pipeline this one mirrors.

It exists because no web API can enumerate printers. A page can call
`window.print()` and nothing more — it cannot see the printer list, cannot
choose a destination, and cannot suppress the dialog. Anything better has to
run outside the browser, which is what this is.

**It is an enhancement and never a dependency.** Sally probes for it; if it is
missing, stopped, or unable to print, Sally silently falls back to its browser
print path. Nothing in the app breaks when the agent is not there.

---

## How it fits together

```
Sally (https://sallyerp.in)                    This agent (127.0.0.1:17777)
  │
  ├─ GET  /v1/ping ──────────────────────────▶ "I'm here", + the token
  │        (probed on print-dialog open,          returned only to an
  │         four ports in parallel, 500ms)        allowlisted origin
  │
  ├─ GET  /v1/printers ─────────────────────▶ the machine's print queues
  │
  └─ POST /v1/print  (the PDF bytes) ───────▶ SumatraPDF (Windows) / lp (macOS)
                                                        │
                                                        ▼
                                                    the printer
```

The web-side half lives in the `erp-sally` monorepo, not here:

| | |
| --- | --- |
| `apps/web/src/lib/print-agent.ts` | the client — detection, printer list, print |
| `apps/web/src/lib/print-pdf.ts` | route selection: agent → hidden iframe → viewer tab |
| `infra/sst.config.ts` | the S3 + CloudFront distribution this publishes to |

**The two repositories share a protocol, so change it in lockstep.** Ports,
header names, endpoint shapes and the `canPrint` flag are a contract. It is
versioned (`/v1`) precisely so an old agent keeps working against a new Sally —
when you break it, bump the prefix rather than redefining `/v1` in place.

## Security

A service on loopback is unreachable from the network but reachable from
**every website the user visits**. That is the threat model, and it is worked
through in full at the top of [`security.go`](security.go). In short:

| Control | Stops |
| --- | --- |
| Binds `127.0.0.1` only | Anything off the machine |
| Origin allowlist (`config.json`) | Any site but Sally — a page cannot forge `Origin` |
| Requires `X-Sally-Token` and `Content-Type: application/pdf` | The no-preflight POST that CORS alone would let *arrive* |
| Token, delivered automatically to allowlisted origins | Other local processes; also makes pairing invisible |
| Printer names resolved against the enumerated list | Command injection through a printer name |
| 64 MiB body cap, 20-copy cap, 30 jobs/minute | Memory exhaustion and paper exhaustion |

Nothing is ever passed to a shell. Commands are executed with separated
arguments, and only a printer name the OS itself reported can reach one.

## Platform notes

**macOS** is CUPS, and PDF is its native spool format, so `lp -d NAME file.pdf`
is the whole implementation.

**Windows** has no supported way to print a PDF to a *named* printer from the
command line: the shell's `print` verb targets only the default printer, and
the spooler rejects raw PDF unless the device speaks PostScript or PDF, which
most desk lasers and inkjets do not. So the agent tries, in order:

1. `SumatraPDF.exe -print-to "<printer>" -silent` — shipped beside the binary,
   or found at a configured `helperPath`. `./fetch-helper.sh` downloads the
   pinned version and verifies its SHA-256; the binary is never committed.
   See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — it is GPLv3, which
   places real obligations on the installer.
2. The shell's `printto` verb, which works when a reader that registers it is
   installed (Acrobat and Foxit do; Edge does not).
3. Neither → answers `503 no_pdf_helper`, and Sally falls back to the browser
   dialog rather than reporting a failed print.

`/v1/ping` reports `canPrint` so Sally can tell the two states apart *before*
offering a choice: a machine with no helper still enumerates its printers
perfectly well, and a printer dropdown whose selection is then ignored is worse
than no dropdown at all.

> **Licence note.** SumatraPDF is GPLv3. Invoking it as a separate program is
> mere aggregation and does not affect Sally's licensing, but the installer
> that ships it must carry its licence text and a written offer for its source.
> Settle this before the first release build.

## Distribution

Binaries are published to the shared desktop-agent bucket and CloudFront
distribution defined in the monorepo's `infra/sst.config.ts`, under the `/print-agent/`
prefix — the same infrastructure the Sally Tally Connector uses under `/tally/`.
The stack outputs `PrintAgentWindowsUrl` and `PrintAgentMacUrl`; the web app
receives them as env vars.

The agent repos are private, so GitHub Releases can't serve customers directly:
CI builds and signs, then uploads here.

## Building

```bash
./fetch-helper.sh       # pinned SumatraPDF -> dist/windows/ (build.sh calls it)
./build.sh              # dev build
VERSION=1.2.0 ./build.sh
```

`dist/windows/` is what the Windows installer packages: the agent plus the PDF
helper it needs. Without the helper the agent still runs, reports
`canPrint:false`, and Sally stays on the browser print path.

Pure Go, zero dependencies, `CGO_ENABLED=0`, so one machine cross-compiles
Windows (amd64/arm64) and macOS (amd64/arm64, plus a universal binary when run
on a Mac). Output ~8 MB per target in `dist/`.

The absence of cgo is why the agent has a **status page instead of a tray
icon** — every tray library needs cgo, which would mean building each platform
on that platform. `http://127.0.0.1:17777/` shows status, the printer list, the
token and a Quit button, and is refused to web pages.

```bash
go test ./...   # security controls and the request path
go vet ./...
```

## Not done yet

The binaries build and run; **packaging and distribution do not exist**. Before
this can go on the website:

- **Code signing.** An Apple Developer ID plus notarisation, or macOS refuses
  to launch it. A Windows code-signing certificate, or endpoint security will
  flag a listening unsigned process.
- **Installers.** `.pkg`/`.dmg` for macOS, `.msi` for Windows, each registering
  start-at-login — a `Run` key or Startup entry on Windows (a *Service* is the
  wrong choice: session 0 has no user profile and cannot see per-user printer
  connections), a LaunchAgent with `RunAtLoad`/`KeepAlive` on macOS.
- **An update path**, or the agent rots. The protocol is small and versioned
  (`/v1`) specifically so an old agent keeps working. Follow the Tally
  connector's `latest.json` shape (version, root-relative url, sha256,
  minVersion, mandatory, releasedAt) so both agents update the same way.
- **A "Direct printing is off" hint** in the print dialog, linking to the
  installer. The URLs are already wired through as
  `NEXT_PUBLIC_PRINT_AGENT_WINDOWS_URL` / `..._MAC_URL`.
- **A real print on paper.** Everything up to the spooler is verified —
  enumeration, refusals, `canPrint` flipping true with the helper present — but
  no sheet has actually come out of a printer yet.
- **Running it on a Mac at all.** The darwin builds cross-compile; they have
  never been executed.

## Configuration

`config.json`, created on first run, `0600`:

- Windows — `%APPDATA%\SallyPrintAgent\config.json`
- macOS — `~/Library/Application Support/SallyPrintAgent/config.json`

```json
{
  "token": "…",
  "machineId": "…",
  "allowedOrigins": ["https://sallyerp.in", "http://localhost:3000"],
  "helperPath": ""
}
```

`machineId` is random, not a hardware identifier: Sally uses it only to key the
remembered printer per counter, and has no business fingerprinting the device.

The log sits beside it as `agent.log`, capped at 2 MB with one rotation.

## Flags

```
sally-print-agent            # bind the first free port of 17777–17780
sally-print-agent -port 9000 # bind a specific port (Sally will not find it)
sally-print-agent -version
```
