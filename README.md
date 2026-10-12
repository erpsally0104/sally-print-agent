# Sally Desktop (the Sally Print Agent)

A small service users install on their own machine so Sally can print to a
**chosen printer** with no browser print dialog, and so a desk scanner can
send **signed copies** to Sally by itself. In Sally's screens it is called
**Sally Desktop** (printing and scanning). The binary, the installers, their
file names and the download URLs keep the `sally-print-agent` name, so
existing installs upgrade in place.

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

## Installing

Windows has an installer; macOS has one that has never been run on a Mac. Both
put the files somewhere permanent and register start-at-login, so there is
nothing to do afterwards.

| | |
| --- | --- |
| Windows | `sally-print-agent-windows.msi` — per-user, **no administrator prompt** |
| macOS | `sally-print-agent-macos.pkg` — installs to `/usr/local/bin`, asks for admin |

The Windows package installs to `%LOCALAPPDATA%\Programs\SallyPrintAgent`
deliberately. Autostart is an `HKCU` Run key, and a per-machine package runs
its actions elevated — `HKCU` there belongs to whoever typed the administrator
password, so the agent would start at login for them and never for the person
who installed it, with nothing reporting an error.

The zip is still published for anyone who would rather not run an installer.
Extract it somewhere permanent, then register it by hand:

```
sally-print-agent -install     # start at login, and start now
sally-print-agent -status      # is it registered? where?
sally-print-agent -uninstall   # stop starting at login
```

Or use the **Start at login** card on the status page, which does the same
thing and is what a user who unzipped the folder will actually find.

Registration is per-user and needs no administrator rights:

| | |
| --- | --- |
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| macOS | `~/Library/LaunchAgents/in.sallyerp.print-agent.plist` |

A Windows *Service* would look like the right answer and is not: services run
in session 0 with no user profile, where per-user printer connections are
invisible. The agent has to run as the person whose printers it enumerates.
The same reasoning rules out a machine-wide LaunchDaemon on macOS. launchd does
give macOS one thing Windows lacks — `KeepAlive`, so a crashed agent restarts
rather than staying dead until the next login.

**Extract before installing.** Registration records an absolute path, so
installing from `Downloads` and then moving the folder leaves the login item
pointing at a binary that is gone. `-status` and the status page both detect
that and say so, rather than letting you discover it at the next restart when
printing has quietly reverted to the browser dialog.

Since macOS Ventura the registration appears in System Settings → General →
Login Items, where the user can switch it off. That is theirs to do; Sally just
falls back to the browser print path.

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
| Scanner controls (`/scan/*`) are POST only, need the page's per-process random token (`X-Sally-CSRF`, embedded in the status page), the `X-Sally-Local` marker, a `Host` of `127.0.0.1:port` or `localhost:port`, and no `Origin` other than the page's own; no CORS headers | Any web page, Sally included, pausing, scanning, pairing or pointing the agent at another scanner; DNS rebinding |
| The watched folder is chosen only on the status page (`/scan/folder`, the same POST, page token, marker, Host and Origin rules) and must be an existing folder given in full; the heartbeat names only its last path element | Any web page pointing the agent at a folder to upload |
| `/status.json` (what the page polls) is GET only with the same Host, Origin and marker checks, no CORS, and counts only | Other sites reading scanner state |
| The status page itself refuses a foreign `Host` | DNS rebinding reading the print token or the page token |

**No web page can start a scan.** Scanning adds no endpoint a web page can
call: nothing under `/v1` changed, and the `/scan/*` controls answer only the
status page. A scan starts from the scanner's own feeder, from a command on
Sally's heartbeat (which only a signed-in person with `voucher.acknowledge`
can queue), or from the Scan now button on the status page.

**What the scanner's Sally token can do.** It is a device token with
capability `SCAN`, approved by one person for one company.

| It can | It cannot |
| --- | --- |
| announce stacks, upload scanned sides to presigned S3 URLs and confirm them | read invoices, parties, amounts or any other company data |
| read its own settings and commands, and report status on the heartbeat | call any Tally route (`/api/agent/companies`, `sync/*`, `reconcile`, …): they refuse a SCAN token |
| all of it for the one approved company only | act for any other company, or be used as a browser session |

Sally checks it on every call against the approver's `voucher.acknowledge`
in that company and the company's plan; it can be revoked from Sally
Settings at any time (the agent then shows "Connect to Sally"). On the PC it
is stored with DPAPI (`scan-token.dat`), never in `config.json`.

**The outbox at rest.** Pages waiting to go up are sealed with DPAPI in user
scope on Windows, so another Windows account or a copied disk cannot read
them; elsewhere they are `0600` files in a `0700` directory. Each side's
SHA-256 is recorded and checked before upload. Copies are deleted once Sally
confirms them, or after 7 days when "Keep a copy" is on.

Nothing is ever passed to a shell. Commands are executed with separated
arguments, and only a printer name the OS itself reported can reach one.

## Scanning

Sally Desktop watches one scanner, scans whatever is put in its feeder, keeps
every page safe on the PC, and sends the pages to Sally as one run per stack
(the wire contract is `erp-sally` `docs/signed-copies/p1-desktop-api.md`). The
code is in `internal/`:

| Package | Does |
| --- | --- |
| `internal/escl` | eSCL client (capabilities, status, scan job, pages); HTTP transport and a hand-written HTTP/1.1 stream transport |
| `internal/usbscan` | Windows: finds and opens the IPP-over-USB channel (stub elsewhere) |
| `internal/mdns` | a minimal mDNS browser for `_uscan._tcp` / `_uscans._tcp` |
| `internal/autoscan` | the pure state machine that decides when a scan starts |
| `internal/outbox` | the encrypted on-disk outbox, its manifests and the background uploader |
| `internal/sally` | pairing, heartbeat, stack calls and presigned S3 PUTs |
| `internal/secure` | DPAPI (Windows) for the device token and the pages |
| `internal/singleinstance` | the scanner lock: only one copy drives the scanner |
| `internal/sound` | the three sounds, generated in code, played through winmm |
| `internal/watchfolder` | the watched folder: polls a chosen folder and sends settled files through the outbox |
| `internal/desktop` | ties them together; the status page's Scanner card reads it |

**The scanner on USB (Windows).** Scanners such as the HP ScanJet Pro N4000
expose IPP-over-USB (class 7/1/4, driver `usbprint`) and nothing in WIA. The
agent asks SetupAPI for the device interface
`{f2f40381-f46d-4e51-bce7-62de6cf2d098}` and, because that found nothing on the
real machine, also reads the subkeys of
`HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{f2f40381-…}` (a subkey
`##?#USB#…` is the path `\\?\USB#…`; ones whose `#\Control` has `Linked = 1`
come first). It opens the path with overlapped I/O and speaks plain HTTP/1.1
over it with `Host: localhost:60000`. Every request goes out in one complete,
unbuffered write; stale bytes are drained before each request; every read has
a timeout (CancelIoEx on expiry). All of it through `package syscall`: no cgo,
no `golang.org/x/sys`.

**Network scanners** are found with an mDNS query for `_uscan._tcp.local` and
`_uscans._tcp.local` (TXT `rs` gives the eSCL path), or by an IP or
`host[:port]` typed on the status page. HTTPS scanners use self-signed
certificates, so certificate checking is switched off **for that scanner's
client only**: the client that talks to Sally always verifies.

**The scan.** One job per feeder load: A4, feeder, colour (RGB24), 300 dpi,
JPEG, with the `pwg:Version` the scanner reports (2.63 if it names none), and
duplex when its capabilities say so (`scan:AdfDuplexInputCaps`, or an
`scan:AdfOption` of `Duplex`). `BlankPageDetectionAndRemoval` is never sent
(the N4000 answers 409, and Sally needs the blank backs as markers). Pages
come from `NextDocument` until 404, in scan order: sheet 1 side 1, sheet 1
side 2, sheet 2 side 1… for a duplex scan; a one-sided scanner's every page
is side 1 of its own sheet. The stack's manifest records which it was. A
page is checked to start with `FF D8` and is otherwise **never decoded or
re-encoded**: scanners often end a JPEG a row short, which Go's decoder
rejects, and the bytes go to Sally exactly as the scanner made them.

**Starting by itself.** A scan starts when paper has been in an idle feeder,
continuously, for the start delay (2, 3 or 5 s from Sally; 3 by default). There
is no "empty → loaded" edge to wait for, so it also starts after a paper jam
is cleared. After any job it waits until it has seen the scanner in some other
state (feeder empty, jam, cover open, busy) before it can start again, so a
load the scanner refuses to feed does not loop. Nothing starts while paused or
while auto-start is off in Sally; paper put in then is not sent when that
changes (take it out and put it back, or press Scan now).

**A paper jam.** The job ends; the sides already received are kept and sent as
**their own stack**; the note says "Paper jam. Open the cover, take out the
stuck sheet and put it back on top of the stack. Sally kept the N sheets
already scanned and sets aside anything scanned twice." Once the scanner
reports the jam cleared and the rest is back in the feeder, the next stack
starts by itself. Sally's page fingerprints set aside a sheet scanned twice.

**The outbox.** Each side is written to disk the moment it arrives: sealed
with DPAPI (user scope) on Windows, a `0600` file in a `0700` directory
elsewhere, fsynced, then recorded in the stack's `manifest.json` (written
through a temp file, fsync and rename). Only when every side of the stack is
on disk does the page say **"Got 48 sheets. Safe on this PC."** and play the
rising chime. Uploads run in the background, three sides at a time, through
`/api/agent/scan/stacks…` and presigned S3 PUTs; they back off when offline
and resume after a restart from the manifests (Sally reports the sides it
already holds). After Sally confirms a side, the local copy is deleted, or
kept 7 days when "Keep a copy" is on (the default); a janitor removes kept
copies after 7 days. The outbox lives in `outbox/` beside `config.json`.

**The watched folder.** For scanners whose own software saves to a folder
(or anyone saving scans by hand), the status page has a **Watched folder**
card: type the folder's full path and press *Watch this folder* (*Clear*
stops). It is stored in `scan.json` with the other per-PC settings. The card
shows the folder, files waiting, files sent today and the last problem.

- The folder is polled every 2 s (no fsnotify: zero dependencies, and it
  works on network drives). A file is taken once its size **and** its
  modification time have stayed the same for 5 s, so a file still being
  written is never sent half done.
- Only PDFs and pictures are taken: `pdf`, `jpg`, `jpeg`, `png`, `tif`,
  `tiff`, and only when the first bytes agree. Temporary and partial files
  (`~$*`, `*.tmp`, `*.part`, `.*`), empty files and everything else are left
  where they are; a file over 100 MB is left there with a note.
- A file directly in the folder is one stack. A sub-folder dropped in is one
  stack for all of its files (up to 500), sent once every file in it has
  settled. The `Sent to Sally` folder itself is never looked into.
- Taking a stack: its files are first copied into the **same outbox** as
  scanned pages (sealed, fsynced, hashed: "safe on this PC" the same way, and
  sent with the same device token and uploader), then a journal
  (`watchfolder.json`, written atomically) records the stack and each file's
  path, size and time, and only then are the files moved into
  `<folder>/Sent to Sally/<date>/` (a dropped folder into a sub-folder of its
  own name there). A name already there gets ` (2)`, ` (3)`…; nothing is
  ever overwritten. Files that are not sent stay in the dropped folder.
- Restarts: pending moves in the journal are finished on start (a file whose
  size or time changed since is a new file and is taken as one). A file
  found in the folder whose bytes an outbox folder stack already holds (the
  agent stopped after copying, before journaling) is moved, not sent again.
  A move Windows refuses because the scanner's software still holds the file
  is tried again on the next poll; the file is never sent twice meanwhile.
- On the wire a folder stack is announced with `kind: "FOLDER"`, its file
  count and `fileName` or `folderName` instead of sheets and sides, and its
  files go up with their names and types (`…/upload-url` with `files`, then
  `…/files`). Sally files it as a run with source `FOLDER`,
  `sourceDetail.door` `WATCHED_FOLDER`, and pairs backs with fronts by its
  own guess, never by a declared sheet. Pausing the scanner does not pause
  the folder.

**Sounds.** A tick when a scan starts, a rising chime when a stack is safe, a
low falling tone on a problem (again after 30 s if a jam is still there).
Generated in code as small WAVs and played with winmm `PlaySoundW`
(`SND_MEMORY|SND_ASYNC`), `MessageBeep` as a fallback; silent on other
systems. Sounds can be switched off on the status page.

**Connecting to Sally.** "Connect to Sally" on the status page runs the device
grant with capability `SCAN`: it opens `/connect?code=…` in the browser and
shows the code; the person approves one company in Sally. The token is stored
with DPAPI in `scan-token.dat`. A `401` drops it and shows "Connect to Sally"
again (pages stay in the outbox); a `403` keeps it, keeps scanning into the
outbox and shows why. Sally's address is `https://sallyerp.in` unless
`sallyBaseUrl` in `config.json`, `SALLY_BASE_URL` or `-sally-url` says
otherwise (plain http only to localhost).

**Heartbeat and commands.** About every 10 s (Sally's `heartbeatSec`), and at
once after a stack: scanner kind, name and state, feeder loaded, pause, outbox
counts, version. Never page content. The answer carries the PC's settings and
single-shot commands: `SCAN_NOW` and `TEST_SCAN` scan once as soon as paper is
in an idle feeder (within two minutes), even while paused; `PAUSE` (15, 60 or
until resumed) and `RESUME`. Unknown kinds are ignored. A `TEST_SCAN` is an
ordinary stack, uploaded like any other: the Setup wizard's "try one copy"
watches for the next run from this PC.

**Pause** from the status page or from Sally: 15 minutes, 1 hour, or until
resumed. It survives a restart.

**One copy scans.** Printing copes with a second copy (it binds the next port).
Scanning cannot share a feeder, so only the copy holding the scanner lock (a
named mutex on Windows, a `flock` elsewhere) watches the scanner, sends the
outbox and sends heartbeats. A second copy only prints and says so on its
status page.

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
on that platform. `http://127.0.0.1:17777/` ("Sally Desktop: printing and
scanning") shows status, the printer list, the token, the Scanner card and a
Quit button, and is refused to web pages.

```bash
go test ./...   # security controls, the request path, autostart comparison,
                # and scanning: eSCL settings and status, chunked reads and the
                # drain over a fake USB handle, the auto-start state machine
                # (jam included), mDNS packets, the outbox, pairing, heartbeat
                # commands and the stack upload against fake Sally + S3, and
                # the watched folder (settling, moves, restarts, folder drops)
go vet ./...
```

Registering at login is not unit-tested: it writes to the real registry or the
real `LaunchAgents` directory, and a test that mutates the developer's login
items is worse than no test. Verify it by hand instead:

```
sally-print-agent -install     # then check the Run key / plist exists
sally-print-agent -status      # should report yes, with this binary's path
cp agent.exe elsewhere/        # run the copy: -status should flag the mismatch
sally-print-agent -uninstall   # then check the key / plist is gone
```

## Release secrets

Set these on the repository (Settings → Secrets and variables → Actions).
Values come from the SST stack outputs — `npx sst outputs --stage production`
in the monorepo, or the tail of a deploy log.

| Secret | Value |
| --- | --- |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Scoped CI user — policy below |
| `AWS_REGION` | `ap-south-1` |
| `DOWNLOADS_BUCKET` | SST output `TallyDownloadsBucket` (one bucket serves both agents) |
| `DOWNLOADS_DISTRIBUTION_ID` | SST output `TallyDownloadsDistributionId` |
| `ES_USERNAME` / `ES_PASSWORD` / `ES_CREDENTIAL_ID` / `ES_TOTP_SECRET` *(optional)* | SSL.com eSigner account, signing credential ID, and the TOTP secret that lets CI sign unattended — see [Windows code signing](#windows-code-signing) |
| `MACOS_CERT_P12` / `MACOS_CERT_PASSWORD` / `MACOS_SIGN_IDENTITY` *(optional)* | Developer ID signing |
| `APPLE_ID` / `APPLE_TEAM_ID` / `APPLE_APP_PASSWORD` *(optional)* | notarisation |
| `MIN_AGENT_VERSION` *(optional)* | forced-update floor written into `latest.json` |

Every optional one is gated in the workflow, so a bare tag still builds:
without the AWS secrets the S3 publish is skipped, and without the certificates
the build ships **unsigned** with a warning.

### Windows code signing

The Windows binaries and both MSIs are signed through **SSL.com eSigner**, a
cloud HSM, not from a `.pfx` held in a secret.

That is not a preference. Since **1 June 2023** the CA/Browser Forum baseline
requirements oblige every publicly trusted code-signing private key — OV as
much as EV — to be generated on, and non-exportable from, FIPS 140-2 Level 2
hardware. No CA issues a downloadable certificate any more, so a `CERT_PFX`
secret is not a thing that can be provisioned; the key stays in SSL.com's HSM
and CI sends it a digest.

Azure Artifact Signing (formerly Trusted Signing) is cheaper at $9.99/month and
authenticates over OIDC with no long-lived secret at all. It is **not an option
for us**: public-trust certificates are issued only to entities in the US,
Canada, the EU, the UK, Australia, New Zealand, Japan, South Korea, Singapore,
Switzerland, Norway and Israel. Sally ERP is an Indian entity. Revisit this only
if that list grows or the signing entity changes.

Certificates now expire in **458 days** or less, so the renewal is roughly
annual and the credential ID changes with it.

### This repo needs its OWN AWS user

Do **not** reuse the Tally connector's keys. Its policy is scoped to
`sally-tally-downloads-production/tally/*`, so uploads to `/print-agent/*`
would be denied — and sharing one key would let either agent's CI overwrite the
other's published installer.

**Create it in account `095453158319`, and pass `--profile erp-sally` to every
command below.** There are two AWS accounts within reach of a normal laptop
here, and only one of them owns any of this:

| Account | Profile | Identity | Owns |
| --- | --- | --- | --- |
| `095453158319` | `erp-sally` | `sally-deployer` | the bucket, the distribution — **this is the one** |
| `405062306899` | `default` | `tally-admin` | something else entirely |

`default` being the wrong one is the trap: omit `--profile` and every command
below still succeeds, just in an account with no bucket and no distribution.
That already happened once — a `sally-print-agent-ci` was created in
`405062306899`, and the release published nothing until the mistake was found.
Confirm with `aws sts get-caller-identity --profile erp-sally` before starting.

The `sally-deployer` user carries AdministratorAccess, so it can create this
user directly (the Tally connector's README says otherwise; that is stale):

```bash
aws iam create-user --user-name sally-print-agent-ci --profile erp-sally
aws iam put-user-policy --user-name sally-print-agent-ci --profile erp-sally \
  --policy-name publish-print-agent --policy-document file://ci-policy.json
aws iam create-access-key --user-name sally-print-agent-ci --profile erp-sally
```

Feed that key straight into the repo secrets — a trailing newline is enough to
make CI fail with `The security token included in the request is invalid`,
which reads like a permissions problem and is not one:

```bash
printf '%s' 'AKIA…'          | gh secret set AWS_ACCESS_KEY_ID
printf '%s' '<secret>'       | gh secret set AWS_SECRET_ACCESS_KEY
printf '%s' 'ap-south-1'     | gh secret set AWS_REGION
```

To check the policy without waiting for a release, ask IAM directly rather
than reading it back:

```bash
aws iam simulate-principal-policy --profile erp-sally \
  --policy-source-arn arn:aws:iam::095453158319:user/sally-print-agent-ci \
  --action-names s3:PutObject \
  --resource-arns arn:aws:s3:::sally-tally-downloads-production/print-agent/latest.json
```

`ci-policy.json`, with this account's real values already filled in:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "PublishBinaries", "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::sally-tally-downloads-production/print-agent/*" },
    { "Sid": "ListForSync", "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::sally-tally-downloads-production" },
    { "Sid": "InvalidateCdn", "Effect": "Allow",
      "Action": ["cloudfront:CreateInvalidation"],
      "Resource": "arn:aws:cloudfront::095453158319:distribution/E7WTFB0QOX8J4" }
  ]
}
```

The `print-agent/*` prefix is the whole point: this user can publish the print
agent and nothing else in the bucket.

(Hardening upgrade, same as the connector's: swap the static user for a GitHub
OIDC role once an OIDC provider exists in the account.)

## Not done yet

The installers build and the release publishes them. What is left:

- **Scanning on real hardware.** The USB path (SetupAPI, the DeviceClasses
  registry, overlapped I/O, DPAPI, PlaySoundW) cross-compiles and vets, but has
  not run against the HP N4000 in this form. Check first: that the registry
  path is found and opened, that a status poll answers within a second, that
  the drain does not eat the start of a reply, and that a 50-sheet duplex
  stack arrives as 100 sides in order.

- **Certificates.** The signing steps are written and gated on secrets, so
  every release still builds without them — and ships **unsigned**. Windows
  needs an SSL.com eSigner credential (`ES_*`); macOS needs an Apple
  Developer ID Application certificate to sign the binary, a Developer ID
  *Installer* certificate to sign the pkg, and an app-specific password to
  notarise. Until then macOS refuses to launch the agent at all, and Windows
  endpoint security flags a listening unsigned process.
- **An update path**, or the agent rots. The protocol is small and versioned
  (`/v1`) specifically so an old agent keeps working. `latest.json` is already
  published in the Tally connector's shape and now carries `zipUrl` beside
  `url`, because an updater replacing a binary in place wants the
  extract-and-run build rather than an installer that would prompt.
- **A "Direct printing is off" hint** in the print dialog, linking to the
  installer. The URLs are already wired through as
  `NEXT_PUBLIC_PRINT_AGENT_WINDOWS_URL` / `..._MAC_URL` — note these now point
  at `.msi` / `.pkg`; the `.zip` aliases are still published beside them.
- **A real print on paper.** The path is verified as far as the Windows
  spooler: a job submitted through `/v1/print` was accepted, rendered to one
  page, and queued on a real printer. No sheet has come out of one yet.
- **Running it on a Mac at all.** The darwin builds cross-compile and the pkg
  assembles, but neither has ever been executed. The pkg scripts in
  particular — dropping to the console user via `launchctl asuser` — have
  never run anywhere.

## Configuration

`config.json`, created on first run, `0600`:

- Windows — `%APPDATA%\SallyPrintAgent\config.json`
- macOS — `~/Library/Application Support/SallyPrintAgent/config.json`

```json
{
  "token": "…",
  "machineId": "…",
  "allowedOrigins": ["https://sallyerp.in", "http://localhost:3000"],
  "helperPath": "",
  "sallyBaseUrl": "https://sallyerp.in"
}
```

Beside it: `scan.json` (the paired company, pause, sounds, keep-a-copy, a typed
scanner address, the watched folder, Sally's last settings; nothing secret),
`watchfolder.json` (the watched folder's journal of moves and today's count), `scan-token.dat` (the
Sally device token, DPAPI on Windows) and `outbox/` (pages waiting to go up).

`machineId` is random, not a hardware identifier: Sally uses it only to key the
remembered printer per counter, and has no business fingerprinting the device.

The log sits beside it as `agent.log`, capped at 2 MB with one rotation.

## Flags

```
sally-print-agent            # bind the first free port of 17777–17780
sally-print-agent -port 9000 # bind a specific port (Sally will not find it)
sally-print-agent -version
sally-print-agent -sally-url http://localhost:3000   # scanning against a dev Sally
sally-print-agent -scan=false                        # print only
```
