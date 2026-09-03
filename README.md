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

## Installing

The release ships a zip, not an installer yet, so setup is two steps: extract
it somewhere permanent, then register it.

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
go test ./...   # security controls, the request path, autostart comparison
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
- **Installers** (`.msi` / `.pkg`). Start-at-login itself is done — the
  installer's remaining job is putting the files somewhere permanent and
  calling `-install`, rather than reimplementing it in a packaging script.
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
