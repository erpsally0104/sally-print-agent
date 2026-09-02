package main

import (
	"html/template"
	"net/http"
	"runtime"
)

/*
The status page stands in for a tray icon.

A native tray needs cgo, and cgo costs the single-command cross-compile that
lets one machine build Windows and both macOS architectures. A page served by
the agent itself answers the same questions — is it running, what can it see,
how do I stop it — with no platform UI code at all, and it is also the one place
a support call can be pointed at.

It is rendered server-side rather than fetched by script so the page works with
no CORS involvement and shows the token without an extra endpoint that could be
reached from elsewhere.
*/

type statusView struct {
	Version        string
	Port           int
	Origin         string
	MachineID      string
	Token          string
	ConfigPath     string
	LogPath        string
	Platform       string
	Printers       []Printer
	CanPrint       bool
	Autostart      AutostartState
	AutostartStale bool
	CurrentExe     string
	PrinterErr     string
	CopiesNote     string
	Origins        []string
}

func (s *server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	// ServeMux's "/" matches everything; anything else is genuinely absent.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// A web page must not be able to read this — it carries the token.
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.selfOrigin() {
		writeJSONError(w, http.StatusForbidden, "not available to web pages")
		return
	}

	view := statusView{
		Version:    s.version,
		Port:       s.port,
		Origin:     s.selfOrigin(),
		MachineID:  s.cfg.MachineID,
		Token:      s.cfg.Token,
		ConfigPath: s.configPath,
		LogPath:    s.logPath,
		Platform:   runtime.GOOS + "/" + runtime.GOARCH,
		CanPrint:   s.canPrint(),
		CopiesNote: copiesNote(),
		Origins:    s.cfg.AllowedOrigins,
	}
	if auto, err := autostartState(); err == nil {
		view.Autostart = auto
		if exe, exeErr := currentExecutable(); exeErr == nil {
			view.CurrentExe = exe
			view.AutostartStale = auto.Stale(exe)
		}
	}
	if list, err := s.printers(); err != nil {
		view.PrinterErr = err.Error()
	} else {
		view.Printers = list
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := statusTemplate.Execute(w, view); err != nil {
		s.logf("rendering the status page failed: %v", err)
	}
}

// html/template escapes every interpolation, so a printer name containing
// markup cannot inject anything into this page.
var statusTemplate = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sally Print Agent</title>
<style>
  :root { color-scheme: light dark; --fg:#111827; --muted:#6b7280; --bg:#f9fafb; --card:#ffffff; --line:#e5e7eb; --ok:#047857; --warn:#b45309; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e5e7eb; --muted:#9ca3af; --bg:#0b0f19; --card:#111827; --line:#1f2937; --ok:#34d399; --warn:#fbbf24; }
  }
  * { box-sizing: border-box; }
  body { margin:0; padding:32px 20px; background:var(--bg); color:var(--fg);
         font:14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; }
  .wrap { max-width: 640px; margin: 0 auto; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:var(--muted); margin:0 0 24px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:18px 20px; margin-bottom:16px; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin:0 0 12px; font-weight:600; }
  dl { display:grid; grid-template-columns:auto 1fr; gap:6px 16px; margin:0; }
  dt { color:var(--muted); }
  dd { margin:0; word-break:break-all; font-variant-numeric:tabular-nums; }
  ul { margin:0; padding-left:18px; }
  li { margin:2px 0; }
  .tag { display:inline-block; font-size:11px; padding:1px 6px; border-radius:99px; background:var(--line); color:var(--muted); margin-left:6px; }
  .ok { color:var(--ok); font-weight:600; }
  .warn { color:var(--warn); }
  code { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }
  button { font:inherit; padding:8px 16px; border-radius:8px; border:1px solid var(--line);
           background:transparent; color:var(--fg); cursor:pointer; }
  button:hover { background:var(--line); }
  .note { color:var(--muted); font-size:12px; margin-top:10px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Sally Print Agent <span class="tag">v{{.Version}}</span></h1>
  <p class="sub"><span class="ok">Running</span> on {{.Origin}} &middot; {{.Platform}}</p>

  <div class="card">
    <h2>Printers</h2>
    {{if .PrinterErr}}
      <p class="warn">Could not read the printer list: {{.PrinterErr}}</p>
    {{else if .Printers}}
      <ul>
        {{range .Printers}}<li>{{.Name}}{{if .IsDefault}} <span class="tag">default</span>{{end}}</li>{{end}}
      </ul>
      {{if .CanPrint}}<p class="note">{{.CopiesNote}}</p>
      {{else}}<p class="warn">No PDF print helper is installed, so Sally will keep using your browser&rsquo;s print dialog. Reinstall the agent to add it.</p>{{end}}
    {{else}}
      <p class="warn">No printers are installed on this machine.</p>
    {{end}}
  </div>

  <div class="card">
    <h2>Allowed websites</h2>
    <ul>{{range .Origins}}<li><code>{{.}}</code></li>{{end}}</ul>
    <p class="note">Only these can see your printers or send a job. Everything else is refused.</p>
  </div>

  <div class="card">
    <h2>Details</h2>
    <dl>
      <dt>Machine ID</dt><dd><code>{{.MachineID}}</code></dd>
      <dt>Token</dt><dd><code>{{.Token}}</code></dd>
      <dt>Config</dt><dd><code>{{.ConfigPath}}</code></dd>
      <dt>Log</dt><dd><code>{{.LogPath}}</code></dd>
    </dl>
    <p class="note">Sally receives the token automatically. You never need to copy it &mdash; it is shown only for support.</p>
  </div>

  <div class="card">
    <h2>Start at login</h2>
    {{if .Autostart.Supported}}
      {{if .Autostart.Enabled}}
        <p><span class="ok">On</span> &mdash; the agent starts automatically when you sign in.</p>
        {{if .AutostartStale}}
          <p class="warn">But it is registered at a different location, so the copy that
          starts at login is not this one:</p>
          <dl>
            <dt>registered</dt><dd><code>{{.Autostart.RegisteredPath}}</code></dd>
            <dt>running</dt><dd><code>{{.CurrentExe}}</code></dd>
          </dl>
          <p class="note">Turn it off and on again here to register this copy.</p>
        {{end}}
        <button id="autostart" data-enable="false" type="button">Turn off</button>
      {{else}}
        <p><span class="warn">Off</span> &mdash; you will have to start the agent yourself
        after each restart, and printing falls back to your browser&rsquo;s print dialog
        until you do.</p>
        <button id="autostart" data-enable="true" type="button">Turn on</button>
      {{end}}
      <p class="note">Registered at <code>{{.Autostart.Location}}</code> for your user
      account only. No administrator rights needed, and nothing is installed
      machine-wide.</p>
    {{else}}
      <p class="note">Not supported on this platform.</p>
    {{end}}
  </div>

  <div class="card">
    <h2>Stop the agent</h2>
    <button id="quit" type="button">Quit</button>
    <p class="note">Printing falls back to your browser&rsquo;s print dialog until you start it again. It restarts at your next login.</p>
  </div>
</div>
<script>
  var auto = document.getElementById('autostart');
  if (auto) {
    auto.addEventListener('click', async function () {
      this.disabled = true;
      var enable = this.dataset.enable;
      try {
        var res = await fetch('/autostart?enable=' + enable, {
          method: 'POST', headers: { 'X-Sally-Local': '1' },
        });
        if (!res.ok) {
          var body = await res.json().catch(function () { return {}; });
          throw new Error(body.error || 'could not change the setting');
        }
        location.reload();
      } catch (e) {
        this.disabled = false;
        this.textContent = 'Failed \u2014 ' + e.message;
      }
    });
  }

  document.getElementById('quit').addEventListener('click', async function () {
    this.disabled = true;
    this.textContent = 'Stopping…';
    try {
      await fetch('/quit', { method: 'POST', headers: { 'X-Sally-Local': '1' } });
      document.querySelector('.sub').innerHTML = '<span class="warn">Stopped.</span> You can close this tab.';
    } catch (e) {
      // The socket closing before the reply lands is the expected outcome.
      document.querySelector('.sub').innerHTML = '<span class="warn">Stopped.</span> You can close this tab.';
    }
  });
</script>
</body>
</html>
`))
