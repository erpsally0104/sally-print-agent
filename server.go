package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// server holds everything the handlers need. There is one per process.
type server struct {
	cfg     *Config
	version string
	port    int
	cache   *printerCache
	limiter *rateLimiter
	logger  *log.Logger
	started time.Time

	// Shown on the status page so a support call can ask for one file path.
	configPath string
	logPath    string

	// stop ends the process cleanly; wired by main so the status page's Quit
	// button doesn't have to kill anything abruptly.
	stop func()

	// The two OS calls, injected so the handlers — where the security controls
	// live — can be tested without a real printer attached.
	listPrinters func() ([]Printer, error)
	printPDF     func(cfg *Config, path, printer, jobName string, copies int) error
	canPrintFn   func(cfg *Config) bool
}

func newServer(cfg *Config, version string, logger *log.Logger) *server {
	return &server{
		cfg:     cfg,
		version: version,
		cache:   newPrinterCache(30 * time.Second),
		// Thirty jobs a minute is far above real counter use and far below
		// what a runaway retry loop would cost in paper.
		limiter: newRateLimiter(30, time.Minute),
		logger:  logger,
		started: time.Now(),

		listPrinters: listPrintersOS,
		printPDF:     printPDFOS,
		canPrintFn:   canPrintOS,
	}
}

func (s *server) logf(format string, args ...any) {
	s.logger.Printf(format, args...)
}

func (s *server) selfOrigin() string {
	return fmt.Sprintf("http://127.0.0.1:%d", s.port)
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// The status page and its Quit button: local only, never a web page.
	mux.HandleFunc("/", s.handleStatusPage)
	mux.HandleFunc("/quit", s.requireLocalPage(s.handleQuit))

	// The API Sally talks to. Every one of these is behind the origin
	// allowlist; the last two additionally require the token.
	mux.HandleFunc("/v1/ping", s.corsMiddleware(s.handlePing))
	mux.HandleFunc("/v1/printers", s.corsMiddleware(s.requireToken(s.handlePrinters)))
	mux.HandleFunc("/v1/print", s.corsMiddleware(s.requireToken(s.handlePrint)))

	return mux
}

// handlePing is the detection endpoint. It is deliberately cheap: Sally probes
// it on page load with a short timeout, and a slow answer would delay a print.
//
// It also delivers the token, which is what makes pairing invisible to the
// user: only an allowlisted origin gets a response it can read, so only Sally
// ever learns the token, and it learns it without anyone copying anything.
func (s *server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	body := map[string]any{
		"name":      "sally-print-agent",
		"version":   s.version,
		"machineId": s.cfg.MachineID,
		"port":      s.port,
		"uptimeSec": int(time.Since(s.started).Seconds()),
		// Sally hides its printer picker when this is false: the agent can list
		// printers on a machine that cannot spool to them, and offering a choice
		// that is then ignored is worse than offering none.
		"canPrint": s.canPrint(),
	}
	// No Origin means a non-browser caller (curl, another local process). It
	// gets to see that the agent is alive, but never the token.
	if originAllowed(r.Header.Get("Origin"), s.cfg.AllowedOrigins) {
		body["token"] = s.cfg.Token
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *server) handlePrinters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	list, err := s.printers()
	if err != nil {
		s.logf("printer enumeration failed: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "could not list printers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"printers": list})
}

func (s *server) canPrint() bool { return s.canPrintFn(s.cfg) }

func (s *server) printers() ([]Printer, error) {
	return s.cache.get(time.Now(), s.listPrinters)
}

// handlePrint spools one PDF.
//
// Query: printer (optional — empty means the default), copies, job.
// Body:  the PDF itself, Content-Type: application/pdf.
//
// The Content-Type requirement is not pedantry: it is not a CORS-safelisted
// value, so the browser must preflight, and the preflight is where a hostile
// origin is turned away. A "simple" POST would already have printed.
func (s *server) handlePrint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/pdf" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "send the PDF with Content-Type: application/pdf")
		return
	}
	if !s.limiter.allow(time.Now()) {
		writeJSONError(w, http.StatusTooManyRequests, "too many print jobs — slow down")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "the PDF is too large to print")
		return
	}
	if !looksLikePDF(body) {
		writeJSONError(w, http.StatusBadRequest, "that is not a PDF")
		return
	}

	q := r.URL.Query()
	copies := clampCopies(atoiOr(q.Get("copies"), 1))
	jobName := sanitiseJobName(q.Get("job"))

	list, err := s.printers()
	if err != nil {
		s.logf("printer enumeration failed: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "could not list printers")
		return
	}
	// Only a name the OS itself gave us ever reaches a command line.
	printer, err := resolvePrinter(q.Get("printer"), list)
	if err != nil {
		s.cache.invalidate() // the queue may have been removed since we cached
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	path, err := writeTempPDF(body)
	if err != nil {
		s.logf("spooling to a temp file failed: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "could not prepare the document")
		return
	}
	defer os.Remove(path)

	if err := s.printPDF(s.cfg, path, printer, jobName, copies); err != nil {
		if isNoHelper(err) {
			// Distinct status and code so Sally can fall back to the browser's
			// print dialog instead of telling the user printing failed.
			s.logf("no PDF print helper installed; asking Sally to fall back")
			writeJSONCode(w, http.StatusServiceUnavailable, "no_pdf_helper",
				"this machine has no PDF print helper installed")
			return
		}
		s.logf("printing to %q failed: %v", printer, err)
		writeJSONError(w, http.StatusInternalServerError, "the printer rejected the job")
		return
	}

	s.logf("printed %q to %q (%d cop%s)", jobName, printer, copies, plural(copies))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"printer": printer,
		"copies":  copies,
	})
}

func (s *server) handleQuit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	s.logf("quit requested from the status page")
	// Let the response flush before the process goes away.
	go func() {
		time.Sleep(150 * time.Millisecond)
		s.stop()
	}()
}

// ── small helpers ──────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// The agent's replies are never a page and never cacheable.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSONCode(w, status, "", message)
}

func writeJSONCode(w http.ResponseWriter, status int, code, message string) {
	body := map[string]any{"error": message}
	if code != "" {
		body["code"] = code
	}
	writeJSON(w, status, body)
}

func atoiOr(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
