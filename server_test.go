package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer builds a server with the OS calls stubbed, so these exercise the
// request path — where the security controls live — and never a real printer.
func newTestServer(t *testing.T, printers []Printer, printErr error) (*server, *[]string) {
	t.Helper()

	var printed []string
	cfg := &Config{
		Token:          "test-token",
		MachineID:      "test-machine",
		AllowedOrigins: []string{"https://sallyerp.in"},
	}
	s := newServer(cfg, "test", log.New(io.Discard, "", 0))
	s.port = 17777
	s.listPrinters = func() ([]Printer, error) { return printers, nil }
	// Whether the machine can spool at all is a platform question; pin it here
	// so these tests behave the same on a box with no PDF helper installed.
	s.canPrintFn = func(*Config) bool { return true }
	s.printPDF = func(_ *Config, _, printer, jobName string, copies int) error {
		if printErr != nil {
			return printErr
		}
		printed = append(printed, printer)
		return nil
	}
	return s, &printed
}

func pdfBody() *bytes.Reader { return bytes.NewReader([]byte("%PDF-1.7\nhello")) }

func TestPingGivesTheTokenOnlyToAllowedOrigins(t *testing.T) {
	s, _ := newTestServer(t, nil, nil)

	t.Run("Sally gets the token, so pairing needs no user action", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
		req.Header.Set("Origin", "https://sallyerp.in")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var body map[string]any
		json.Unmarshal(rec.Body.Bytes(), &body)
		if body["token"] != "test-token" {
			t.Fatalf("expected the token, got %v", body["token"])
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "https://sallyerp.in" {
			t.Fatal("the response must be readable by Sally")
		}
	})

	t.Run("says whether the machine can actually spool a PDF", func(t *testing.T) {
		// Sally hides its printer picker on false: a machine can list printers
		// and still have no way to send a PDF to one (Windows without a helper),
		// and a dropdown that is silently ignored is worse than none.
		s.canPrintFn = func(*Config) bool { return false }
		defer func() { s.canPrintFn = func(*Config) bool { return true } }()

		req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
		req.Header.Set("Origin", "https://sallyerp.in")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		var body map[string]any
		json.Unmarshal(rec.Body.Bytes(), &body)
		if body["canPrint"] != false {
			t.Fatalf("canPrint = %v, want false", body["canPrint"])
		}
	})

	t.Run("a foreign origin is refused outright", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rec.Code)
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("test-token")) {
			t.Fatal("the token must never appear in a refused response")
		}
	})

	t.Run("a non-browser caller sees liveness but not the token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil) // no Origin
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var body map[string]any
		json.Unmarshal(rec.Body.Bytes(), &body)
		if _, ok := body["token"]; ok {
			t.Fatal("a caller with no origin must not receive the token")
		}
	})
}

func TestPreflightAnswersPrivateNetworkAccess(t *testing.T) {
	s, _ := newTestServer(t, nil, nil)

	// Chrome preflights a public page's request to loopback and drops the real
	// request unless this header comes back. Without it, printing silently
	// never happens — the failure mode that is hardest to diagnose in the field.
	req := httptest.NewRequest(http.MethodOptions, "/v1/print", nil)
	req.Header.Set("Origin", "https://sallyerp.in")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Private-Network", "true")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Private-Network") != "true" {
		t.Fatal("the private-network preflight was not granted")
	}
}

func TestPrivilegedEndpointsRequireTheToken(t *testing.T) {
	s, _ := newTestServer(t, []Printer{{Name: "Office Laser", IsDefault: true}}, nil)

	for _, path := range []string{"/v1/printers", "/v1/print"} {
		t.Run(path+" without a token", func(t *testing.T) {
			method := http.MethodGet
			var body io.Reader
			if path == "/v1/print" {
				method, body = http.MethodPost, pdfBody()
			}
			req := httptest.NewRequest(method, path, body)
			req.Header.Set("Origin", "https://sallyerp.in")
			req.Header.Set("Content-Type", "application/pdf")
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", rec.Code)
			}
		})
	}
}

func TestPrint(t *testing.T) {
	t.Run("prints to the named printer", func(t *testing.T) {
		s, printed := newTestServer(t, []Printer{
			{Name: "Office Laser", IsDefault: true},
			{Name: "Counter Thermal"},
		}, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/print?printer=Counter+Thermal&copies=2&job=INV-0001", pdfBody())
		req.Header.Set("Origin", "https://sallyerp.in")
		req.Header.Set("Content-Type", "application/pdf")
		req.Header.Set(tokenHeader, "test-token")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		if len(*printed) != 1 || (*printed)[0] != "Counter Thermal" {
			t.Fatalf("printed to %v", *printed)
		}
	})

	t.Run("a printer that is not installed is refused", func(t *testing.T) {
		s, printed := newTestServer(t, []Printer{{Name: "Office Laser", IsDefault: true}}, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/print?printer=Someone+Elses+Printer", pdfBody())
		req.Header.Set("Origin", "https://sallyerp.in")
		req.Header.Set("Content-Type", "application/pdf")
		req.Header.Set(tokenHeader, "test-token")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", rec.Code)
		}
		if len(*printed) != 0 {
			t.Fatal("nothing should have been spooled")
		}
	})

	t.Run("a body that is not a PDF never reaches the spooler", func(t *testing.T) {
		s, printed := newTestServer(t, []Printer{{Name: "Office Laser", IsDefault: true}}, nil)

		req := httptest.NewRequest(http.MethodPost, "/v1/print", bytes.NewReader([]byte("<html>lots of pages</html>")))
		req.Header.Set("Origin", "https://sallyerp.in")
		req.Header.Set("Content-Type", "application/pdf")
		req.Header.Set(tokenHeader, "test-token")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", rec.Code)
		}
		if len(*printed) != 0 {
			t.Fatal("nothing should have been spooled")
		}
	})

	t.Run("the wrong content type is refused, which is what forces a preflight", func(t *testing.T) {
		s, _ := newTestServer(t, []Printer{{Name: "Office Laser", IsDefault: true}}, nil)

		// text/plain is CORS-safelisted, so a hostile page could send it with
		// no preflight. Refusing it here is why that attack cannot print.
		req := httptest.NewRequest(http.MethodPost, "/v1/print", pdfBody())
		req.Header.Set("Origin", "https://sallyerp.in")
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set(tokenHeader, "test-token")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status %d, want 415", rec.Code)
		}
	})

	t.Run("a missing PDF helper asks Sally to fall back rather than failing", func(t *testing.T) {
		s, _ := newTestServer(t, []Printer{{Name: "Office Laser", IsDefault: true}}, errNoPdfHelper)

		req := httptest.NewRequest(http.MethodPost, "/v1/print", pdfBody())
		req.Header.Set("Origin", "https://sallyerp.in")
		req.Header.Set("Content-Type", "application/pdf")
		req.Header.Set(tokenHeader, "test-token")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", rec.Code)
		}
		var body map[string]any
		json.Unmarshal(rec.Body.Bytes(), &body)
		if body["code"] != "no_pdf_helper" {
			t.Fatalf("expected the fallback code, got %v", body["code"])
		}
	})
}

func TestStatusPageIsNotReadableByWebPages(t *testing.T) {
	s, _ := newTestServer(t, []Printer{{Name: "Office Laser", IsDefault: true}}, nil)

	// The page renders the token, so even an allowlisted origin must not read it.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://sallyerp.in")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("test-token")) {
		t.Fatal("the token leaked to a web page")
	}
}

func TestQuitIsNotReachableFromAWebPage(t *testing.T) {
	s, _ := newTestServer(t, nil, nil)
	stopped := false
	s.stop = func() { stopped = true }

	t.Run("an allowlisted site cannot stop the agent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/quit", nil)
		req.Header.Set("Origin", "https://sallyerp.in")
		req.Header.Set(localHeader, "1")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rec.Code)
		}
		if stopped {
			t.Fatal("a web page must not be able to stop the agent")
		}
	})

	t.Run("the local marker is required", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/quit", nil)
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rec.Code)
		}
	})
}

func TestAutostartCannotBeChangedByAWebPage(t *testing.T) {
	s, _ := newTestServer(t, nil, nil)

	// Registering a background process that launches at login is exactly the
	// kind of thing a hostile page would want. requireLocalPage refuses before
	// the handler runs, so nothing touches the registry or LaunchAgents here.
	for _, origin := range []string{"https://sallyerp.in", "https://evil.example"} {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/autostart?enable=true", nil)
			req.Header.Set("Origin", origin)
			req.Header.Set(localHeader, "1")
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403 - a web page must not register a login item", rec.Code)
			}
		})
	}

	t.Run("and not without the local marker either", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/autostart?enable=true", nil)
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rec.Code)
		}
	})
}

func TestPrinterListIsCached(t *testing.T) {
	s, _ := newTestServer(t, nil, nil)
	calls := 0
	s.listPrinters = func() ([]Printer, error) {
		calls++
		return []Printer{{Name: "Office Laser", IsDefault: true}}, nil
	}

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/printers", nil)
		req.Header.Set("Origin", "https://sallyerp.in")
		req.Header.Set(tokenHeader, "test-token")
		s.routes().ServeHTTP(httptest.NewRecorder(), req)
	}
	// Enumeration shells out to the OS; the dialog asks every time it opens.
	if calls != 1 {
		t.Fatalf("enumerated %d times, want 1", calls)
	}
}
