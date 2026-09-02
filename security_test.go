package main

import (
	"testing"
	"time"
)

/*
These cover the controls described at the top of security.go. They are the
tests that matter most in this program: the agent is reachable by every website
the user visits, so a regression here is a stranger's page spooling to a
customer's printer, not a cosmetic bug.
*/

func TestOriginAllowed(t *testing.T) {
	allowed := []string{"https://sallyerp.in", "http://localhost:3000"}

	cases := []struct {
		name   string
		origin string
		want   bool
	}{
		{"exact match", "https://sallyerp.in", true},
		{"scheme is compared, not ignored", "http://sallyerp.in", false},
		{"a different host is refused", "https://evil.example", false},
		{"a subdomain is not the same origin", "https://app.sallyerp.in", false},
		{"a lookalike suffix is refused", "https://notsallyerp.in", false},
		{"the port is part of the origin", "http://localhost:3001", false},
		{"case in the host does not matter", "https://SallyERP.in", true},
		{"an empty origin is not on the list", "", false},
		{"a trailing slash is not an origin", "https://sallyerp.in/", false},
		{"a path is not an origin", "https://sallyerp.in/print", false},
		{"the null origin is refused", "null", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := originAllowed(c.origin, allowed); got != c.want {
				t.Fatalf("originAllowed(%q) = %v, want %v", c.origin, got, c.want)
			}
		})
	}
}

func TestTokenMatches(t *testing.T) {
	if !tokenMatches("abc123", "abc123") {
		t.Fatal("an identical token should match")
	}
	if tokenMatches("abc123", "abc124") {
		t.Fatal("a different token must not match")
	}
	if tokenMatches("", "abc123") {
		t.Fatal("an empty token must not match")
	}
	// A prefix must not pass — the comparison is over the whole value.
	if tokenMatches("abc", "abc123") {
		t.Fatal("a prefix must not match")
	}
}

func TestRateLimiter(t *testing.T) {
	base := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	rl := newRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !rl.allow(base) {
			t.Fatalf("job %d should have been allowed", i+1)
		}
	}
	if rl.allow(base) {
		t.Fatal("the fourth job inside the window should be refused")
	}
	// Still inside the window a moment later.
	if rl.allow(base.Add(30 * time.Second)) {
		t.Fatal("the window has not passed yet")
	}
	// Once the window rolls past, capacity returns.
	if !rl.allow(base.Add(61 * time.Second)) {
		t.Fatal("capacity should return after the window")
	}
}

func TestResolvePrinterOnlyReturnsKnownNames(t *testing.T) {
	list := []Printer{
		{Name: "Office Laser", IsDefault: true},
		{Name: "Counter Thermal"},
	}

	t.Run("an empty name means the default", func(t *testing.T) {
		got, err := resolvePrinter("", list)
		if err != nil || got != "Office Laser" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("matching is case-insensitive but returns the OS spelling", func(t *testing.T) {
		got, err := resolvePrinter("counter thermal", list)
		if err != nil {
			t.Fatal(err)
		}
		// The caller's casing must never reach a command line.
		if got != "Counter Thermal" {
			t.Fatalf("got %q, want the enumerated spelling", got)
		}
	})

	t.Run("an unknown printer is refused", func(t *testing.T) {
		if _, err := resolvePrinter("Not Installed", list); err == nil {
			t.Fatal("expected an error for a printer that is not installed")
		}
	})

	t.Run("an injection attempt is refused, not sanitised", func(t *testing.T) {
		// The point of resolving against the enumerated list: anything the OS
		// did not name cannot get through, so quoting is not load-bearing.
		for _, attempt := range []string{
			`Office Laser" & calc.exe & "`,
			"Office Laser; rm -rf /",
			"$(reboot)",
			"Office Laser`whoami`",
		} {
			if _, err := resolvePrinter(attempt, list); err == nil {
				t.Fatalf("expected %q to be refused", attempt)
			}
		}
	})

	t.Run("no printers at all is an error, not a silent default", func(t *testing.T) {
		if _, err := resolvePrinter("", nil); err == nil {
			t.Fatal("expected an error when the machine has no printers")
		}
	})

	t.Run("falls back to the first printer when none is default", func(t *testing.T) {
		got, err := resolvePrinter("", []Printer{{Name: "Only One"}})
		if err != nil || got != "Only One" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}

func TestClampCopies(t *testing.T) {
	cases := map[int]int{0: 1, -5: 1, 1: 1, 7: 7, 20: 20, 21: maxCopies, 10000: maxCopies}
	for in, want := range cases {
		if got := clampCopies(in); got != want {
			t.Fatalf("clampCopies(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestLooksLikePDF(t *testing.T) {
	if !looksLikePDF([]byte("%PDF-1.7\n...")) {
		t.Fatal("a real PDF header should be accepted")
	}
	// A printer handed HTML or a script emits pages of garbage, so the sniff
	// runs before anything reaches the spooler.
	for _, bad := range [][]byte{
		[]byte("<html>"),
		[]byte("GIF89a"),
		[]byte("%PD"),
		{},
		nil,
	} {
		if looksLikePDF(bad) {
			t.Fatalf("%q should not be accepted as a PDF", string(bad))
		}
	}
}

func TestSanitiseJobName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"INV-2026-27-0001", "INV-2026-27-0001"},
		{"", "Sally document"},
		{"   ", "Sally document"},
		// Everything a shell or print queue could misread is dropped rather
		// than escaped, since the job title carries no meaning to the system.
		{"inv & calc.exe", "inv  calc.exe"},
		{"$(reboot)", "reboot"},
		{"a\"b'c;d|e", "abcde"},
		{"日本語", "Sally document"},
	}
	for _, c := range cases {
		if got := sanitiseJobName(c.in); got != c.want {
			t.Fatalf("sanitiseJobName(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	if got := sanitiseJobName(string(make([]byte, 0, 0)) + repeat("A", 200)); len(got) > 64 {
		t.Fatalf("a long job name should be truncated, got %d chars", len(got))
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
