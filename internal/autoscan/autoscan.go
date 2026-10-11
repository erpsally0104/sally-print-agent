// Package autoscan decides when a scan starts by itself.
//
// The rule: start when there is paper in the feeder and the scanner has been
// idle, continuously, for the PC's start delay (2, 3 or 5 s; 3 by default).
// It is driven only by (time, status) observations, so it is a pure state
// machine that tests can walk through second by second.
//
// It deliberately does not look for an empty→loaded edge. After a paper jam
// the feeder often never reports "empty": the person opens the door, takes
// the stuck sheet out, puts it back on top and closes the door. The machine
// must start again from "loaded and idle for 3 s" alone.
//
// What stops it looping: once a job ends, it will not start again until it
// has seen something other than "idle with paper in the feeder" (the feeder
// empty, a jam, an open door, the scanner busy or unreachable). A job that
// leaves paper in the tray (a misfeed the scanner gave up on) therefore waits
// for the person to touch the scanner instead of retrying every 3 seconds.
package autoscan

import "time"

// Kind says why a scan starts.
type Kind string

const (
	None     Kind = ""
	Auto     Kind = "AUTO"
	ScanNow  Kind = "SCAN_NOW"
	TestScan Kind = "TEST_SCAN"
)

// Observation is one poll of the scanner.
type Observation struct {
	// Reachable is false when the status could not be read.
	Reachable bool
	Idle      bool
	Loaded    bool
}

// Settings come from Sally on the heartbeat.
type Settings struct {
	AutoStart bool
	Delay     time.Duration
}

// DefaultDelay is the wait when Sally has not said otherwise.
const DefaultDelay = 3 * time.Second

// manualWindow is how long a SCAN_NOW or TEST_SCAN waits for paper. Someone
// who presses "Scan now" and then loads the paper should still get a scan.
const manualWindow = 2 * time.Minute

// Machine is the auto-start state. The zero value is not ready; use New.
type Machine struct {
	// armed: a new idle-loaded period may start a scan.
	armed bool
	// since: start of the current continuous idle-with-paper period.
	since time.Time
	// running: a job is in progress.
	running bool
	// manual request and its expiry.
	manual      Kind
	manualUntil time.Time
	// heldWhilePaused: paper sat in the feeder while starting was not
	// allowed. Shown on the status page as "paper put in while paused".
	heldWhilePaused bool
}

// New returns a machine ready to start on the first idle-loaded period.
func New() *Machine { return &Machine{armed: true} }

// Request records a SCAN_NOW or TEST_SCAN. It scans once, as soon as there is
// paper in an idle scanner, even while paused or with auto-start off.
func (m *Machine) Request(now time.Time, k Kind) {
	m.manual = k
	m.manualUntil = now.Add(manualWindow)
}

// Pending reports a manual request still waiting for paper.
func (m *Machine) Pending(now time.Time) Kind {
	if m.manual != None && now.Before(m.manualUntil) {
		return m.manual
	}
	return None
}

// HeldWhilePaused reports paper sitting in the feeder that will not be sent
// because starting is not allowed (paused or auto-start off).
func (m *Machine) HeldWhilePaused() bool { return m.heldWhilePaused }

// Running reports a job in progress.
func (m *Machine) Running() bool { return m.running }

// Observe feeds one status poll and says whether to start a scan now.
// paused is the PC's current pause state. When it returns a Kind, the caller
// must start the job and call Started (or Ended at once if the start failed).
func (m *Machine) Observe(now time.Time, o Observation, s Settings, paused bool) Kind {
	if m.running {
		return None
	}
	if m.manual != None && !now.Before(m.manualUntil) {
		m.manual = None
	}

	idleLoaded := o.Reachable && o.Idle && o.Loaded
	if !idleLoaded {
		// Anything else (empty, jam, door open, busy, unreachable) ends the
		// period and lets the next one count.
		m.since = time.Time{}
		m.armed = true
		m.heldWhilePaused = false
		return None
	}

	if m.manual != None {
		k := m.manual
		m.manual = None
		return k
	}

	if paused || !s.AutoStart {
		// Paper put in while starting is not allowed is not sent when that
		// changes: it needs the person to take it out or press Scan now.
		m.armed = false
		m.since = time.Time{}
		m.heldWhilePaused = true
		return None
	}

	if !m.armed {
		return None
	}
	if m.since.IsZero() {
		m.since = now
	}
	delay := s.Delay
	if delay <= 0 {
		delay = DefaultDelay
	}
	if now.Sub(m.since) >= delay {
		return Auto
	}
	return None
}

// Started records that a job began.
func (m *Machine) Started() {
	m.running = true
	m.since = time.Time{}
}

// Ended records that the job finished, failed or never began. Whatever the
// outcome, the next scan needs a new idle-loaded period that begins after
// something else has been seen.
func (m *Machine) Ended() {
	m.running = false
	m.armed = false
	m.since = time.Time{}
	m.heldWhilePaused = false
}
