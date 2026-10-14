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
//
// After a pile is stopped part-way (Stop this pile), the rest of the pile is
// usually still in the feeder. The hold (HoldUntilClear) keeps it from
// starting again by itself until the scanner has read idle with the feeder
// clear; a busy moment, a jam or an open door does not lift it. Scan now
// still scans during a hold.
//
// Manual requests carry ids (Sally's command ids, or "" for the status
// page) so the agent can report what became of each: fired on a pile
// (TakeFired), lapsed without paper (TakeLapsed) or cancelled by a pause
// (TakeCancelled).
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
	// Clear: the feeder is empty, or the scanner reports no feeder state.
	Clear bool
}

// Hold is why a loaded feeder is kept from starting by itself after a Stop.
type Hold int

const (
	HoldNone Hold = iota
	// HoldAfterStop: a pile was stopped from Sally.
	HoldAfterStop
	// HoldAfterStopOnPC: a pile was stopped on the PC's status page.
	HoldAfterStopOnPC
)

// maxManualIDs bounds the ids one waiting request collects.
const maxManualIDs = 20

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
	// manualIDs are the ids waiting on the manual request; fired, lapsed
	// and cancelled hold ids until the agent takes them.
	manualIDs []string
	fired     []string
	lapsed    []string
	cancelled []string
	// hold keeps auto-start off after a Stop until the feeder is clear.
	hold Hold
}

// New returns a machine ready to start on the first idle-loaded period.
func New() *Machine { return &Machine{armed: true} }

// Request records a SCAN_NOW or TEST_SCAN with its id ("" from the status
// page). It scans once, as soon as there is paper in an idle scanner, even
// while paused, with auto-start off or during a hold. Requests made while
// one waits join it, and the 2-minute window starts again; a request whose
// window had already passed is lapsed first.
func (m *Machine) Request(now time.Time, k Kind, id string) {
	m.expire(now)
	m.manual = k
	m.manualUntil = now.Add(manualWindow)
	m.manualIDs = append(m.manualIDs, id)
	if n := len(m.manualIDs) - maxManualIDs; n > 0 {
		m.lapsed = append(m.lapsed, m.manualIDs[:n]...)
		m.manualIDs = append([]string(nil), m.manualIDs[n:]...)
	}
}

// expire lapses a request whose window has passed.
func (m *Machine) expire(now time.Time) {
	if m.manual != None && !now.Before(m.manualUntil) {
		m.lapsed = append(m.lapsed, m.manualIDs...)
		m.manual, m.manualIDs = None, nil
	}
}

// TakeFired returns the ids of the requests that started the current pile.
func (m *Machine) TakeFired() []string {
	out := m.fired
	m.fired = nil
	return out
}

// TakeLapsed returns the ids of requests whose 2 minutes passed without
// paper, each once. It also lapses an expired request by itself, so the ids
// come back even while nothing is observed.
func (m *Machine) TakeLapsed(now time.Time) []string {
	m.expire(now)
	out := m.lapsed
	m.lapsed = nil
	return out
}

// Cancel drops the waiting request (a pause cancels a scan that has not
// started); its ids go to TakeCancelled.
func (m *Machine) Cancel() {
	m.cancelled = append(m.cancelled, m.manualIDs...)
	m.manual, m.manualIDs = None, nil
}

// TakeCancelled returns the ids Cancel dropped.
func (m *Machine) TakeCancelled() []string {
	out := m.cancelled
	m.cancelled = nil
	return out
}

// HoldUntilClear keeps auto-start off until the scanner reads idle with the
// feeder clear. Call it after Ended.
func (m *Machine) HoldUntilClear(h Hold) { m.hold = h }

// Held says why paper in the feeder will not start by itself:
// AFTER_STOP, AFTER_STOP_ON_PC, WHILE_PAUSED, or "".
func (m *Machine) Held() string {
	switch {
	case m.hold == HoldAfterStop:
		return "AFTER_STOP"
	case m.hold == HoldAfterStopOnPC:
		return "AFTER_STOP_ON_PC"
	case m.heldWhilePaused:
		return "WHILE_PAUSED"
	}
	return ""
}

// HoldKind is the current hold.
func (m *Machine) HoldKind() Hold { return m.hold }

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
	m.expire(now)

	idleLoaded := o.Reachable && o.Idle && o.Loaded
	if !idleLoaded {
		// Anything else (empty, jam, door open, busy, unreachable) ends the
		// period and lets the next one count; during a hold, only an idle
		// scanner with a clear feeder does.
		m.since = time.Time{}
		m.heldWhilePaused = false
		if m.hold == HoldNone {
			m.armed = true
		} else if o.Reachable && o.Idle && o.Clear {
			m.hold = HoldNone
			m.armed = true
		}
		return None
	}

	if m.manual != None {
		k := m.manual
		m.fired = append(m.fired, m.manualIDs...)
		m.manual, m.manualIDs = None, nil
		return k
	}
	if m.hold != HoldNone {
		return None
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
// something else has been seen. It clears a hold.
func (m *Machine) Ended() {
	m.running = false
	m.hold = HoldNone
	m.armed = false
	m.since = time.Time{}
	m.heldWhilePaused = false
}
