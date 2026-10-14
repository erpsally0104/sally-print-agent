package desktop

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/sally"
)

/*
Command results and status-page actions, reported on the heartbeat
(erp-sally docs/signed-copies/p1-desktop-api.md, "D1-D3").

Every command Sally hands over gets a result: WAITING_FOR_PAPER, SCANNING,
STOPPING, then a final one (DONE, STOPPED, NO_PAPER, NOTHING_TO_STOP,
FAILED). Each change is resent until a check-in answers 2xx; an entry is
dropped once it is final and delivered. Everything here is guarded by
Agent.mu and lives in memory only.
*/

// desktopFeatures is what this agent tells Sally it supports, on every
// check-in. It is Sally's only version gate, so it is never derived from
// the version string.
var desktopFeatures = []string{"COMMAND_RESULTS", "STOP", "SCANNERS"}

// Results.
const (
	resWaitingForPaper = "WAITING_FOR_PAPER"
	resScanning        = "SCANNING"
	resStopping        = "STOPPING"
	resDone            = "DONE"
	resStopped         = "STOPPED"
	resNoPaper         = "NO_PAPER"
	resNothingToStop   = "NOTHING_TO_STOP"
	resFailed          = "FAILED"
)

// rank orders results: a result never goes back, and a final one never
// changes.
func rank(result string) int {
	switch result {
	case resWaitingForPaper, resStopping:
		return 1
	case resScanning:
		return 2
	case resDone, resStopped, resNoPaper, resNothingToStop, resFailed:
		return 3
	}
	return 0
}

const (
	maxTracked      = 32
	maxSentResults  = 20
	maxLocalActions = 10
	maxMessage      = 200
)

type tracked struct {
	r       sally.CommandResult
	seq     uint64 // bumped on each change
	sentSeq uint64 // the seq last delivered
}

func (t *tracked) final() bool { return rank(t.r.Result) == 3 }

// tracker holds the results waiting to be reported.
type tracker struct {
	byID  map[string]*tracked
	order []string // oldest first
	seq   uint64
}

func newTracker() *tracker { return &tracker{byID: map[string]*tracked{}} }

// count is a pointer to n, for the optional counts of a result.
func count(n int) *int { return &n }

// record sets a command's result. A result of a lower or equal rank than
// the current one is ignored, except that SCANNING updates its side count.
func (t *tracker) record(id, result string, sides, sheets *int, stack, message string) {
	if id == "" {
		return
	}
	e := t.byID[id]
	if e != nil {
		if e.final() || rank(result) < rank(e.r.Result) {
			return
		}
		if rank(result) == rank(e.r.Result) && result != e.r.Result {
			return
		}
	} else {
		e = &tracked{}
		t.byID[id] = e
		t.order = append(t.order, id)
	}
	t.seq++
	e.seq = t.seq
	e.r = sally.CommandResult{ID: id, Result: result, Sides: sides, Sheets: sheets, Stack: stack, Message: cutRunes(message, maxMessage)}
	t.trim()
}

// trim keeps at most maxTracked entries: delivered finals go first, then
// the oldest.
func (t *tracker) trim() {
	for len(t.order) > maxTracked {
		drop := -1
		for i, id := range t.order {
			if e := t.byID[id]; e.final() && e.sentSeq == e.seq {
				drop = i
				break
			}
		}
		if drop < 0 {
			drop = 0
		}
		delete(t.byID, t.order[drop])
		t.order = append(t.order[:drop], t.order[drop+1:]...)
	}
}

// snapshot returns at most 20 entries changed since their last delivery,
// oldest change first, and the seq each was sent at.
func (t *tracker) snapshot() ([]sally.CommandResult, map[string]uint64) {
	var es []*tracked
	for _, id := range t.order {
		if e := t.byID[id]; e.seq > e.sentSeq {
			es = append(es, e)
		}
	}
	sort.SliceStable(es, func(i, j int) bool { return es[i].seq < es[j].seq })
	if len(es) > maxSentResults {
		es = es[:maxSentResults]
	}
	out := make([]sally.CommandResult, 0, len(es))
	sent := map[string]uint64{}
	for _, e := range es {
		out = append(out, e.r)
		sent[e.r.ID] = e.seq
	}
	return out, sent
}

// delivered notes a 2xx for what snapshot returned, and drops the entries
// that are final and were sent at their latest seq.
func (t *tracker) delivered(sent map[string]uint64) {
	kept := t.order[:0]
	for _, id := range t.order {
		e := t.byID[id]
		if s, ok := sent[id]; ok && s > e.sentSeq {
			e.sentSeq = s
		}
		if e.final() && e.sentSeq == e.seq {
			delete(t.byID, id)
			continue
		}
		kept = append(kept, id)
	}
	t.order = kept
}

// result returns a command's current result, for tests and the log.
func (t *tracker) result(id string) (sally.CommandResult, bool) {
	e, ok := t.byID[id]
	if !ok {
		return sally.CommandResult{}, false
	}
	return e.r, true
}

// randomID is a random id for a local action or a pile.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// queueActionLocked adds a status-page action to report, dropping the
// oldest past maxLocalActions. A SELECT_SCANNER always carries scannerId:
// the id, or null for automatic.
func (a *Agent) queueActionLocked(kind, job string, scannerID *string) {
	act := sally.LocalAction{ID: "pc-" + randomHex(8), Kind: kind, At: a.opt.Now().UTC(), Job: job}
	if kind == "SELECT_SCANNER" {
		act.ScannerID = json.RawMessage("null")
		if scannerID != nil {
			act.ScannerID, _ = json.Marshal(*scannerID)
		}
	}
	a.actions = append(a.actions, act)
	if n := len(a.actions) - maxLocalActions; n > 0 {
		a.actions = append([]sally.LocalAction(nil), a.actions[n:]...)
	}
}

// actionsDelivered drops the actions a 2xx check-in carried.
func (a *Agent) actionsDeliveredLocked(sent []sally.LocalAction) {
	gone := map[string]bool{}
	for _, s := range sent {
		gone[s.ID] = true
	}
	kept := a.actions[:0]
	for _, x := range a.actions {
		if !gone[x.ID] {
			kept = append(kept, x)
		}
	}
	a.actions = kept
}

// newJobID is 'j' + UTC yyyymmddThhmmss + '-' + 4 hex.
func newJobID(now time.Time) string {
	return "j" + now.UTC().Format("20060102T150405") + "-" + randomHex(2)
}

// validCommandID: at most 64 of [A-Za-z0-9-].
func validCommandID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
