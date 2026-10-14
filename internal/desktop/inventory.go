package desktop

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/sally"
)

/*
The scanner list. inventoryLoop looks for every scanner the PC can reach
(USB and network) every InventoryEvery and when asked (Look again, a new
choice), never while a pile scans. Sightings with the same id are one entry
(identity.go). An entry unseen for 3 passes is dropped, unless it is the
chosen one; the open scanner is never probed by the list, and is listed as
answering while the agent talks to it.
*/

// maxScanners is the most the heartbeat lists.
const maxScanners = 16

// dropAfterMisses: an entry unseen for this many passes leaves the list.
const dropAfterMisses = 3

func (a *Agent) inventoryLoop(ctx context.Context) {
	for ctx.Err() == nil {
		a.inventoryPass(ctx)
		t := time.NewTimer(a.opt.InventoryEvery)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-a.invKick:
			t.Stop()
		case <-t.C:
		}
	}
}

// inventoryPass runs one Look and merges it into the list. It skips while
// a pile scans.
func (a *Agent) inventoryPass(ctx context.Context) {
	// lookMu first: the scanner loop marks a scanner it opens in openSkip
	// before it lets go of lookMu, so the skip read below is never stale.
	a.lookMu.Lock()
	a.mu.Lock()
	if a.job != nil {
		a.mu.Unlock()
		a.lookMu.Unlock()
		return
	}
	addr := a.local.ScannerAddress
	skip := a.openSkip
	skip.Cache = a.probes
	skip.Seen = map[string]bool{}
	for _, f := range a.inventory {
		for _, b := range f.Net {
			if b.keys.key != "" {
				skip.Seen[b.keys.key] = true
			}
		}
	}
	known := make(map[string]string, len(a.local.KnownScanners))
	for k, v := range a.local.KnownScanners {
		known[k] = v
	}
	a.mu.Unlock()

	found := a.opt.Look(ctx, addr, skip, known, a.logf)
	a.lookMu.Unlock()
	if ctx.Err() != nil {
		return
	}

	a.mu.Lock()
	changed := a.mergeInventoryLocked(found, a.opt.Now())
	a.mu.Unlock()
	if changed {
		a.kickHeartbeat()
	}
	select {
	case a.invDone <- struct{}{}:
	default:
	}
}

// signature is what a change to the list is judged by: ids, names and
// answering flags.
func signature(fs []Found) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.ID + "\x00" + f.Name + "\x00")
		if f.Answering {
			b.WriteString("1")
		}
		b.WriteString("\x00")
	}
	return b.String()
}

// mergeInventoryLocked takes a Look's result as the new list: entries seen
// before keep when they were first seen, unseen ones count a miss and stop
// answering, and the open scanner is kept answering. It remembers the ids
// the capabilities gave, and reports whether the list changed.
func (a *Agent) mergeInventoryLocked(found []Found, now time.Time) bool {
	before := signature(a.inventory)
	prev := map[string]Found{}
	for _, f := range a.inventory {
		prev[f.ID] = f
	}
	seen := map[string]bool{}
	var out []Found
	for _, f := range found {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		if p, ok := prev[f.ID]; ok {
			f.FirstSeen = p.FirstSeen
		} else {
			f.FirstSeen = now
		}
		f.LastSeen, f.Misses = now, 0
		a.learnLocked(f.learned, now)
		out = append(out, f)
	}
	inUse := ""
	if a.inUse != nil {
		inUse = a.inUse.ID
	}
	for _, p := range a.inventory {
		if seen[p.ID] {
			continue
		}
		if p.ID != inUse {
			p.Misses++
			p.Answering = false
		}
		if p.Misses < dropAfterMisses || p.ID == a.local.ScannerID || p.ID == inUse {
			out = append(out, p)
		}
	}
	a.inventory = out
	a.mergeInUseLocked(now)
	a.invPass = now
	return signature(a.inventory) != before
}

// mergeInUseLocked puts the open scanner on the list, answering while the
// agent talks to it, joined with the entry of the same id.
func (a *Agent) mergeInUseLocked(now time.Time) {
	if a.inUse == nil {
		return
	}
	u := *a.inUse
	answering := a.scanner.State != "OFFLINE"
	for i := range a.inventory {
		f := &a.inventory[i]
		if f.ID != u.ID {
			continue
		}
		f.USB = unionStrings(u.USB, f.USB)
		f.Net = unionBases(f.Net, u.Net)
		f.Answering = f.Answering || answering
		if f.Feeder == nil {
			f.Feeder = u.Feeder
		}
		f.LastSeen, f.Misses = now, 0
		return
	}
	u.Answering = answering
	if u.FirstSeen.IsZero() {
		u.FirstSeen = now
	}
	u.LastSeen = now
	a.inventory = append(a.inventory, u)
}

func unionStrings(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, x := range b {
		dup := false
		for _, y := range out {
			if strings.EqualFold(x, y) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, x)
		}
	}
	return out
}

func unionBases(a, b []netBase) []netBase {
	out := append([]netBase(nil), a...)
	for _, x := range b {
		dup := false
		for _, y := range out {
			if strings.EqualFold(x.URL, y.URL) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, x)
		}
	}
	return out
}

// learnLocked remembers sighting key → id pairs the capabilities gave, at
// most maxKnownScanners, dropping the least recently seen.
func (a *Agent) learnLocked(learned map[string]string, now time.Time) {
	if len(learned) == 0 {
		return
	}
	if a.local.KnownScanners == nil {
		a.local.KnownScanners = map[string]string{}
	}
	changed := false
	for k, id := range learned {
		if a.local.KnownScanners[k] != id {
			a.local.KnownScanners[k] = id
			changed = true
		}
		a.knownSeen[k] = now
	}
	for len(a.local.KnownScanners) > maxKnownScanners {
		oldest, at := "", time.Time{}
		for k := range a.local.KnownScanners {
			t := a.knownSeen[k]
			if oldest == "" || t.Before(at) || (t.Equal(at) && k < oldest) {
				oldest, at = k, t
			}
		}
		delete(a.local.KnownScanners, oldest)
		delete(a.knownSeen, oldest)
		changed = true
	}
	if changed {
		a.saveLocked()
	}
}

// foundLocked finds an entry of the list by id.
func (a *Agent) foundLocked(id string) (Found, bool) {
	for _, f := range a.inventory {
		if f.ID == id {
			return f, true
		}
	}
	return Found{}, false
}

// orderedLocked is the list in the order the heartbeat sends it: the one
// in use; the chosen one; scanners seen in an earlier pass (first seen
// first) before new ones; USB before network; answering before not; then
// by name. The chosen scanner is always there, not answering when it was
// never seen.
func (a *Agent) orderedLocked() []Found {
	list := append([]Found(nil), a.inventory...)
	chosen := a.local.ScannerID
	if chosen != "" {
		if _, ok := a.foundLocked(chosen); !ok {
			f := Found{ID: chosen, Name: a.local.ScannerName, Stable: !a.local.ScannerUnstable}
			if f.Name == "" {
				f.Name = "Scanner"
			}
			for _, v := range a.local.ScannerVia {
				if v == "USB" {
					f.USB = []string{""}
				} else if v == "NETWORK" {
					f.Net = []netBase{{}}
				}
			}
			if len(f.USB) == 0 && len(f.Net) == 0 {
				f.Net = []netBase{{}}
			}
			list = append(list, f)
		}
	}
	inUse := a.scanner.ID
	if !a.scannerOpen {
		inUse = ""
	}
	pass := a.invPass
	sort.SliceStable(list, func(i, j int) bool {
		x, y := list[i], list[j]
		if (x.ID == inUse) != (y.ID == inUse) {
			return x.ID == inUse
		}
		if (x.ID == chosen) != (y.ID == chosen) {
			return x.ID == chosen
		}
		xe, ye := !x.FirstSeen.IsZero() && x.FirstSeen.Before(pass), !y.FirstSeen.IsZero() && y.FirstSeen.Before(pass)
		if xe != ye {
			return xe
		}
		if xe && !x.FirstSeen.Equal(y.FirstSeen) {
			return x.FirstSeen.Before(y.FirstSeen)
		}
		if (len(x.USB) > 0) != (len(y.USB) > 0) {
			return len(x.USB) > 0
		}
		if x.Answering != y.Answering {
			return x.Answering
		}
		return x.Name < y.Name
	})
	return list
}

// scannersLocked is the heartbeat's scanners: at most 16, never nil.
func (a *Agent) scannersLocked() []sally.ScannerChoice {
	list := a.orderedLocked()
	if len(list) > maxScanners {
		list = list[:maxScanners]
	}
	out := make([]sally.ScannerChoice, 0, len(list))
	for _, f := range list {
		c := sally.ScannerChoice{
			ID: f.ID, Name: cutRunes(f.Name, 120), Via: f.Via(), Detail: safeDetail(f.Detail),
			Answering: f.Answering, Feeder: f.Feeder, Stable: f.Stable,
		}
		if c.Name == "" {
			c.Name = "Scanner"
		}
		out = append(out, c)
	}
	return out
}
