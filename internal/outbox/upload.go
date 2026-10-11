package outbox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sallyerp/sally-print-agent/internal/sally"
)

// API is the part of the Sally client the uploader uses.
type API interface {
	AnnounceStack(ctx context.Context, stack string, sheets, sides int, scannedAt time.Time) (string, []sally.SideRef, error)
	UploadURLs(ctx context.Context, runID string, sides []sally.SideDecl) ([]sally.UploadTarget, error)
	PutObject(ctx context.Context, t sally.UploadTarget, body []byte) error
	ConfirmSide(ctx context.Context, runID string, sheet, side int, sha256, ticket string) error
	Done(ctx context.Context, runID string) error
}

// Uploader sends the outbox to Sally in the background.
type Uploader struct {
	Store *Store
	API   API
	// Ready reports whether sending is possible (paired, token present).
	Ready func() bool
	// Parallel is how many sides go up at once.
	Parallel int
	// OnError and OnSent let the agent show progress and problems.
	OnError func(error)
	OnSent  func(stack string)
	// OnRefused reports a stack Sally will never take as it is.
	OnRefused func(stack, reason string, err error)

	kick chan struct{}
	once sync.Once
}

func (u *Uploader) init() {
	u.once.Do(func() {
		u.kick = make(chan struct{}, 1)
		if u.Parallel <= 0 {
			u.Parallel = 3
		}
	})
}

// Kick wakes the uploader (a new stack, or the internet is back).
func (u *Uploader) Kick() {
	u.init()
	select {
	case u.kick <- struct{}{}:
	default:
	}
}

// Run sends until ctx ends. Being offline is normal: it backs off from 2 s up
// to 5 min and tries again, and a Kick retries at once.
func (u *Uploader) Run(ctx context.Context) {
	u.init()
	backoff := time.Duration(0)
	for {
		if u.Ready == nil || u.Ready() {
			if err := u.SendAll(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				if u.OnError != nil {
					u.OnError(err)
				}
				backoff = nextBackoff(backoff)
			} else {
				backoff = 0
			}
		}
		wait := 30 * time.Second
		if backoff > 0 {
			wait = backoff
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-u.kick:
			t.Stop()
		case <-t.C:
		}
	}
}

func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return 2 * time.Second
	}
	d *= 2
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}

// MaxBadHash is how many times one side may come back 422 (the bytes Sally
// got did not match the hash) before the stack counts as refused.
const MaxBadHash = 3

// SendAll sends every waiting stack, oldest first.
//
// A failure that concerns Sally or the connection as a whole (offline, 5xx,
// 401, 403, 429) stops at once so the caller can back off. A failure that
// concerns one stack only must not block the stacks behind it: a refusal
// that can never clear (400, 404, 409, or MaxBadHash 422s for one side)
// marks the stack refused and moves on, and a 422 below that count is
// retried on the next round after the other stacks have had their turn.
func (u *Uploader) SendAll(ctx context.Context) error {
	u.init()
	var later error
	for _, m := range u.Store.Stacks() {
		err := u.sendStack(ctx, m)
		if err == nil {
			if u.OnSent != nil {
				u.OnSent(m.Stack)
			}
			continue
		}
		if ctx.Err() != nil {
			return err
		}
		if reason := finalRefusal(err); reason != "" {
			u.refuse(m.Stack, reason, err)
			continue
		}
		var se *sideError
		if errors.As(err, &se) && sally.StatusOf(err) == http.StatusUnprocessableEntity {
			n, nerr := u.Store.NoteBadHash(m.Stack, se.sheet, se.side)
			if nerr != nil {
				return nerr
			}
			if n >= MaxBadHash {
				u.refuse(m.Stack, fmt.Sprintf("sheet %d side %d did not arrive intact after %d tries", se.sheet, se.side, n), err)
				continue
			}
			later = err
			continue
		}
		return err
	}
	return later
}

func (u *Uploader) refuse(stack, reason string, err error) {
	if merr := u.Store.MarkRefused(stack, reason); merr != nil {
		return
	}
	if u.OnRefused != nil {
		u.OnRefused(stack, reason, err)
	}
}

// finalRefusal says why Sally will never take a stack as it is, or "" when
// the error may clear by itself. Only Sally's own answers count: an S3
// refusal of a presigned PUT (an expired address) clears with a new one.
func finalRefusal(err error) string {
	var ae *sally.APIError
	if !errors.As(err, &ae) || ae.Path == "(upload)" {
		return ""
	}
	switch ae.Status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict:
	default:
		return ""
	}
	msg := strings.TrimSpace(ae.Message)
	if msg == "" || strings.HasPrefix(msg, "<") {
		msg = map[int]string{
			http.StatusBadRequest: "it did not accept the pages",
			http.StatusNotFound:   "it does not know this stack",
			http.StatusConflict:   "the stack was already started",
		}[ae.Status]
	}
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

// sideError ties a failure to the one side it concerns.
type sideError struct {
	sheet, side int
	err         error
}

func (e *sideError) Error() string {
	return fmt.Sprintf("sheet %d side %d: %v", e.sheet, e.side, e.err)
}
func (e *sideError) Unwrap() error { return e.err }

func (u *Uploader) sendStack(ctx context.Context, m *Manifest) error {
	// Announcing is idempotent: for a stack Sally already knows, it answers
	// with the same run and the sides it already holds, which is how a
	// restarted agent resumes without sending anything twice.
	runID, received, err := u.API.AnnounceStack(ctx, m.Stack, m.Sheets, len(m.Sides), m.Created)
	if err != nil {
		return err
	}
	if err := u.Store.SetRunID(m.Stack, runID); err != nil {
		return err
	}
	have := map[[2]int]bool{}
	for _, r := range received {
		have[[2]int{r.Sheet, r.Side}] = true
		if err := u.Store.MarkConfirmed(m.Stack, r.Sheet, r.Side); err != nil {
			return err
		}
	}

	var todo []Side
	for _, sd := range m.Sides {
		if sd.State != Confirmed && !have[[2]int{sd.Sheet, sd.Side}] {
			todo = append(todo, sd)
		}
	}
	for len(todo) > 0 {
		n := 25
		if n > len(todo) {
			n = len(todo)
		}
		batch := todo[:n]
		todo = todo[n:]
		if err := u.sendBatch(ctx, m.Stack, runID, batch); err != nil {
			return err
		}
	}

	if err := u.API.Done(ctx, runID); err != nil {
		return err
	}
	return u.Store.MarkDone(m.Stack)
}

func (u *Uploader) sendBatch(ctx context.Context, stack, runID string, batch []Side) error {
	decls := make([]sally.SideDecl, len(batch))
	bySide := map[[2]int]Side{}
	for i, sd := range batch {
		decls[i] = sally.SideDecl{Sheet: sd.Sheet, Side: sd.Side, Size: sd.Size, SHA256: sd.SHA256}
		bySide[[2]int{sd.Sheet, sd.Side}] = sd
	}
	targets, err := u.API.UploadURLs(ctx, runID, decls)
	if err != nil {
		return err
	}
	if len(targets) != len(batch) {
		return errors.New("outbox: Sally returned a different number of upload addresses")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, u.Parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	fail := func(err error) {
		mu.Lock()
		if first == nil {
			first = err
			cancel()
		}
		mu.Unlock()
	}
	for _, t := range targets {
		if _, ok := bySide[[2]int{t.Sheet, t.Side}]; !ok {
			return errors.New("outbox: Sally returned an upload address for a side it was not asked about")
		}
	}
	for _, t := range targets {
		sd := bySide[[2]int{t.Sheet, t.Side}]
		wg.Add(1)
		sem <- struct{}{}
		go func(t sally.UploadTarget, sd Side) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			page, err := u.Store.ReadSide(stack, sd.Sheet, sd.Side)
			if err != nil {
				fail(err)
				return
			}
			if err := u.API.PutObject(ctx, t, page); err != nil {
				fail(err)
				return
			}
			_ = u.Store.MarkUploaded(stack, sd.Sheet, sd.Side)
			if err := u.API.ConfirmSide(ctx, runID, sd.Sheet, sd.Side, sd.SHA256, t.Ticket); err != nil {
				fail(&sideError{sheet: sd.Sheet, side: sd.Side, err: err})
				return
			}
			if err := u.Store.MarkConfirmed(stack, sd.Sheet, sd.Side); err != nil {
				fail(err)
			}
		}(t, sd)
	}
	wg.Wait()
	return first
}
