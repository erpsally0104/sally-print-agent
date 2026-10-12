package outbox

import (
	"context"
	"errors"
	"sync"

	"github.com/sallyerp/sally-print-agent/internal/sally"
)

// sendFolder sends a watched-folder stack: announce it as a FOLDER stack,
// upload each file not yet with Sally (25 addresses at a time, Parallel at
// once), confirm each, then done. Like a scanned stack, announcing again
// answers the files Sally already holds (by SHA-256), so a restart resumes.
func (u *Uploader) sendFolder(ctx context.Context, m *Manifest) error {
	runID, received, err := u.API.AnnounceFolder(ctx, sally.FolderStack{
		Stack: m.Stack, Files: len(m.Sides), FileName: m.FileName, FolderName: m.FolderName, ScannedAt: m.Created,
	})
	if err != nil {
		return err
	}
	if err := u.Store.SetRunID(m.Stack, runID); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, h := range received {
		have[h] = true
	}
	var todo []Side
	for _, sd := range m.Sides {
		if have[sd.SHA256] {
			if err := u.Store.MarkConfirmed(m.Stack, sd.Sheet, sd.Side); err != nil {
				return err
			}
			continue
		}
		if sd.State != Confirmed {
			todo = append(todo, sd)
		}
	}
	for len(todo) > 0 {
		n := 25
		if n > len(todo) {
			n = len(todo)
		}
		if err := u.sendFileBatch(ctx, m.Stack, runID, todo[:n]); err != nil {
			return err
		}
		todo = todo[n:]
	}
	if err := u.API.Done(ctx, runID); err != nil {
		return err
	}
	return u.Store.MarkDone(m.Stack)
}

func fileDecl(sd Side) sally.FileDecl {
	return sally.FileDecl{Index: sd.Sheet, Name: sd.Name, FolderPath: sd.FolderPath, Size: sd.Size, SHA256: sd.SHA256, ContentType: sd.ContentType}
}

func (u *Uploader) sendFileBatch(ctx context.Context, stack, runID string, batch []Side) error {
	decls := make([]sally.FileDecl, len(batch))
	byIndex := map[int]Side{}
	for i, sd := range batch {
		decls[i] = fileDecl(sd)
		byIndex[sd.Sheet] = sd
	}
	targets, err := u.API.FileUploadURLs(ctx, runID, decls)
	if err != nil {
		return err
	}
	if len(targets) != len(batch) {
		return errors.New("outbox: Sally returned a different number of upload addresses")
	}
	for _, t := range targets {
		if _, ok := byIndex[t.Index]; !ok {
			return errors.New("outbox: Sally returned an upload address for a file it was not asked about")
		}
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
		sd := byIndex[t.Index]
		wg.Add(1)
		sem <- struct{}{}
		go func(t sally.FileTarget, sd Side) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			body, err := u.Store.ReadSide(stack, sd.Sheet, sd.Side)
			if err != nil {
				fail(err)
				return
			}
			if err := u.API.PutObject(ctx, t.Upload(), body); err != nil {
				fail(err)
				return
			}
			_ = u.Store.MarkUploaded(stack, sd.Sheet, sd.Side)
			if err := u.API.ConfirmFile(ctx, runID, fileDecl(sd), t.Ticket); err != nil {
				fail(&sideError{sheet: sd.Sheet, side: 0, err: err})
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
