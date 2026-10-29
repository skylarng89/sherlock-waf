package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Sink consumes events from a bus subscription. Implementations are used by a
// single goroutine and must not block the bus; slowness only grows the
// subscriber's own lag.
type Sink interface {
	Write(ev *Event) error
	Flush() error
	Close() error
}

// jsonlBatchBytes is how much encoded output JSONLWriter accumulates before
// writing it out.
const jsonlBatchBytes = 64 << 10

// JSONLWriter writes one JSON object per line to w. It batches events but only
// ever hands the underlying writer whole lines, so a reader tailing the file
// (a log shipper, go-ftw) can never observe a half-written event. A plain
// bufio.Writer cannot give that guarantee: it flushes when its buffer fills,
// in the middle of a line.
type JSONLWriter struct {
	mu      sync.Mutex
	w       io.Writer
	c       io.Closer
	pending bytes.Buffer
	line    bytes.Buffer
	enc     *json.Encoder
}

// NewJSONLWriter wraps w. If w is also an io.Closer, Close closes it.
func NewJSONLWriter(w io.Writer) *JSONLWriter {
	j := &JSONLWriter{w: w}
	j.enc = json.NewEncoder(&j.line)
	j.enc.SetEscapeHTML(false)
	if c, ok := w.(io.Closer); ok {
		j.c = c
	}
	return j
}

// Write encodes ev as one line and queues it. Queued lines are written out in
// one call once enough have accumulated, or on Flush.
func (j *JSONLWriter) Write(ev *Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.line.Reset()
	if err := j.enc.Encode(ev); err != nil { // Encode appends the newline
		return fmt.Errorf("encoding event %s: %w", ev.ID, err)
	}
	if j.pending.Len() > 0 && j.pending.Len()+j.line.Len() > jsonlBatchBytes {
		if err := j.flushLocked(); err != nil {
			return err
		}
	}
	j.pending.Write(j.line.Bytes())
	return nil
}

func (j *JSONLWriter) flushLocked() error {
	if j.pending.Len() == 0 {
		return nil
	}
	_, err := j.w.Write(j.pending.Bytes()) // whole lines only, in a single call
	j.pending.Reset()
	if err != nil {
		return fmt.Errorf("writing events: %w", err)
	}
	return nil
}

// Flush writes every queued line.
func (j *JSONLWriter) Flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.flushLocked()
}

// Close flushes and closes the underlying writer when it is closable.
func (j *JSONLWriter) Close() error {
	err := j.Flush()
	if j.c != nil {
		err = errors.Join(err, j.c.Close())
	}
	return err
}

// RotatingFile is an io.WriteCloser that appends to path and rotates it by
// size: path -> path.1 -> ... -> path.<keep>, dropping the oldest.
type RotatingFile struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	keep    int
	f       *os.File
	size    int64
}

// NewRotatingFile opens (creating directories as needed) path for append with
// 0600 permissions. maxSize is in bytes; keep is the number of rotated files.
func NewRotatingFile(path string, maxSize int64, keep int) (*RotatingFile, error) {
	if maxSize < 1 {
		return nil, fmt.Errorf("rotating file %s: max size must be positive", path)
	}
	r := &RotatingFile{path: path, maxSize: maxSize, keep: max(keep, 0)}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating directory for %s: %w", path, err)
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // operator-configured data dir
	if err != nil {
		return fmt.Errorf("opening %s: %w", r.path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat %s: %w", r.path, err)
	}
	r.f, r.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when it would exceed the size limit. A
// single write is never split across files.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.maxSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", r.path, err)
	}
	if r.keep == 0 {
		if err := os.Remove(r.path); err != nil {
			return fmt.Errorf("removing %s: %w", r.path, err)
		}
	} else {
		_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
		for i := r.keep - 1; i >= 1; i-- {
			if err := os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rotating %s: %w", r.path, err)
			}
		}
		if err := os.Rename(r.path, r.path+".1"); err != nil {
			return fmt.Errorf("rotating %s: %w", r.path, err)
		}
	}
	return r.open()
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// Drain pumps events from sub into every sink until ctx is done or the
// subscription closes, flushing after each batch and at least every
// flushEvery while events keep arriving. It returns after a final drain and
// flush. Sink errors are logged and never stop the pump.
func Drain(ctx context.Context, sub *Subscription, flushEvery time.Duration, sinks ...Sink) {
	const batch = 512
	buf := make([]*Event, batch)
	logErr := func(name string, err error) {
		if err != nil {
			slog.Error("event sink failed", "sink", name, "error", err)
		}
	}
	flush := func() {
		for _, s := range sinks {
			logErr("flush", s.Flush())
		}
	}
	pump := func() {
		for {
			n := sub.Read(buf)
			if n == 0 {
				return
			}
			for _, ev := range buf[:n] {
				for _, s := range sinks {
					logErr("write", s.Write(ev))
				}
			}
		}
	}

	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	for {
		// Wait for events, but never let buffered lines sit longer than flushEvery.
		waitCtx, cancel := context.WithTimeout(ctx, flushEvery)
		alive := sub.Wait(waitCtx)
		cancel()
		pump()
		flush()
		if ctx.Err() != nil || (!alive && sub.closed.Load()) {
			pump()
			flush()
			return
		}
	}
}
