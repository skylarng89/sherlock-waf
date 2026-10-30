// Package audit writes the tamper-evident audit log: every row carries the hash
// of the previous row, so editing or removing an entry in the middle breaks the
// chain from that point on.
//
// The honest limits (also in docs/security): anyone who can write the database
// can rewrite the newest entries and recompute every hash after the edit, and
// can truncate the tail. Verify catches truncation against the head row, and
// Checkpoint exposes (seq, head hash) so it can be witnessed off the box (logs,
// or Enterprise's signed checkpoints). It does not make a compromised database
// trustworthy.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// domain separates audit hashes from every other SHA-256 use and versions the encoding.
const domain = "sherlock-audit-v1"

// Actor types.
const (
	ActorUser   = "user"
	ActorToken  = "token"
	ActorSystem = "system"
)

// Input describes one audited action.
type Input struct {
	ActorType  string
	ActorID    string
	IP         string
	Action     string // for example "config.apply", "auth.login_failed"
	ObjectType string
	ObjectID   string
	// Details is marshalled to JSON once; those exact bytes are stored and hashed.
	// It must not carry secrets: keys that look like credentials are rejected.
	Details any
}

// Service appends to the chain.
type Service struct {
	now    func() time.Time
	logger *slog.Logger
	sinks  []extension.AuditSink
}

// New returns a Service. Sinks are notified after commit via Deliver.
func New(logger *slog.Logger, sinks ...extension.AuditSink) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{now: time.Now, logger: logger, sinks: sinks}
}

// AddSink registers a post-commit observer.
func (s *Service) AddSink(sink extension.AuditSink) { s.sinks = append(s.sinks, sink) }

var secretKey = regexp.MustCompile(`(?i)password|passwd|secret|totp|private|authorization|cookie|^token$|^key$|api[_-]?key|session[_-]?id`)

// ErrSecretInDetails means an audit detail key looks like a credential. It is
// returned instead of writing, so a careless call site cannot put a secret into
// a log that is retained and shipped.
var ErrSecretInDetails = errors.New("audit: details contain a key that looks like a credential")

func checkDetails(v any) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encoding audit details: %w", err)
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, fmt.Errorf("re-reading audit details: %w", err)
	}
	if k, found := findSecretKey(generic); found {
		return nil, fmt.Errorf("%w: %q", ErrSecretInDetails, k)
	}
	return b, nil
}

func findSecretKey(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if secretKey.MatchString(k) {
				return k, true
			}
			if sub, ok := findSecretKey(val); ok {
				return sub, true
			}
		}
	case []any:
		for _, val := range t {
			if sub, ok := findSecretKey(val); ok {
				return sub, true
			}
		}
	}
	return "", false
}

// Append adds one entry inside the caller's transaction, which makes the audit
// row commit or roll back together with the change it records. Taking the head
// row serialises concurrent appenders; the new head hash is set before return.
func (s *Service) Append(ctx context.Context, tx store.Tx, in Input) (store.AuditEntry, error) {
	details, err := checkDetails(in.Details)
	if err != nil {
		return store.AuditEntry{}, err
	}
	at := s.now().UTC().Truncate(time.Microsecond)
	id, err := ids.New(at)
	if err != nil {
		return store.AuditEntry{}, err
	}
	seq, prev, err := tx.BumpAuditHead(ctx)
	if err != nil {
		return store.AuditEntry{}, fmt.Errorf("taking audit head: %w", err)
	}
	e := store.AuditEntry{
		Seq: seq, ID: id, At: at, ActorType: in.ActorType, ActorID: in.ActorID, IP: in.IP, Action: in.Action,
		ObjectType: in.ObjectType, ObjectID: in.ObjectID, Details: details, PrevHash: prev,
	}
	e.Hash = Hash(e)
	if err := tx.InsertAudit(ctx, e); err != nil {
		return store.AuditEntry{}, fmt.Errorf("inserting audit entry: %w", err)
	}
	if err := tx.SetAuditHeadHash(ctx, e.Hash); err != nil {
		return store.AuditEntry{}, fmt.Errorf("advancing audit head: %w", err)
	}
	return e, nil
}

// Record appends one entry in a transaction of its own and delivers it.
func (s *Service) Record(ctx context.Context, st store.Store, in Input) error {
	var e store.AuditEntry
	if err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		e, err = s.Append(ctx, tx, in)
		return err
	}); err != nil {
		return err
	}
	s.Deliver(ctx, e)
	return nil
}

// Deliver notifies the sinks of committed entries. Call it after the
// transaction that Appended them has committed. Sink failures and panics are
// logged and never affect the audited operation.
func (s *Service) Deliver(ctx context.Context, entries ...store.AuditEntry) {
	for _, e := range entries {
		rec := extension.AuditRecord{
			Seq: e.Seq, ID: e.ID, At: e.At, ActorType: e.ActorType, ActorID: e.ActorID, IP: e.IP, Action: e.Action,
			ObjectType: e.ObjectType, ObjectID: e.ObjectID, Details: json.RawMessage(e.Details), PrevHash: e.PrevHash, Hash: e.Hash,
		}
		for _, sink := range s.sinks {
			s.deliverOne(ctx, sink, rec)
		}
	}
}

func (s *Service) deliverOne(ctx context.Context, sink extension.AuditSink, rec extension.AuditRecord) {
	defer func() {
		if p := recover(); p != nil {
			s.logger.Error("audit sink panicked", "seq", rec.Seq, "panic", fmt.Sprint(p))
		}
	}()
	if err := sink.Deliver(ctx, rec); err != nil {
		s.logger.Error("audit sink failed", "seq", rec.Seq, "error", err)
	}
}

// Hash computes an entry's hash:
//
//	SHA-256( "sherlock-audit-v1" || prev_hash || field(seq) || field(id) || ... || field(details) )
//
// where every field is a 4-byte big-endian length followed by its bytes (seq and
// time are 8-byte big-endian integers), so no field boundary is ambiguous.
// Details is hashed exactly as stored.
func Hash(e store.AuditEntry) string {
	h := sha256.New()
	h.Write([]byte(domain))
	field := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b))) //nolint:gosec // audit fields are far below 4 GiB
		h.Write(n[:])
		h.Write(b)
	}
	field([]byte(e.PrevHash))
	var i8 [8]byte
	binary.BigEndian.PutUint64(i8[:], uint64(e.Seq)) //nolint:gosec // seq is positive
	field(i8[:])
	field([]byte(e.ID))
	binary.BigEndian.PutUint64(i8[:], uint64(e.At.UnixMicro())) //nolint:gosec // microseconds since the epoch are positive
	field(i8[:])
	for _, s := range []string{e.ActorType, e.ActorID, e.IP, e.Action, e.ObjectType, e.ObjectID} {
		field([]byte(s))
	}
	field(e.Details)
	return hex.EncodeToString(h.Sum(nil))
}

// Problem describes where a chain stops being valid.
type Problem struct {
	Seq    int64
	Reason string
}

func (p Problem) Error() string {
	return fmt.Sprintf("audit chain broken at seq %d: %s", p.Seq, p.Reason)
}

// Report is the outcome of Verify.
type Report struct {
	Entries int
	Head    store.AuditEntry // last entry checked (zero when the log is empty)
	// Problem is nil when the chain is intact.
	Problem *Problem
}

// Verify walks the whole chain in order. It checks that sequence numbers are
// contiguous, each entry points at the previous hash, each hash recomputes, and
// that the log ends at the head row (so a truncated tail is noticed).
func Verify(ctx context.Context, st store.Store) (Report, error) {
	var rep Report
	const page = 500
	after, prev := int64(0), ""
	for {
		var batch []store.AuditEntry
		if err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
			batch, err = tx.ListAuditAfter(ctx, after, page)
			return err
		}); err != nil {
			return rep, fmt.Errorf("reading audit log: %w", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			switch {
			case e.Seq != after+1:
				rep.Problem = &Problem{Seq: after + 1, Reason: fmt.Sprintf("sequence jumps to %d: entries were removed", e.Seq)}
				return rep, nil
			case e.PrevHash != prev:
				rep.Problem = &Problem{Seq: e.Seq, Reason: "does not point at the previous entry"}
				return rep, nil
			case Hash(e) != e.Hash:
				rep.Problem = &Problem{Seq: e.Seq, Reason: "contents do not match the stored hash: the entry was altered"}
				return rep, nil
			}
			after, prev = e.Seq, e.Hash
			rep.Entries++
			rep.Head = e
		}
	}

	var headSeq int64
	var headHash string
	if err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		headSeq, headHash, err = tx.AuditHead(ctx)
		return err
	}); err != nil {
		return rep, fmt.Errorf("reading audit head: %w", err)
	}
	if headSeq != after || headHash != prev {
		rep.Problem = &Problem{Seq: after + 1, Reason: fmt.Sprintf("log ends at seq %d but the head records seq %d: the newest entries were removed", after, headSeq)}
	}
	return rep, nil
}

// Checkpoint is the (sequence, hash) of the newest entry. Publishing it
// somewhere an attacker with database access cannot rewrite lets anyone later
// prove the log was not rolled back past it.
type Checkpoint struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// Head returns the current checkpoint.
func Head(ctx context.Context, st store.Store) (Checkpoint, error) {
	var c Checkpoint
	err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		c.Seq, c.Hash, err = tx.AuditHead(ctx)
		return err
	})
	return c, err
}

// RunCheckpointer logs the checkpoint every interval until ctx ends, so that the
// log pipeline (journald, a SIEM) holds an independent witness of the chain head.
func RunCheckpointer(ctx context.Context, st store.Store, logger *slog.Logger, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c, err := Head(ctx, st)
			if err != nil {
				logger.Error("audit checkpoint failed", "error", err)
				continue
			}
			if c.Seq > 0 {
				logger.Info("audit checkpoint", "seq", c.Seq, "head_hash", c.Hash)
			}
		}
	}
}

// Redacted reports whether a key would be refused in details (exported for tests and callers that pre-check).
func Redacted(key string) bool { return secretKey.MatchString(strings.TrimSpace(key)) }
