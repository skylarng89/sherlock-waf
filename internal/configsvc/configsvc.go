// Package configsvc owns the lifecycle of the node's configuration: versioned
// storage, optimistic concurrency, activation in the data plane, rollback and
// audit.
//
// Applying a change is ordered so the database never claims a version that is
// not live, and no change is lost silently:
//
//  1. serialise in-process and compare the caller's If-Match to the head;
//  2. validate (pure) and detect no-ops;
//  3. activate in the data plane (Caddy rolls itself back if it refuses);
//  4. ONE transaction: insert the version, compare-and-set the head, replace the
//     site projection, append the audit row;
//  5. if step 4 fails, re-activate the previous configuration.
//
// A crash between 3 and 4 is harmless: the client never saw success and boot
// always loads the database head, so the node returns to the last committed
// version.
package configsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Errors mapped to HTTP statuses by the API layer.
var (
	// ErrPreconditionFailed: If-Match names a version that is not the head (412).
	ErrPreconditionFailed = errors.New("configsvc: the configuration changed since you read it")
	// ErrPreconditionRequired: a change was attempted without If-Match (428).
	ErrPreconditionRequired = errors.New("configsvc: If-Match is required to change an existing configuration")
	// ErrActivation: the data plane refused the configuration; nothing was saved (422).
	ErrActivation = errors.New("configsvc: the data plane rejected the configuration")
	// ErrNotFound: no such version.
	ErrNotFound = errors.New("configsvc: version not found")
)

// InvalidError carries the validation errors of a rejected configuration (422).
type InvalidError struct{ Errors config.Errors }

func (e *InvalidError) Error() string { return e.Errors.Error() }

// Activator makes a validated configuration live in the data plane. It must
// leave the previous configuration serving if it returns an error.
type Activator interface {
	Activate(ctx context.Context, root *config.Root) error
}

// Actor is who requested a change, recorded in the audit log.
type Actor struct {
	Type string // audit.ActorUser, ActorToken, ActorSystem
	ID   string
	IP   string
}

// System is the actor for changes the node makes itself.
var System = Actor{Type: audit.ActorSystem, ID: "node"}

// Version sources.
const (
	SourceAPI      = "api"
	SourceImport   = "import"
	SourceRollback = "rollback"
	SourceCLI      = "cli"
	SourceBoot     = "boot"
)

// Service manages configuration versions.
type Service struct {
	st     store.Store
	audit  *audit.Service
	act    Activator
	logger *slog.Logger
	now    func() time.Time

	refs func(context.Context, *config.Root) config.Errors // existence of referenced stored objects; nil in tests

	mu     sync.Mutex   // serialises every change
	head   string       // id of the version believed live ("" = none)
	active *config.Root // the configuration the data plane is running

	degraded atomic.Bool
}

// New returns a Service. audit may be nil only in tests.
func New(st store.Store, a *audit.Service, act Activator, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{st: st, audit: a, act: act, logger: logger, now: time.Now}
}

// SetReferenceChecker installs the check that every stored object a
// configuration refers to (certificates, block pages) exists. It runs on every
// change, including rollbacks, so an old version that points at a deleted
// object is refused instead of half-applied.
func (s *Service) SetReferenceChecker(fn func(context.Context, *config.Root) config.Errors) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs = fn
}

// Check validates root as Apply would, including references, without applying it.
func (s *Service) Check(ctx context.Context, root *config.Root) config.Errors {
	errs := Validate(root)
	if len(errs) > 0 {
		return errs
	}
	s.mu.Lock()
	refs := s.refs
	s.mu.Unlock()
	if refs == nil {
		return nil
	}
	cp := *root
	cp.ApplyDefaults()
	return refs(ctx, &cp)
}

// Ready reports false when the data plane may be running something other than
// the stored head (a failed compensation, or a failed boot).
func (s *Service) Ready() bool { return !s.degraded.Load() }

// ETag is the strong entity tag for a version id.
func ETag(id string) string { return `"` + id + `"` }

// ParseIfMatch extracts the version id from an If-Match header value. Only a
// single strong tag is accepted: weak validators and lists are refused, since a
// precondition on a configuration must be exact.
func ParseIfMatch(header string) (id string, present bool, err error) {
	h := strings.TrimSpace(header)
	if h == "" {
		return "", false, nil
	}
	if strings.HasPrefix(h, "W/") || strings.Contains(h, ",") || h == "*" {
		return "", true, errors.New("If-Match must be a single strong entity tag")
	}
	if len(h) < 2 || h[0] != '"' || h[len(h)-1] != '"' {
		return "", true, errors.New("If-Match must be a quoted entity tag")
	}
	return h[1 : len(h)-1], true, nil
}

// Head returns the live version id ("" when none has been applied).
func (s *Service) Head() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head
}

// Boot loads the stored head and activates it. With an empty database there is
// nothing to activate and the node waits for a first configuration.
func (s *Service) Boot(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var v store.ConfigVersion
	var head string
	if err := s.st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		var err error
		if head, err = tx.ConfigHead(ctx); err != nil || head == "" {
			return err
		}
		v, err = tx.GetConfigVersion(ctx, head)
		return err
	}); err != nil {
		s.degraded.Store(true)
		return fmt.Errorf("reading stored configuration: %w", err)
	}
	if head == "" {
		return nil
	}
	root, err := config.FromSnapshot(v.Snapshot)
	if err != nil {
		s.degraded.Store(true)
		return fmt.Errorf("stored configuration %s is unusable: %w", head, err)
	}
	if err := s.act.Activate(ctx, root); err != nil {
		s.degraded.Store(true)
		return fmt.Errorf("activating stored configuration %s: %w", head, err)
	}
	s.head, s.active = head, root
	s.degraded.Store(false)
	return nil
}

// Request is one change.
type Request struct {
	Root *config.Root
	// Expected is the version id from If-Match; Conditional says whether the
	// header was present at all.
	Expected    string
	Conditional bool
	Actor       Actor
	Source      string
}

// Validate checks a configuration without applying it.
func Validate(root *config.Root) config.Errors {
	cp := *root
	cp.ApplyDefaults()
	return cp.Validate()
}

// Apply validates, activates and records a new configuration version. It
// returns the live version (the existing head if nothing changed).
func (s *Service) Apply(ctx context.Context, req Request) (store.ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apply(ctx, req, "config.apply")
}

func (s *Service) apply(ctx context.Context, req Request, action string) (store.ConfigVersion, error) {
	if s.head != "" && !req.Conditional {
		return store.ConfigVersion{}, ErrPreconditionRequired
	}
	if req.Expected != s.head {
		return store.ConfigVersion{}, ErrPreconditionFailed
	}

	root := req.Root
	root.ApplyDefaults()
	errs := root.Validate()
	if len(errs) == 0 && s.refs != nil {
		errs = s.refs(ctx, root)
	}
	if len(errs) > 0 {
		s.auditFailure(ctx, req, action, "invalid", fmt.Sprintf("%d validation errors", len(errs)))
		return store.ConfigVersion{}, &InvalidError{Errors: errs}
	}
	snapshot, err := config.Snapshot(root)
	if err != nil {
		return store.ConfigVersion{}, err
	}

	prev, prevSnap := s.loadActive(ctx)
	if s.head != "" && string(snapshot) == string(prevSnap) {
		return s.versionByID(ctx, s.head) // nothing to do: same bytes, same version
	}

	if err := s.act.Activate(ctx, root); err != nil {
		s.logger.Error("the data plane rejected a configuration", "action", action, "error", err)
		s.auditFailure(ctx, req, action, "activation", err.Error())
		return store.ConfigVersion{}, fmt.Errorf("%w: %v", ErrActivation, err)
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	id, err := ids.New(now)
	if err != nil {
		s.restore(ctx, prev)
		return store.ConfigVersion{}, err
	}
	diff, err := Diff(prev, root)
	if err != nil {
		s.restore(ctx, prev)
		return store.ConfigVersion{}, err
	}
	version := store.ConfigVersion{
		ID: id, ParentID: s.head, CreatedAt: now, AuthorType: req.Actor.Type, AuthorID: req.Actor.ID,
		Source: req.Source, SchemaVersion: root.SchemaVersion, Snapshot: snapshot, Diff: diff, Applied: true,
	}

	var entry store.AuditEntry
	commitErr := s.st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err := tx.InsertConfigVersion(ctx, version); err != nil {
			return err
		}
		ok, err := tx.CompareAndSetConfigHead(ctx, s.head, id)
		if err != nil {
			return err
		}
		if !ok {
			return ErrPreconditionFailed // another process moved the head
		}
		if err := tx.ReplaceSites(ctx, projection(root, now)); err != nil {
			return err
		}
		if s.audit == nil {
			return nil
		}
		entry, err = s.audit.Append(ctx, tx, audit.Input{
			ActorType: req.Actor.Type, ActorID: req.Actor.ID, IP: req.Actor.IP, Action: action,
			ObjectType: "config", ObjectID: id,
			Details: map[string]any{"from": s.head, "source": req.Source, "diff": json.RawMessage(diff)},
		})
		return err
	})
	if commitErr != nil {
		s.restore(ctx, prev)
		return store.ConfigVersion{}, commitErr
	}

	s.head, s.active = id, root
	s.degraded.Store(false)
	if s.audit != nil {
		s.audit.Deliver(ctx, entry)
	}
	return version, nil
}

// loadActive returns the running configuration and its canonical snapshot.
func (s *Service) loadActive(ctx context.Context) (*config.Root, []byte) {
	if s.active == nil {
		return nil, nil
	}
	snap, err := config.Snapshot(s.active)
	if err != nil {
		s.logger.Error("encoding the active configuration", "error", err)
		return s.active, nil
	}
	return s.active, snap
}

// restore puts the data plane back on prev after a failed commit. If that fails
// too, the node reports itself not ready: it is running something that was not saved.
func (s *Service) restore(ctx context.Context, prev *config.Root) {
	if prev == nil {
		s.degraded.Store(true)
		s.logger.Error("data plane runs a configuration that could not be saved and there is no previous one to restore")
		return
	}
	if err := s.act.Activate(ctx, prev); err != nil {
		s.degraded.Store(true)
		s.logger.Error("could not restore the previous configuration after a failed save", "error", err)
	}
}

func (s *Service) auditFailure(ctx context.Context, req Request, action, reason, detail string) {
	if s.audit == nil {
		return
	}
	if len(detail) > 300 {
		detail = detail[:300]
	}
	err := s.audit.Record(ctx, s.st, audit.Input{
		ActorType: req.Actor.Type, ActorID: req.Actor.ID, IP: req.Actor.IP, Action: action + "_failed",
		ObjectType: "config", ObjectID: s.head, Details: map[string]any{"reason": reason, "detail": detail, "source": req.Source},
	})
	if err != nil {
		s.logger.Error("recording a failed config change", "error", err)
	}
}

func (s *Service) versionByID(ctx context.Context, id string) (store.ConfigVersion, error) {
	var v store.ConfigVersion
	err := s.st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		v, err = tx.GetConfigVersion(ctx, id)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return v, ErrNotFound
	}
	return v, err
}

// Rollback applies the snapshot of an earlier version as a NEW version, through
// the same validation and activation as any other change, so history stays
// linear and the rollback is itself audited and reversible.
func (s *Service) Rollback(ctx context.Context, targetID string, req Request) (store.ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.versionByID(ctx, targetID)
	if err != nil {
		return store.ConfigVersion{}, err
	}
	root, err := config.FromSnapshot(target.Snapshot)
	if err != nil {
		return store.ConfigVersion{}, fmt.Errorf("version %s cannot be restored: %w", targetID, err)
	}
	req.Root, req.Source = root, SourceRollback
	return s.apply(ctx, req, "config.rollback")
}

// Current returns the live version and its configuration, or ErrNotFound before
// the first configuration is applied.
func (s *Service) Current(ctx context.Context) (store.ConfigVersion, *config.Root, error) {
	s.mu.Lock()
	head, active := s.head, s.active
	s.mu.Unlock()
	if head == "" || active == nil {
		return store.ConfigVersion{}, nil, ErrNotFound
	}
	v, err := s.versionByID(ctx, head)
	return v, active, err
}

// Version returns one stored version.
func (s *Service) Version(ctx context.Context, id string) (store.ConfigVersion, error) {
	return s.versionByID(ctx, id)
}

// Versions lists history newest first.
func (s *Service) Versions(ctx context.Context, c store.Cursor, limit int) ([]store.ConfigVersion, error) {
	var out []store.ConfigVersion
	err := s.st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = tx.ListConfigVersions(ctx, c, limit)
		return err
	})
	return out, err
}

func projection(root *config.Root, at time.Time) []store.Site {
	out := make([]store.Site, len(root.Sites))
	for i, site := range root.Sites {
		hosts, _ := json.Marshal(site.Hosts)
		mode := string(config.ModeDetect)
		if site.Policy.Mode != nil {
			mode = string(*site.Policy.Mode)
		}
		out[i] = store.Site{ID: site.ID, Name: site.Name, Mode: mode, Hosts: hosts, UpdatedAt: at}
	}
	return out
}

// Diff summarises what changed between two configurations as JSON:
// {"global":bool,"sites":{"added":[],"removed":[],"changed":[{"site":"shop","fields":["policy"]}]}}.
// prev may be nil (the first version). User-chosen names appear only as values,
// never as keys, so a site called "token" cannot trip the audit credential guard.
func Diff(prev, next *config.Root) ([]byte, error) {
	type siteChange struct {
		Site   string   `json:"site"`
		Fields []string `json:"fields"`
	}
	type siteDiff struct {
		Added   []string     `json:"added"`
		Removed []string     `json:"removed"`
		Changed []siteChange `json:"changed"`
	}
	d := struct {
		Global bool     `json:"global"`
		Sites  siteDiff `json:"sites"`
	}{Sites: siteDiff{Added: []string{}, Removed: []string{}, Changed: []siteChange{}}}

	fields := func(site config.Site) (map[string]json.RawMessage, error) {
		b, err := json.Marshal(site)
		if err != nil {
			return nil, err
		}
		var m map[string]json.RawMessage
		return m, json.Unmarshal(b, &m)
	}

	oldSites := map[string]config.Site{}
	if prev != nil {
		for _, site := range prev.Sites {
			oldSites[site.ID] = site
		}
		a, _ := json.Marshal(prev.Global)
		b, _ := json.Marshal(next.Global)
		d.Global = string(a) != string(b)
	} else {
		d.Global = true
	}
	seen := map[string]bool{}
	for _, site := range next.Sites {
		seen[site.ID] = true
		old, existed := oldSites[site.ID]
		if !existed {
			d.Sites.Added = append(d.Sites.Added, site.ID)
			continue
		}
		om, err := fields(old)
		if err != nil {
			return nil, err
		}
		nm, err := fields(site)
		if err != nil {
			return nil, err
		}
		var changed []string
		for k := range nm {
			if string(om[k]) != string(nm[k]) {
				changed = append(changed, k)
			}
		}
		for k := range om {
			if _, ok := nm[k]; !ok {
				changed = append(changed, k)
			}
		}
		if len(changed) > 0 {
			sort.Strings(changed)
			d.Sites.Changed = append(d.Sites.Changed, siteChange{Site: site.ID, Fields: changed})
		}
	}
	for id := range oldSites {
		if !seen[id] {
			d.Sites.Removed = append(d.Sites.Removed, id)
		}
	}
	sort.Strings(d.Sites.Added)
	sort.Strings(d.Sites.Removed)
	sort.Slice(d.Sites.Changed, func(i, j int) bool { return d.Sites.Changed[i].Site < d.Sites.Changed[j].Site })
	return json.Marshal(d)
}
