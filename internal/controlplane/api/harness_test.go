package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/certstore"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const pw = "correct horse battery"

type plane struct {
	mu   sync.Mutex
	live *config.Root
}

func (p *plane) Activate(_ context.Context, r *config.Root) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.live = r
	return nil
}

type harness struct {
	t     *testing.T
	srv   *httptest.Server
	st    store.Store
	auth  *auth.Service
	cfg   *configsvc.Service
	audit *audit.Service
	plane *plane
	admin store.User
	view  store.User

	dataDir string
	secrets *secrets.Service
	certs   *certstore.Files
	gate    *SetupGate
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

const seedConfig = `{"schema_version":1,"sites":[{"id":"shop","hosts":["shop.example.test"],"tls":{"mode":"none"},"upstreams":{"targets":["127.0.0.1:9"]},"policy":{"mode":"detect"}}]}`

type harnessOpts struct {
	noUsers bool
	update  UpdateService
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, harnessOpts{}) }

func newHarnessWith(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	ctx := t.Context()
	st, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "api.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	key, err := secrets.LoadKey(ctx, st, t.TempDir(), nil)
	require.NoError(t, err)

	au := audit.New(nil)
	pl := &plane{}
	cfg := configsvc.New(st, au, pl, nil)
	hasher := auth.NewHasher(4)
	as := auth.New(auth.Config{Store: st, Secrets: secrets.New(key), Audit: au, Hasher: hasher})

	root, err := config.FromSnapshot([]byte(seedConfig))
	require.NoError(t, err)
	_, err = cfg.Apply(ctx, configsvc.Request{Root: root, Actor: configsvc.System, Source: configsvc.SourceBoot})
	require.NoError(t, err)

	hash, err := hasher.Hash(ctx, pw)
	require.NoError(t, err)
	h := &harness{t: t, st: st, auth: as, cfg: cfg, audit: au, plane: pl}
	h.dataDir = t.TempDir()
	h.secrets = secrets.New(key)
	mk := func(id, name, role string) store.User {
		u := store.User{ID: id, Username: name, PasswordHash: hash, Role: role, CreatedAt: time.Now().UTC()}
		require.NoError(t, st.Tx(ctx, func(ctx context.Context, tx store.Tx) error { return tx.CreateUser(ctx, u) }))
		return u
	}
	if !o.noUsers {
		h.admin = mk("01ADMIN000000000000000000A", "ada", auth.RoleAdmin)
		h.view = mk("01VIEWER00000000000000000V", "vic", auth.RoleViewer)
	} else {
		gate, err := NewSetupGate(h.dataDir)
		require.NoError(t, err)
		h.gate = gate
	}

	certs := &certstore.Files{Store: st, Secrets: h.secrets, Dir: filepath.Join(h.dataDir, "certs")}
	h.certs = certs
	cfg.SetReferenceChecker(testRefs(st))
	s, err := New(Deps{
		Store: st, Config: cfg, Auth: as, Audit: au, Hasher: hasher, Info: Info{Version: "test", CRSVersion: "4.25.0"},
		Secrets: h.secrets, Certs: certs, Setup: h.gate, DataDir: h.dataDir, Update: o.update,
	})
	require.NoError(t, err)
	h.srv = httptest.NewTLSServer(s.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

// session is a client holding credentials.
type session struct {
	h      *harness
	client *http.Client
	csrf   string
	bearer string
}

func (h *harness) anon() *session {
	jar, _ := cookiejar.New(nil)
	c := *h.srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &session{h: h, client: &c}
}

// mint inserts a session row directly (the login flow has its own tests) and
// returns a client carrying its cookie and CSRF token.
func (h *harness) mint(u store.User, stage string) *session {
	h.t.Helper()
	tok, csrf := "tok-"+u.ID+"-"+stage+time.Now().Format("150405.000000"), "csrf-"+u.ID+time.Now().Format("150405.000000")
	now := time.Now().UTC()
	require.NoError(h.t, h.st.Tx(h.t.Context(), func(ctx context.Context, tx store.Tx) error {
		return tx.CreateSession(ctx, store.Session{ID: sha(tok), UserID: u.ID, Stage: stage, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), CSRFTokenHash: sha(csrf)})
	}))
	s := h.anon()
	s.client.Jar.SetCookies(mustURL(h.srv.URL), []*http.Cookie{{Name: SessionCookie, Value: tok, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}})
	s.csrf = csrf
	return s
}

// token mints an API token for u.
func (h *harness) token(u store.User, scopes []string, cidrs []string) *session {
	h.t.Helper()
	ct, err := h.auth.CreateToken(h.t.Context(), u.ID, "t", scopes, cidrs, time.Time{})
	require.NoError(h.t, err)
	s := h.anon()
	s.bearer = ct.Secret
	return s
}

type resp struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r resp) JSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(r.Body, &m), string(r.Body))
	return m
}

func (s *session) do(method, path string, body any, hdr ...string) resp {
	s.h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = bytes.NewBufferString(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(s.h.t, err)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(s.h.t.Context(), method, s.h.srv.URL+BasePath+path, rd)
	require.NoError(s.h.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+s.bearer)
	}
	if s.csrf != "" && method != http.MethodGet {
		req.Header.Set(CSRFHeader, s.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	res, err := s.client.Do(req)
	require.NoError(s.h.t, err)
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	require.NoError(s.h.t, err)
	return resp{Status: res.StatusCode, Header: res.Header, Body: b}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func timeAt(i int) time.Time {
	return time.Now().UTC().Add(-time.Duration(i) * time.Minute).Truncate(time.Microsecond)
}

// testRefs mirrors the production reference checker without importing the server package.
func testRefs(st store.Store) func(context.Context, *config.Root) config.Errors {
	return ops.ReferenceChecker(st)
}
