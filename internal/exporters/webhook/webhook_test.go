package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/exporters/exptest"
	"github.com/skylarng89/sherlock-waf/internal/netx"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

var secret = strings.Repeat("hmac-test-", 4) + "-secret" // built at runtime so secret scanners ignore it

func cfg(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func batch(ids ...string) []extension.ExportRecord {
	var out []extension.ExportRecord
	for _, id := range ids {
		out = append(out, extension.ExportRecord{ID: id, Stream: extension.StreamEvents, At: time.Unix(1700000000, 0).UTC(), Body: json.RawMessage(`{"id":"` + id + `"}`)})
	}
	return out
}

func newExp(t *testing.T, url string, extra map[string]any) extension.Exporter {
	t.Helper()
	m := map[string]any{"url": url, "hmac_secret": secret, "allow_http": strings.HasPrefix(url, "http://")}
	for k, v := range extra {
		m[k] = v
	}
	e, err := Type{Version: "1.0"}.New(cfg(t, m))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestSendSignsAndBatches(t *testing.T) {
	var gotBody []byte
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		hdr = r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	e := newExp(t, srv.URL, map[string]any{"headers": map[string]string{"Authorization": "Bearer abc"}})
	require.NoError(t, e.Send(t.Context(), batch("e1", "e2")))

	var env struct {
		Schema  string
		Records []struct {
			ID, Stream string
			At         time.Time
			Body       map[string]string
		}
	}
	require.NoError(t, json.Unmarshal(gotBody, &env))
	assert.Equal(t, SchemaV1, env.Schema)
	require.Len(t, env.Records, 2)
	assert.Equal(t, "e1", env.Records[0].ID)
	assert.Equal(t, "e2", env.Records[1].Body["id"])

	ts := hdr.Get("X-Sherlock-Timestamp")
	_, err := strconv.ParseInt(ts, 10, 64)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(gotBody)))
	assert.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), hdr.Get("X-Sherlock-Signature"))
	assert.Len(t, hdr.Get("X-Sherlock-Delivery"), 32)
	assert.Equal(t, "application/json", hdr.Get("Content-Type"))
	assert.Equal(t, "Sherlock-WAF/1.0", hdr.Get("User-Agent"))
	assert.Equal(t, "Bearer abc", hdr.Get("Authorization"))
}

func TestStatusClassification(t *testing.T) {
	for code, class := range map[int]string{
		200: "ok", 204: "ok", 408: "transient", 429: "transient", 500: "transient", 503: "transient",
		400: "permanent", 401: "permanent", 404: "permanent", 413: "permanent", 302: "permanent",
	} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if code == 302 {
					w.Header().Set("Location", "http://169.254.169.254/latest")
				}
				w.WriteHeader(code)
			}))
			defer srv.Close()
			err := newExp(t, srv.URL, nil).Send(t.Context(), batch("e1"))
			switch class {
			case "ok":
				assert.NoError(t, err)
			case "transient":
				require.Error(t, err)
				assert.NotErrorIs(t, err, extension.ErrPermanent)
			case "permanent":
				assert.ErrorIs(t, err, extension.ErrPermanent)
			}
		})
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	e := newExp(t, srv.URL, nil)
	require.Error(t, e.Send(t.Context(), batch("e1")))
	err := e.Send(t.Context(), batch("e1"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retry after")
	assert.EqualValues(t, 1, calls.Load(), "no request is made while the receiver asked us to wait")
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, 30*time.Second, retryAfter("30", now))
	assert.Equal(t, maxRetryAfter, retryAfter("99999", now), "capped at five minutes")
	assert.Equal(t, time.Minute, retryAfter(now.Add(time.Minute).Format(http.TimeFormat), now))
	assert.Zero(t, retryAfter("", now))
	assert.Zero(t, retryAfter("-5", now))
	assert.Zero(t, retryAfter("soon", now))
}

func TestTLSWithPrivateCA(t *testing.T) {
	ca := exptest.NewCA(t)
	leaf := ca.Issue(t, false)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	srv.TLS = tlsConfig(leaf)
	srv.StartTLS()
	defer srv.Close()

	require.NoError(t, newExp(t, srv.URL, map[string]any{"tls": map[string]any{"ca_pem": ca.PEM}}).Send(t.Context(), batch("e1")))
	err := newExp(t, srv.URL, nil).Send(t.Context(), batch("e1"))
	require.Error(t, err, "an unknown CA must not be trusted")
	assert.NotErrorIs(t, err, extension.ErrPermanent)
}

func TestDialGuardBlocksLinkLocal(t *testing.T) {
	e := &exporter{
		s: settings{HMACSecret: secret}, target: "http://169.254.169.254/x", host: "169.254.169.254", ua: "t", now: time.Now,
		client: netx.NewClient(netx.Options{AllowPrivate: true, Timeout: 2 * time.Second}),
	}
	err := e.Send(t.Context(), batch("e1"))
	require.Error(t, err)
	assert.ErrorIs(t, err, netx.ErrBlockedAddress)
	assert.NotErrorIs(t, err, extension.ErrPermanent)
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	require.Error(t, newExp(t, srv.URL, nil).Send(t.Context(), batch("e1")))
	assert.False(t, hit.Load(), "the signed batch must not be replayed to a redirect target")
}

func TestContextTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	ctx, cancel := contextTimeout(t, 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := newExp(t, srv.URL, nil).Send(ctx, batch("e1"))
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.NotErrorIs(t, err, extension.ErrPermanent)
}

func TestErrorsNeverContainURLOrSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(400) }))
	url := srv.URL + "/hook/tok-123456?key=queryTOKEN"
	e := newExp(t, url, map[string]any{"headers": map[string]string{"X-Api-Key": "headerTOKEN"}})
	for _, err := range []error{e.Send(t.Context(), batch("e1"))} {
		require.Error(t, err)
		for _, leak := range []string{"tok-123456", "queryTOKEN", "headerTOKEN", secret} {
			assert.NotContains(t, err.Error(), leak)
		}
	}
	srv.Close()
	err := e.Send(t.Context(), batch("e1")) // connection refused now
	require.Error(t, err)
	for _, leak := range []string{"tok-123456", "queryTOKEN", "headerTOKEN", secret} {
		assert.NotContains(t, err.Error(), leak)
	}
}

func TestTestPostsEmptyFlaggedBatch(t *testing.T) {
	var env envelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &env)
	}))
	defer srv.Close()
	require.NoError(t, newExp(t, srv.URL, nil).(extension.ExporterTester).Test(t.Context()))
	assert.True(t, env.Test)
	assert.Empty(t, env.Records)
}

func TestSkipsUndecodableBodies(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	bad := []extension.ExportRecord{{ID: "x", Body: json.RawMessage(`{broken`)}}
	require.NoError(t, newExp(t, srv.URL, nil).Send(t.Context(), bad))
	assert.Zero(t, calls.Load())
}

func TestValidate(t *testing.T) {
	ca := exptest.NewCA(t)
	good := func(m map[string]any) map[string]any {
		base := map[string]any{"url": "https://siem.example/hook", "hmac_secret": secret}
		for k, v := range m {
			base[k] = v
		}
		return base
	}
	cases := map[string]struct {
		cfg  map[string]any
		fail bool
	}{
		"https":                 {good(nil), false},
		"http with opt-in":      {good(map[string]any{"url": "http://10.0.0.5:8080/h", "allow_http": true}), false},
		"loopback https":        {good(map[string]any{"url": "https://127.0.0.1:9/h"}), false},
		"private https":         {good(map[string]any{"url": "https://10.1.2.3/h"}), false},
		"private CA":            {good(map[string]any{"tls": map[string]any{"ca_pem": ca.PEM}}), false},
		"http without opt-in":   {good(map[string]any{"url": "http://siem.example/h"}), true},
		"ftp":                   {good(map[string]any{"url": "ftp://siem.example/h"}), true},
		"no url":                {map[string]any{"hmac_secret": secret}, true},
		"relative url":          {good(map[string]any{"url": "/hook"}), true},
		"userinfo":              {good(map[string]any{"url": "https://u:p@siem.example/h"}), true}, //nolint:gosec // fake credentials in a rejection test
		"metadata literal":      {good(map[string]any{"url": "https://169.254.169.254/latest"}), true},
		"link-local v6 literal": {good(map[string]any{"url": "https://[fe80::1]/h"}), true},
		"unspecified":           {good(map[string]any{"url": "https://0.0.0.0/h"}), true},
		"short secret":          {good(map[string]any{"hmac_secret": "short"}), true},
		"no secret":             {map[string]any{"url": "https://siem.example/h"}, true},
		"bad header name":       {good(map[string]any{"headers": map[string]string{"Bad Name": "v"}}), true},
		"header injection":      {good(map[string]any{"headers": map[string]string{"X-A": "v\r\nX-B: w"}}), true},
		"reserved header":       {good(map[string]any{"headers": map[string]string{"X-Sherlock-Signature": "v"}}), true},
		"content-type override": {good(map[string]any{"headers": map[string]string{"content-type": "text/plain"}}), true},
		"garbage ca":            {good(map[string]any{"tls": map[string]any{"ca_pem": "nope"}}), true},
		"unknown field":         {good(map[string]any{"verify_tls": false}), true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := Type{}.Validate(cfg(t, c.cfg))
			if c.fail {
				assert.Error(t, err)
				if err != nil {
					assert.NotContains(t, err.Error(), secret)
					assert.NotContains(t, err.Error(), "u:p")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
	tooMany := map[string]string{}
	for i := range 21 {
		tooMany["X-H"+strconv.Itoa(i)] = "v"
	}
	assert.Error(t, Type{}.Validate(cfg(t, good(map[string]any{"headers": tooMany}))))
}
