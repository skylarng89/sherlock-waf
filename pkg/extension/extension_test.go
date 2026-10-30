package extension_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/pkg/extension"
	"github.com/skylarng89/sherlock-waf/pkg/extension/extensiontest"
)

// denyAll is a minimal extension that exercises every registration point.
type denyAll struct{ name string }

func (d denyAll) Name() string { return d.name }

func (d denyAll) Init(_ context.Context, h extension.Host) error {
	h.SetAuthorizer(authorizer{})
	h.AddAuthProvider(provider{})
	h.AddAuditSink(sink{})
	h.SetEventStore(store{})
	return nil
}

type authorizer struct{}

func (authorizer) Authorize(context.Context, extension.AuthzRequest) (extension.Decision, error) {
	return extension.Decision{Allow: false, Reason: "deny all"}, nil
}

type provider struct{}

func (provider) Name() string         { return "fake" }
func (provider) Routes() http.Handler { return http.NotFoundHandler() }

type sink struct{}

func (sink) Deliver(context.Context, extension.AuditRecord) error { return nil }

type store struct{}

func (store) Write(context.Context, []extension.EventRecord) error { return nil }
func (store) Get(context.Context, string) (extension.EventRecord, error) {
	return extension.EventRecord{}, extension.ErrNotFound
}

func (store) Query(context.Context, extension.EventQuery) (extension.EventPage, error) {
	return extension.EventPage{}, nil
}

func TestNoneRegistersNothing(t *testing.T) {
	h := extensiontest.New()
	require.NoError(t, extension.None().Init(t.Context(), h))
	assert.Nil(t, h.Authorizer)
	assert.Empty(t, h.AuthProviders)
	assert.Empty(t, h.AuditSinks)
	assert.Nil(t, h.EventStore)
	assert.Equal(t, "none", extension.None().Name())
}

func TestExtensionRegistersEverything(t *testing.T) {
	h := extensiontest.New()
	require.NoError(t, denyAll{name: "x"}.Init(t.Context(), h))

	require.NotNil(t, h.Authorizer)
	d, err := h.Authorizer.Authorize(t.Context(), extension.AuthzRequest{Permission: "config:write"})
	require.NoError(t, err)
	assert.False(t, d.Allow)
	require.Len(t, h.AuthProviders, 1)
	assert.Equal(t, "fake", h.AuthProviders[0].Name())
	require.Len(t, h.AuditSinks, 1)
	_, err = h.EventStore.Get(t.Context(), "nope")
	assert.ErrorIs(t, err, extension.ErrNotFound)
}

func TestBundleInitialisesInOrderAndStopsAtTheFirstError(t *testing.T) {
	var order []string
	mk := func(name string, err error) extension.Extension {
		return funcExt{name: name, init: func() error { order = append(order, name); return err }}
	}
	boom := errors.New("boom")
	b := extension.Bundle(mk("a", nil), mk("b", boom), mk("c", nil))
	err := b.Init(t.Context(), extensiontest.New())
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), `"b"`, "the failing extension is named")
	assert.Equal(t, []string{"a", "b"}, order, "c never starts")
	assert.Equal(t, "a+b+c", b.Name())

	assert.Equal(t, "none", extension.Bundle().Name(), "an empty bundle is None")
}

type funcExt struct {
	name string
	init func() error
}

func (f funcExt) Name() string                               { return f.name }
func (f funcExt) Init(context.Context, extension.Host) error { return f.init() }

func TestFakeHostDefaults(t *testing.T) {
	h := extensiontest.New()
	assert.Equal(t, "test", h.CoreVersion())
	assert.NotNil(t, h.Logger())
	_, dialect := h.DB()
	assert.Equal(t, extension.DialectSQLite, dialect)
	assert.NoError(t, h.Sessions().Issue(t.Context(), nil, nil, extension.Principal{}))
}
