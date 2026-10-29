package server

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

func TestAutoBansArePersistedAuditedAndRestored(t *testing.T) {
	acl.Bans.Replace(nil)
	t.Cleanup(func() { acl.SetBanSink(nil); acl.Bans.Replace(nil) })
	env, err := ops.Open(t.Context(), ops.OpenOptions{DataDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = env.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { persistBans(ctx, env, slog.New(slog.DiscardHandler)); close(done) }()
	require.Eventually(t, func() bool {
		acl.AddAutoBan(acl.Ban{IP: netip.MustParseAddr("203.0.113.5"), Until: time.Now().Add(time.Hour), Source: "auto", SiteID: "shop", Reason: "too many blocks", CreatedAt: time.Now()})
		var n int
		_ = env.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			bans, err := tx.ListActiveBans(ctx, time.Now())
			n = len(bans)
			return err
		})
		return n == 1
	}, 5*time.Second, 50*time.Millisecond, "the ban reaches the database")

	var entries []store.AuditEntry
	require.NoError(t, env.Store.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		entries, err = tx.ListAudit(ctx, 0, 10)
		return err
	}))
	require.NotEmpty(t, entries)
	assert.Equal(t, "ban.auto", entries[0].Action)
	assert.Equal(t, "autoban", entries[0].ActorID)
	rep, err := audit.Verify(t.Context(), env.Store)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem)
	cancel()
	<-done

	// A restart restores the live ban set from the database.
	acl.Bans.Replace(nil)
	require.NoError(t, loadBans(t.Context(), env, slog.New(slog.DiscardHandler)))
	_, banned := acl.Bans.Active(netip.MustParseAddr("203.0.113.5"), "shop", time.Now())
	assert.True(t, banned)
	_, other := acl.Bans.Active(netip.MustParseAddr("203.0.113.5"), "other", time.Now())
	assert.False(t, other, "scope survives the round trip")
}
