package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/app"
	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/feeds"
	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// activator makes a configuration live in the data plane and then points the
// feeds job at its feed settings.
type activator struct {
	dp    *app.App
	feeds *feeds.Manager
}

func (a *activator) Activate(ctx context.Context, root *config.Root) error {
	if err := a.dp.Activate(ctx, root); err != nil {
		return err
	}
	a.feeds.Apply(root.Global.Feeds)
	return nil
}

func feedStatuses(fm *feeds.Manager) []api.FeedStatus {
	var out []api.FeedStatus
	for _, s := range fm.Statuses() {
		out = append(out, api.FeedStatus{Name: s.Name, State: s.State, LastSuccess: s.LastSuccess, LastError: s.LastError, Entries: s.Entries})
	}
	return out
}

// loadBans restores the persisted bans into the data plane.
func loadBans(ctx context.Context, env *ops.Env, log *slog.Logger) error {
	var bans []store.Ban
	if err := env.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		bans, err = tx.ListActiveBans(ctx, time.Now())
		return err
	}); err != nil {
		return fmt.Errorf("loading bans: %w", err)
	}
	live := make([]acl.Ban, 0, len(bans))
	for _, b := range bans {
		ip, err := netip.ParseAddr(b.IP)
		if err != nil {
			log.Warn("skipping a stored ban with an unreadable address", "id", b.ID)
			continue
		}
		live = append(live, acl.Ban{IP: ip, Until: b.Until, Source: b.Source, Reason: b.Reason, SiteID: b.SiteID, CreatedAt: b.CreatedAt})
	}
	acl.Bans.Replace(live)
	return nil
}

// persistBans stores the bans the data plane creates by itself (auto-ban) and
// prunes expired rows. The request path only ever does a non-blocking channel
// send; if the store is slow the ban stays in memory and is merely not
// persisted, which is logged.
func persistBans(ctx context.Context, env *ops.Env, log *slog.Logger) {
	ch := make(chan acl.Ban, 256)
	acl.SetBanSink(func(b acl.Ban) {
		select {
		case ch <- b:
		default:
			log.Warn("ban persistence queue is full; the ban is active in memory but will not survive a restart", "ip", b.IP.String())
		}
	})
	prune := time.NewTicker(10 * time.Minute)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-ch:
			id, err := ids.New(b.CreatedAt)
			if err != nil {
				continue
			}
			row := store.Ban{ID: id, IP: b.IP.String(), SiteID: b.SiteID, Source: store.BanAuto, Reason: b.Reason, CreatedBy: "autoban", CreatedAt: b.CreatedAt.UTC().Truncate(time.Microsecond), Until: b.Until}
			var entry store.AuditEntry
			err = env.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
				if err := tx.PutBan(ctx, row); err != nil {
					return err
				}
				entry, err = env.Audit.Append(ctx, tx, audit.Input{
					ActorType: audit.ActorSystem, ActorID: "autoban", Action: "ban.auto", ObjectType: "ban", ObjectID: id,
					Details: map[string]any{"ip": row.IP, "site": row.SiteID, "until": row.Until.Format(time.RFC3339), "reason": row.Reason},
				})
				return err
			})
			if err != nil {
				log.Error("persisting an automatic ban failed", "error", err)
				continue
			}
			env.Audit.Deliver(ctx, entry)
		case <-prune.C:
			if err := env.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.DeleteExpiredBans(ctx, time.Now())
				return err
			}); err != nil {
				log.Error("pruning expired bans failed", "error", err)
			}
		}
	}
}
