package api

import (
	"context"
	"net/netip"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

func banDTO(b store.Ban) apigen.Ban {
	out := apigen.Ban{Id: b.ID, Ip: b.IP, Source: apigen.BanSource(b.Source), Reason: b.Reason, CreatedBy: b.CreatedBy, CreatedAt: b.CreatedAt, Until: b.Until}
	if b.SiteID != "" {
		out.SiteId = &b.SiteID
	}
	return out
}

func (h *handlers) ListBans(ctx context.Context, _ apigen.ListBansRequestObject) (apigen.ListBansResponseObject, error) {
	var bans []store.Ban
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		bans, err = tx.ListActiveBans(ctx, h.s.Now())
		return err
	}); err != nil {
		return nil, err
	}
	out := apigen.BanList{Items: make([]apigen.Ban, 0, len(bans))}
	for _, b := range bans {
		out.Items = append(out.Items, banDTO(b))
	}
	return apigen.ListBans200JSONResponse(out), nil
}

func (h *handlers) CreateBan(ctx context.Context, req apigen.CreateBanRequestObject) (apigen.CreateBanResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	ip, err := netip.ParseAddr(b.Ip)
	if err != nil {
		return nil, errBadRequest("ip must be a single IPv4 or IPv6 address.")
	}
	ip = ip.WithZone("").Unmap()
	if b.DurationSeconds < 60 || b.DurationSeconds > 30*24*3600 {
		return nil, errBadRequest("duration_seconds must be between 60 and 2592000 (30 days).")
	}
	if me, perr := netip.ParseAddr(ipFrom(ctx)); perr == nil && me.Unmap() == ip {
		return nil, errConflict("you would ban the address you are using right now")
	}
	site := ""
	if b.SiteId != nil {
		site = *b.SiteId
	}
	if site != "" {
		_, live, err := h.s.Config.Current(ctx)
		if err != nil || findSite(live, site) < 0 {
			return nil, errBadRequest("site_id does not name a site.")
		}
	}
	reason := "manual ban"
	if b.Reason != nil && *b.Reason != "" {
		reason = *b.Reason
	}
	now := h.s.Now().UTC().Truncate(time.Microsecond)
	id, err := ids.New(now)
	if err != nil {
		return nil, err
	}
	p := principalFrom(ctx)
	ban := store.Ban{ID: id, IP: ip.String(), SiteID: site, Source: store.BanManual, Reason: reason, CreatedBy: p.Username, CreatedAt: now, Until: now.Add(time.Duration(b.DurationSeconds) * time.Second)}
	if err := h.audited(ctx, "ban.create", "ban", id, map[string]any{"ip": ban.IP, "site": site, "until": ban.Until.Format(time.RFC3339), "reason": reason}, func(ctx context.Context, tx store.Tx) error {
		return tx.PutBan(ctx, ban)
	}); err != nil {
		return nil, err
	}
	acl.Bans.Add(acl.Ban{IP: ip, Until: ban.Until, Source: ban.Source, Reason: reason, SiteID: site, CreatedAt: now})
	return apigen.CreateBan201JSONResponse(banDTO(ban)), nil
}

func (h *handlers) DeleteBan(ctx context.Context, req apigen.DeleteBanRequestObject) (apigen.DeleteBanResponseObject, error) {
	var ban store.Ban
	err := h.audited(ctx, "ban.lift", "ban", req.Id, nil, func(ctx context.Context, tx store.Tx) (err error) {
		if ban, err = tx.GetBan(ctx, req.Id); err != nil {
			return err
		}
		return tx.DeleteBan(ctx, req.Id)
	})
	if err != nil {
		return nil, err
	}
	if ip, perr := netip.ParseAddr(ban.IP); perr == nil {
		acl.Bans.RemoveSite(ip, ban.SiteID)
	}
	return apigen.DeleteBan204Response{}, nil
}

func (h *handlers) GetFeedsStatus(_ context.Context, _ apigen.GetFeedsStatusRequestObject) (apigen.GetFeedsStatusResponseObject, error) {
	out := apigen.FeedsStatus{Items: []apigen.FeedStatus{}}
	if h.s.Feeds == nil {
		return apigen.GetFeedsStatus200JSONResponse(out), nil
	}
	for _, f := range h.s.Feeds() {
		item := apigen.FeedStatus{Name: f.Name, State: apigen.FeedStatusState(f.State), Entries: &f.Entries}
		if !f.LastSuccess.IsZero() {
			item.LastSuccess = &f.LastSuccess
		}
		if f.LastError != "" {
			item.LastError = &f.LastError
		}
		out.Items = append(out.Items, item)
	}
	return apigen.GetFeedsStatus200JSONResponse(out), nil
}
