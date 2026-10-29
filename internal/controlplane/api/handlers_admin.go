package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

var countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

// audited runs fn and appends an audit entry in one transaction, so the change
// and its record commit or fail together; sinks are notified after commit.
func (h *handlers) audited(ctx context.Context, action, objectType, objectID string, details any, fn func(context.Context, store.Tx) error) error {
	p := principalFrom(ctx)
	in := audit.Input{ActorType: audit.ActorUser, ActorID: p.UserID, IP: ipFrom(ctx), Action: action, ObjectType: objectType, ObjectID: objectID, Details: details}
	if p.IsToken() {
		in.ActorType, in.ActorID = audit.ActorToken, p.TokenID
	}
	var e store.AuditEntry
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		if err := fn(ctx, tx); err != nil {
			return err
		}
		var err error
		e, err = h.s.Audit.Append(ctx, tx, in)
		return err
	}); err != nil {
		return err
	}
	h.s.Audit.Deliver(ctx, e)
	return nil
}

func ptrTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// --- events ---

func (h *handlers) ListEvents(ctx context.Context, req apigen.ListEventsRequestObject) (apigen.ListEventsResponseObject, error) {
	cur, err := decodeCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	f := store.EventFilter{}
	if v := req.Params.Site; v != nil {
		f.SiteID = *v
	}
	if v := req.Params.Action; v != nil {
		f.Action = string(*v)
	}
	if v := req.Params.RuleId; v != nil {
		f.RuleID = *v
	}
	if v := req.Params.Ip; v != nil {
		a, err := netip.ParseAddr(*v)
		if err != nil {
			return nil, errBadRequest("ip must be an IP address.")
		}
		f.ClientIP = a.String()
	}
	if v := req.Params.From; v != nil {
		f.From = *v
	}
	if v := req.Params.To; v != nil {
		f.To = *v
	}
	if v := req.Params.Country; v != nil {
		if !countryPattern.MatchString(*v) {
			return nil, errBadRequest("country must be an ISO 3166-1 alpha-2 code in capitals.")
		}
		f.Country = *v
	}
	if v := req.Params.Method; v != nil {
		f.Method = strings.ToUpper(*v)
	}
	if v := req.Params.Status; v != nil {
		f.Status = *v
	}
	if v := req.Params.Mode; v != nil {
		if !slices.Contains([]string{"off", "detect", "block"}, string(*v)) {
			return nil, errBadRequest("mode must be off, detect or block.")
		}
		f.Mode = string(*v)
	}
	if v := req.Params.Q; v != nil {
		f.Text = strings.TrimSpace(*v)
	}
	limit := limitOf(req.Params.Limit)
	var rows []store.EventRow
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		rows, err = tx.ListEvents(ctx, f, cur, limit)
		return err
	}); err != nil {
		return nil, err
	}
	page := apigen.EventPage{Items: make([]apigen.Event, 0, len(rows))}
	for _, r := range rows {
		ev, err := eventDoc(r)
		if err != nil {
			return nil, err
		}
		page.Items = append(page.Items, ev)
	}
	if len(rows) == limit {
		last := rows[len(rows)-1]
		next := encodeCursor(store.Cursor{Time: last.TS, ID: last.ID})
		page.NextCursor = &next
	}
	return apigen.ListEvents200JSONResponse(page), nil
}

func eventDoc(r store.EventRow) (apigen.Event, error) {
	var ev apigen.Event
	if err := json.Unmarshal(r.Body, &ev); err != nil {
		return nil, fmt.Errorf("stored event %s is not valid JSON: %w", r.ID, err)
	}
	return ev, nil
}

func (h *handlers) GetEvent(ctx context.Context, req apigen.GetEventRequestObject) (apigen.GetEventResponseObject, error) {
	var row store.EventRow
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		row, err = tx.GetEvent(ctx, req.Id)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errNotFound("event " + req.Id)
		}
		return nil, err
	}
	ev, err := eventDoc(row)
	if err != nil {
		return nil, err
	}
	return apigen.GetEvent200JSONResponse(ev), nil
}

// --- users ---

func userDTO(u store.User, now time.Time) apigen.User {
	return apigen.User{
		Id: u.ID, Username: u.Username, Role: apigen.UserRole(u.Role), MfaEnabled: u.MFAEnabled, Disabled: u.Disabled,
		Locked: u.LockedUntil.After(now), LastLoginAt: ptrTime(u.LastLoginAt), CreatedAt: u.CreatedAt,
	}
}

func (h *handlers) ListUsers(ctx context.Context, _ apigen.ListUsersRequestObject) (apigen.ListUsersResponseObject, error) {
	var us []store.User
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		us, err = tx.ListUsers(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	now := h.s.Now()
	out := apigen.UserList{Items: make([]apigen.User, 0, len(us))}
	for _, u := range us {
		out.Items = append(out.Items, userDTO(u, now))
	}
	return apigen.ListUsers200JSONResponse(out), nil
}

func validRole(r string) bool { return r == auth.RoleAdmin || r == auth.RoleViewer }

func (h *handlers) CreateUser(ctx context.Context, req apigen.CreateUserRequestObject) (apigen.CreateUserResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	if !usernamePattern.MatchString(b.Username) {
		return nil, errBadRequest("username must be 3-64 characters from A-Z a-z 0-9 . _ -")
	}
	if !validRole(string(b.Role)) {
		return nil, errBadRequest("role must be admin or viewer.")
	}
	if err := auth.ValidatePassword(b.Password); err != nil {
		return nil, err
	}
	hash, err := h.s.Hasher.Hash(ctx, b.Password)
	if err != nil {
		return nil, err
	}
	now := h.s.Now()
	id, err := ids.New(now)
	if err != nil {
		return nil, err
	}
	u := store.User{ID: id, Username: b.Username, PasswordHash: hash, Role: string(b.Role), CreatedAt: now}
	err = h.audited(ctx, "user.create", "user", id, map[string]any{"username": b.Username, "role": b.Role}, func(ctx context.Context, tx store.Tx) error {
		return tx.CreateUser(ctx, u)
	})
	if errors.Is(err, store.ErrConflict) {
		return nil, errConflict("that username is already taken")
	}
	if err != nil {
		return nil, err
	}
	return apigen.CreateUser201JSONResponse(userDTO(u, now)), nil
}

// lastAdminGuard refuses a change that would leave no enabled admin.
func lastAdminGuard(ctx context.Context, tx store.Tx, target store.User) error {
	if target.Role != auth.RoleAdmin || target.Disabled {
		return nil
	}
	us, err := tx.ListUsers(ctx)
	if err != nil {
		return err
	}
	others := 0
	for _, u := range us {
		if u.ID != target.ID && u.Role == auth.RoleAdmin && !u.Disabled {
			others++
		}
	}
	if others == 0 {
		return errConflict("this is the last enabled administrator")
	}
	return nil
}

func (h *handlers) PatchUser(ctx context.Context, req apigen.PatchUserRequestObject) (apigen.PatchUserResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	if b.Role != nil && !validRole(string(*b.Role)) {
		return nil, errBadRequest("role must be admin or viewer.")
	}
	var newHash string
	if b.Password != nil {
		if err := auth.ValidatePassword(*b.Password); err != nil {
			return nil, err
		}
		var err error
		if newHash, err = h.s.Hasher.Hash(ctx, *b.Password); err != nil {
			return nil, err
		}
	}
	changed := map[string]any{}
	var result store.User
	err := h.audited(ctx, "user.update", "user", req.Id, changed, func(ctx context.Context, tx store.Tx) error {
		u, err := tx.UserByID(ctx, req.Id)
		if err != nil {
			return err
		}
		revoke := false
		if b.Role != nil && string(*b.Role) != u.Role {
			if err := lastAdminGuard(ctx, tx, u); err != nil {
				return err
			}
			if err := tx.SetUserRole(ctx, u.ID, string(*b.Role)); err != nil {
				return err
			}
			changed["role"] = string(*b.Role)
			u.Role, revoke = string(*b.Role), true
		}
		if b.Disabled != nil && *b.Disabled != u.Disabled {
			if *b.Disabled {
				if err := lastAdminGuard(ctx, tx, u); err != nil {
					return err
				}
			}
			if err := tx.SetUserDisabled(ctx, u.ID, *b.Disabled); err != nil {
				return err
			}
			changed["disabled"] = *b.Disabled
			u.Disabled, revoke = *b.Disabled, true
		}
		if newHash != "" {
			if err := tx.SetUserPassword(ctx, u.ID, newHash); err != nil {
				return err
			}
			changed["password_changed"] = true
			u.FailedCount, u.LockedUntil, revoke = 0, time.Time{}, true
		}
		if revoke { // a changed credential, role or state ends every live session
			if err := tx.DeleteUserSessions(ctx, u.ID); err != nil {
				return err
			}
		}
		result = u
		return nil
	})
	if err != nil {
		return nil, err
	}
	return apigen.PatchUser200JSONResponse(userDTO(result, h.s.Now())), nil
}

func (h *handlers) DeleteUser(ctx context.Context, req apigen.DeleteUserRequestObject) (apigen.DeleteUserResponseObject, error) {
	if req.Id == principalFrom(ctx).UserID {
		return nil, errConflict("you cannot delete your own account")
	}
	err := h.audited(ctx, "user.delete", "user", req.Id, nil, func(ctx context.Context, tx store.Tx) error {
		u, err := tx.UserByID(ctx, req.Id)
		if err != nil {
			return err
		}
		if err := lastAdminGuard(ctx, tx, u); err != nil {
			return err
		}
		if u.MFASecretID != "" {
			if err := tx.DeleteSecret(ctx, u.MFASecretID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return tx.DeleteUser(ctx, u.ID) // sessions and tokens go with the row (ON DELETE CASCADE)
	})
	if err != nil {
		return nil, err
	}
	return apigen.DeleteUser204Response{}, nil
}

func (h *handlers) ResetUserMFA(ctx context.Context, req apigen.ResetUserMFARequestObject) (apigen.ResetUserMFAResponseObject, error) {
	err := h.audited(ctx, "user.reset_mfa", "user", req.Id, nil, func(ctx context.Context, tx store.Tx) error {
		u, err := tx.UserByID(ctx, req.Id)
		if err != nil {
			return err
		}
		if err := tx.SetUserMFA(ctx, u.ID, "", false); err != nil {
			return err
		}
		if u.MFASecretID != "" {
			if err := tx.DeleteSecret(ctx, u.MFASecretID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return tx.DeleteUserSessions(ctx, u.ID)
	})
	if err != nil {
		return nil, err
	}
	return apigen.ResetUserMFA204Response{}, nil
}

// --- tokens ---

func tokenFields(t store.Token) (scopes, cidrs []string) {
	_ = json.Unmarshal(t.Scopes, &scopes)
	_ = json.Unmarshal(t.CIDRs, &cidrs)
	if scopes == nil {
		scopes = []string{}
	}
	if cidrs == nil {
		cidrs = []string{}
	}
	return scopes, cidrs
}

func tokenDTO(t store.Token) apigen.Token {
	scopes, cidrs := tokenFields(t)
	out := apigen.Token{Id: t.ID, UserId: t.UserID, Name: t.Name, Cidrs: cidrs, ExpiresAt: ptrTime(t.ExpiresAt), LastUsedAt: ptrTime(t.LastUsedAt), CreatedAt: t.CreatedAt}
	for _, s := range scopes {
		out.Scopes = append(out.Scopes, apigen.TokenScopes(s))
	}
	return out
}

func (h *handlers) ListTokens(ctx context.Context, _ apigen.ListTokensRequestObject) (apigen.ListTokensResponseObject, error) {
	p := principalFrom(ctx)
	var ts []store.Token
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		if auth.Has(p.Permissions, auth.PermUsersManage) {
			ts, err = tx.ListTokens(ctx)
		} else {
			ts, err = tx.ListTokensByUser(ctx, p.UserID)
		}
		return err
	}); err != nil {
		return nil, err
	}
	out := apigen.TokenList{Items: make([]apigen.Token, 0, len(ts))}
	for _, t := range ts {
		out.Items = append(out.Items, tokenDTO(t))
	}
	return apigen.ListTokens200JSONResponse(out), nil
}

func (h *handlers) CreateToken(ctx context.Context, req apigen.CreateTokenRequestObject) (apigen.CreateTokenResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	name := strings.TrimSpace(b.Name)
	if name == "" || len(name) > 64 {
		return nil, errBadRequest("name must be 1-64 characters.")
	}
	scopes := make([]string, len(b.Scopes))
	for i, s := range b.Scopes {
		scopes[i] = string(s)
	}
	var cidrs []string
	if b.Cidrs != nil {
		cidrs = *b.Cidrs
	}
	var exp time.Time
	if b.ExpiresAt != nil {
		exp = *b.ExpiresAt
	}
	p := principalFrom(ctx)
	ct, err := h.s.Auth.CreateToken(ctx, p.UserID, name, scopes, cidrs, exp)
	if err != nil {
		return nil, errBadRequest(err.Error())
	}
	if err := h.s.Audit.Record(ctx, h.s.Store, audit.Input{
		ActorType: audit.ActorUser, ActorID: p.UserID, IP: ipFrom(ctx), Action: "token.create", ObjectType: "token", ObjectID: ct.Record.ID,
		Details: map[string]any{"name": name, "scopes": scopes, "cidrs": cidrs},
	}); err != nil {
		return nil, fmt.Errorf("auditing token creation: %w", err)
	}
	dto := tokenDTO(ct.Record)
	out := apigen.CreatedToken{Id: dto.Id, UserId: dto.UserId, Name: dto.Name, Cidrs: dto.Cidrs, ExpiresAt: dto.ExpiresAt, LastUsedAt: dto.LastUsedAt, CreatedAt: dto.CreatedAt, Token: ct.Secret}
	for _, s := range dto.Scopes {
		out.Scopes = append(out.Scopes, apigen.CreatedTokenScopes(s))
	}
	return apigen.CreateToken201JSONResponse(out), nil
}

func (h *handlers) DeleteToken(ctx context.Context, req apigen.DeleteTokenRequestObject) (apigen.DeleteTokenResponseObject, error) {
	p := principalFrom(ctx)
	admin := auth.Has(p.Permissions, auth.PermUsersManage)
	err := h.audited(ctx, "token.revoke", "token", req.Id, nil, func(ctx context.Context, tx store.Tx) error {
		t, err := tx.GetToken(ctx, req.Id)
		if err != nil {
			return err
		}
		if t.UserID != p.UserID && !admin {
			return store.ErrNotFound // do not reveal other users' token ids
		}
		return tx.DeleteToken(ctx, t.ID)
	})
	if err != nil {
		return nil, err
	}
	return apigen.DeleteToken204Response{}, nil
}

// --- audit and system ---

func (h *handlers) ListAudit(ctx context.Context, req apigen.ListAuditRequestObject) (apigen.ListAuditResponseObject, error) {
	var before int64
	if req.Params.BeforeSeq != nil {
		before = *req.Params.BeforeSeq
	}
	limit := limitOf(req.Params.Limit)
	var es []store.AuditEntry
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		es, err = tx.ListAudit(ctx, before, limit)
		return err
	}); err != nil {
		return nil, err
	}
	page := apigen.AuditPage{Items: make([]apigen.AuditEntry, 0, len(es))}
	for _, e := range es {
		item := apigen.AuditEntry{Seq: e.Seq, Id: e.ID, At: e.At, ActorType: e.ActorType, ActorId: e.ActorID, Action: e.Action, Hash: e.Hash}
		if e.IP != "" {
			item.Ip = &e.IP
		}
		if e.ObjectType != "" {
			item.ObjectType, item.ObjectId = &e.ObjectType, &e.ObjectID
		}
		if len(e.Details) > 0 {
			var d map[string]any
			if json.Unmarshal(e.Details, &d) == nil {
				item.Details = &d
			}
		}
		page.Items = append(page.Items, item)
	}
	if len(es) == limit {
		next := es[len(es)-1].Seq
		page.NextBeforeSeq = &next
	}
	return apigen.ListAudit200JSONResponse(page), nil
}

func (h *handlers) GetSystemInfo(ctx context.Context, _ apigen.GetSystemInfoRequestObject) (apigen.GetSystemInfoResponseObject, error) {
	in := h.s.Info
	features := slices.Clone(in.Features)
	if features == nil {
		features = []string{}
	}
	out := apigen.SystemInfo{
		Version: in.Version, CrsVersion: in.CRSVersion, Features: features, Ready: h.s.Config.Ready(),
		Database: apigen.SystemInfoDatabase(h.s.Store.Dialect()),
	}
	if in.Commit != "" {
		out.Commit = &in.Commit
	}
	if head := h.s.Config.Head(); head != "" {
		out.ConfigVersion = &head
	}
	cp, err := audit.Head(ctx, h.s.Store)
	if err != nil {
		return nil, fmt.Errorf("reading audit head: %w", err)
	}
	out.AuditHead = &struct {
		Hash *string `json:"hash,omitempty"`
		Seq  *int64  `json:"seq,omitempty"`
	}{Hash: &cp.Hash, Seq: &cp.Seq}
	return apigen.GetSystemInfo200JSONResponse(out), nil
}
