package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

func actorOf(ctx context.Context) configsvc.Actor {
	p := principalFrom(ctx)
	a := configsvc.Actor{Type: audit.ActorUser, ID: p.UserID, IP: ipFrom(ctx)}
	if p.IsToken() {
		a.Type, a.ID = audit.ActorToken, p.TokenID
	}
	return a
}

func etag(id string) *string { s := configsvc.ETag(id); return &s }

// cloneRoot deep-copies the live configuration so handlers can edit it; the
// service hands out its active pointer and must never see it mutated.
func cloneRoot(r *config.Root) (*config.Root, error) {
	b, err := config.Snapshot(r)
	if err != nil {
		return nil, fmt.Errorf("snapshotting configuration: %w", err)
	}
	return config.FromSnapshot(b)
}

func versionDTO(v store.ConfigVersion) apigen.Version {
	out := apigen.Version{
		Id: v.ID, ParentId: v.ParentID, CreatedAt: v.CreatedAt, AuthorType: v.AuthorType, AuthorId: v.AuthorID,
		Source: apigen.VersionSource(v.Source), SchemaVersion: v.SchemaVersion, Applied: v.Applied,
	}
	if len(v.Diff) > 0 {
		var d map[string]any
		if json.Unmarshal(v.Diff, &d) == nil {
			out.Diff = &d
		}
	}
	return out
}

func versionResponse(v store.ConfigVersion) apigen.ConfigVersionJSONResponse {
	return apigen.ConfigVersionJSONResponse{Body: versionDTO(v), Headers: apigen.ConfigVersionResponseHeaders{ETag: etag(v.ID)}}
}

func ifMatch(p *string) (id string, present bool, err error) {
	if p == nil {
		return "", false, nil
	}
	id, present, err = configsvc.ParseIfMatch(*p)
	if err != nil {
		return "", false, errBadRequest("If-Match must be a single ETag from a previous response.")
	}
	return id, present, nil
}

// mutate applies fn to a copy of the live configuration and activates the
// result. If-Match is checked by the service against the head it applies to.
func (h *handlers) mutate(ctx context.Context, match *string, fn func(*config.Root) error) (store.ConfigVersion, error) {
	expected, present, err := ifMatch(match)
	if err != nil {
		return store.ConfigVersion{}, err
	}
	_, live, err := h.s.Config.Current(ctx)
	if err != nil {
		return store.ConfigVersion{}, err
	}
	next, err := cloneRoot(live)
	if err != nil {
		return store.ConfigVersion{}, err
	}
	if err := fn(next); err != nil {
		return store.ConfigVersion{}, err
	}
	return h.s.Config.Apply(ctx, configsvc.Request{Root: next, Expected: expected, Conditional: present, Actor: actorOf(ctx), Source: configsvc.SourceAPI})
}

func (h *handlers) current(ctx context.Context) (store.ConfigVersion, *config.Root, error) {
	return h.s.Config.Current(ctx)
}

func (h *handlers) GetConfig(ctx context.Context, _ apigen.GetConfigRequestObject) (apigen.GetConfigResponseObject, error) {
	v, root, err := h.current(ctx)
	if err != nil {
		return nil, err
	}
	return apigen.GetConfig200JSONResponse{Body: *root, Headers: apigen.GetConfig200ResponseHeaders{ETag: etag(v.ID)}}, nil
}

func (h *handlers) PutConfig(ctx context.Context, req apigen.PutConfigRequestObject) (apigen.PutConfigResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	expected, present, err := ifMatch(req.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	v, err := h.s.Config.Apply(ctx, configsvc.Request{Root: req.Body, Expected: expected, Conditional: present, Actor: actorOf(ctx), Source: configsvc.SourceAPI})
	if err != nil {
		return nil, err
	}
	return apigen.PutConfig200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

func validationErrors(errs config.Errors) []apigen.ValidationError {
	out := make([]apigen.ValidationError, 0, len(errs))
	for _, e := range errs {
		out = append(out, apigen.ValidationError{Path: e.Path, Code: e.Code, Message: e.Message})
	}
	return out
}

func (h *handlers) ValidateConfig(ctx context.Context, req apigen.ValidateConfigRequestObject) (apigen.ValidateConfigResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	errs := h.s.Config.Check(ctx, req.Body)
	return apigen.ValidateConfig200JSONResponse{Valid: len(errs) == 0, Errors: validationErrors(errs)}, nil
}

// Page cursors are opaque to clients: base64url of "<rfc3339nano>|<id>".
func encodeCursor(c store.Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.Time.UTC().Format(time.RFC3339Nano) + "|" + c.ID))
}

func decodeCursor(s *string) (store.Cursor, error) {
	if s == nil || *s == "" {
		return store.Cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(*s)
	ts, id, ok := strings.Cut(string(raw), "|")
	if err != nil || !ok || id == "" {
		return store.Cursor{}, errBadRequest("cursor is not valid.")
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return store.Cursor{}, errBadRequest("cursor is not valid.")
	}
	return store.Cursor{Time: t, ID: id}, nil
}

func limitOf(l *int) int {
	switch {
	case l == nil:
		return 50
	case *l < 1:
		return 1
	case *l > 1000:
		return 1000
	}
	return *l
}

func (h *handlers) ListConfigVersions(ctx context.Context, req apigen.ListConfigVersionsRequestObject) (apigen.ListConfigVersionsResponseObject, error) {
	cur, err := decodeCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := limitOf(req.Params.Limit)
	vs, err := h.s.Config.Versions(ctx, cur, limit)
	if err != nil {
		return nil, err
	}
	page := apigen.VersionPage{Items: make([]apigen.Version, 0, len(vs))}
	for _, v := range vs {
		page.Items = append(page.Items, versionDTO(v))
	}
	if len(vs) == limit {
		last := vs[len(vs)-1]
		next := encodeCursor(store.Cursor{Time: last.CreatedAt, ID: last.ID})
		page.NextCursor = &next
	}
	return apigen.ListConfigVersions200JSONResponse(page), nil
}

func (h *handlers) GetConfigVersion(ctx context.Context, req apigen.GetConfigVersionRequestObject) (apigen.GetConfigVersionResponseObject, error) {
	v, err := h.s.Config.Version(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	snap, err := config.FromSnapshot(v.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("reading stored snapshot %s: %w", v.ID, err)
	}
	d := versionDTO(v)
	return apigen.GetConfigVersion200JSONResponse{
		Id: d.Id, ParentId: d.ParentId, CreatedAt: d.CreatedAt, AuthorType: d.AuthorType, AuthorId: d.AuthorId,
		Source: apigen.VersionDetailSource(d.Source), SchemaVersion: d.SchemaVersion, Applied: d.Applied, Diff: d.Diff, Snapshot: *snap,
	}, nil
}

func (h *handlers) RollbackConfig(ctx context.Context, req apigen.RollbackConfigRequestObject) (apigen.RollbackConfigResponseObject, error) {
	expected, present, err := ifMatch(req.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	v, err := h.s.Config.Rollback(ctx, req.Id, configsvc.Request{Expected: expected, Conditional: present, Actor: actorOf(ctx), Source: configsvc.SourceRollback})
	if err != nil {
		return nil, err
	}
	return apigen.RollbackConfig200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

func (h *handlers) GetDefaults(ctx context.Context, _ apigen.GetDefaultsRequestObject) (apigen.GetDefaultsResponseObject, error) {
	v, root, err := h.current(ctx)
	if err != nil {
		return nil, err
	}
	return apigen.GetDefaults200JSONResponse{Body: root.Global.Defaults, Headers: apigen.GetDefaults200ResponseHeaders{ETag: etag(v.ID)}}, nil
}

func (h *handlers) PutDefaults(ctx context.Context, req apigen.PutDefaultsRequestObject) (apigen.PutDefaultsResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		r.Global.Defaults = *req.Body
		return nil
	})
	if err != nil {
		return nil, err
	}
	return apigen.PutDefaults200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

// --- sites ---

func findSite(r *config.Root, id string) int {
	for i := range r.Sites {
		if r.Sites[i].ID == id {
			return i
		}
	}
	return -1
}

func findEndpoint(s *config.Site, id string) int {
	for i := range s.Endpoints {
		if s.Endpoints[i].ID == id {
			return i
		}
	}
	return -1
}

func (h *handlers) ListSites(ctx context.Context, _ apigen.ListSitesRequestObject) (apigen.ListSitesResponseObject, error) {
	v, root, err := h.current(ctx)
	if err != nil {
		return nil, err
	}
	items := root.Sites
	if items == nil {
		items = []config.Site{}
	}
	return apigen.ListSites200JSONResponse{Body: apigen.SiteList{Items: items}, Headers: apigen.ListSites200ResponseHeaders{ETag: etag(v.ID)}}, nil
}

func (h *handlers) CreateSite(ctx context.Context, req apigen.CreateSiteRequestObject) (apigen.CreateSiteResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		if findSite(r, req.Body.ID) >= 0 {
			return errConflict(fmt.Sprintf("site %q already exists", req.Body.ID))
		}
		r.Sites = append(r.Sites, *req.Body)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return apigen.CreateSite201JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

func (h *handlers) GetSite(ctx context.Context, req apigen.GetSiteRequestObject) (apigen.GetSiteResponseObject, error) {
	v, root, err := h.current(ctx)
	if err != nil {
		return nil, err
	}
	i := findSite(root, req.Site)
	if i < 0 {
		return nil, errNotFound("site " + req.Site)
	}
	return apigen.GetSite200JSONResponse{Body: root.Sites[i], Headers: apigen.GetSite200ResponseHeaders{ETag: etag(v.ID)}}, nil
}

func (h *handlers) DeleteSite(ctx context.Context, req apigen.DeleteSiteRequestObject) (apigen.DeleteSiteResponseObject, error) {
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		r.Sites = slices.Delete(r.Sites, i, i+1)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return apigen.DeleteSite200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

func (h *handlers) PatchSite(ctx context.Context, req apigen.PatchSiteRequestObject) (apigen.PatchSiteResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		return patchInto(&r.Sites[i], map[string]any(*req.Body), req.Site)
	})
	if err != nil {
		return nil, err
	}
	return apigen.PatchSite200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

// patchInto applies an RFC 7386 JSON Merge Patch to target (a *config.Site or
// *config.Endpoint). Unknown fields are rejected and the id may not change.
func patchInto[T config.Site | config.Endpoint](target *T, patch map[string]any, id string) error {
	raw, err := json.Marshal(target)
	if err != nil {
		return fmt.Errorf("encoding object: %w", err)
	}
	doc := map[string]any{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("decoding object: %w", err)
	}
	if v, ok := patch["id"]; ok && v != id {
		return errUnprocessed("the id of an object cannot be changed")
	}
	mergePatch(doc, patch)
	merged, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding patched object: %w", err)
	}
	var out T
	dec := json.NewDecoder(bytes.NewReader(merged))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return errUnprocessed("the patch does not produce a valid object: " + err.Error())
	}
	*target = out
	return nil
}

func mergePatch(target, patch map[string]any) {
	for k, v := range patch {
		switch pv := v.(type) {
		case nil:
			delete(target, k)
		case map[string]any:
			tm, _ := target[k].(map[string]any)
			if tm == nil {
				tm = map[string]any{}
			}
			mergePatch(tm, pv)
			target[k] = tm
		default:
			target[k] = v
		}
	}
}

// --- endpoints ---

func (h *handlers) ListEndpoints(ctx context.Context, req apigen.ListEndpointsRequestObject) (apigen.ListEndpointsResponseObject, error) {
	v, root, err := h.current(ctx)
	if err != nil {
		return nil, err
	}
	i := findSite(root, req.Site)
	if i < 0 {
		return nil, errNotFound("site " + req.Site)
	}
	items := root.Sites[i].Endpoints
	if items == nil {
		items = []config.Endpoint{}
	}
	return apigen.ListEndpoints200JSONResponse{Body: apigen.EndpointList{Items: items}, Headers: apigen.ListEndpoints200ResponseHeaders{ETag: etag(v.ID)}}, nil
}

func (h *handlers) CreateEndpoint(ctx context.Context, req apigen.CreateEndpointRequestObject) (apigen.CreateEndpointResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		if findEndpoint(&r.Sites[i], req.Body.ID) >= 0 {
			return errConflict(fmt.Sprintf("endpoint %q already exists on site %q", req.Body.ID, req.Site))
		}
		r.Sites[i].Endpoints = append(r.Sites[i].Endpoints, *req.Body)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return apigen.CreateEndpoint201JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

func (h *handlers) GetEndpoint(ctx context.Context, req apigen.GetEndpointRequestObject) (apigen.GetEndpointResponseObject, error) {
	v, root, err := h.current(ctx)
	if err != nil {
		return nil, err
	}
	i := findSite(root, req.Site)
	if i < 0 {
		return nil, errNotFound("site " + req.Site)
	}
	j := findEndpoint(&root.Sites[i], req.Endpoint)
	if j < 0 {
		return nil, errNotFound("endpoint " + req.Endpoint)
	}
	return apigen.GetEndpoint200JSONResponse{Body: root.Sites[i].Endpoints[j], Headers: apigen.GetEndpoint200ResponseHeaders{ETag: etag(v.ID)}}, nil
}

func (h *handlers) PatchEndpoint(ctx context.Context, req apigen.PatchEndpointRequestObject) (apigen.PatchEndpointResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		j := findEndpoint(&r.Sites[i], req.Endpoint)
		if j < 0 {
			return errNotFound("endpoint " + req.Endpoint)
		}
		return patchInto(&r.Sites[i].Endpoints[j], map[string]any(*req.Body), req.Endpoint)
	})
	if err != nil {
		return nil, err
	}
	return apigen.PatchEndpoint200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

func (h *handlers) DeleteEndpoint(ctx context.Context, req apigen.DeleteEndpointRequestObject) (apigen.DeleteEndpointResponseObject, error) {
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		j := findEndpoint(&r.Sites[i], req.Endpoint)
		if j < 0 {
			return errNotFound("endpoint " + req.Endpoint)
		}
		r.Sites[i].Endpoints = slices.Delete(r.Sites[i].Endpoints, j, j+1)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return apigen.DeleteEndpoint200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

func (h *handlers) GetEffectivePolicy(ctx context.Context, req apigen.GetEffectivePolicyRequestObject) (apigen.GetEffectivePolicyResponseObject, error) {
	reqPath, method := "/", http.MethodGet
	if req.Params.Path != nil {
		reqPath = *req.Params.Path
	}
	if req.Params.Method != nil {
		method = strings.ToUpper(*req.Params.Method)
	}
	if !strings.HasPrefix(reqPath, "/") {
		return nil, errBadRequest("path must start with /.")
	}
	_, root, err := h.current(ctx)
	if err != nil {
		return nil, err
	}
	i := findSite(root, req.Site)
	if i < 0 {
		return nil, errNotFound("site " + req.Site)
	}
	site := &root.Sites[i]
	ep := site.MatchEndpoint(reqPath, method)
	eff := root.EffectivePolicy(site, ep)

	raw, err := json.Marshal(eff)
	if err != nil {
		return nil, fmt.Errorf("encoding effective policy: %w", err)
	}
	pol := map[string]any{}
	if err := json.Unmarshal(raw, &pol); err != nil {
		return nil, fmt.Errorf("decoding effective policy: %w", err)
	}
	delete(pol, "sources")
	out := apigen.EffectivePolicy{Site: req.Site, Path: &reqPath, Method: &method, Policy: pol, Sources: eff.Sources}
	if out.Sources == nil {
		out.Sources = map[string]string{}
	}
	if ep != nil {
		out.MatchedEndpoint = &ep.ID
	}
	return apigen.GetEffectivePolicy200JSONResponse(out), nil
}
