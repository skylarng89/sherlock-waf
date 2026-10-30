package api

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	dpapi "github.com/skylarng89/sherlock-waf/internal/dataplane/api"
	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const (
	endpointCountRows  = 2000
	maxCABundleCerts   = 20
	defaultEndpointWin = 24 * time.Hour
)

// --- OpenAPI documents ---

func apiDocDTO(d store.OpenAPIDoc, endpoints int) apigen.APIDoc {
	return apigen.APIDoc{Id: d.ID, Name: d.Name, Version: apigen.APIDocVersion(d.Version), Sha256: d.SHA256, EndpointCount: endpoints, UpdatedAt: d.UpdatedAt}
}

func (h *handlers) ListAPIDocs(ctx context.Context, _ apigen.ListAPIDocsRequestObject) (apigen.ListAPIDocsResponseObject, error) {
	var docs []store.OpenAPIDoc
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		docs, err = tx.ListOpenAPIDocs(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	out := apigen.APIDocList{Items: make([]apigen.APIDoc, 0, len(docs))}
	for _, d := range docs {
		n := 0
		if sp := dpapi.Specs.Get(d.ID); sp != nil {
			n = len(sp.Endpoints)
		}
		out.Items = append(out.Items, apiDocDTO(d, n))
	}
	return apigen.ListAPIDocs200JSONResponse(out), nil
}

func (h *handlers) PutAPIDoc(ctx context.Context, req apigen.PutAPIDocRequestObject) (apigen.PutAPIDocResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	if !blockPageID.MatchString(req.Id) {
		return nil, errBadRequest("the id must be a slug: lower-case letters, digits and hyphens.")
	}
	name := strings.TrimSpace(req.Body.Name)
	if name == "" || len(name) > 64 {
		return nil, errBadRequest("name must be 1-64 characters.")
	}
	// Compile first: a document that does not compile is never stored, and the
	// copy the data plane runs is replaced only after the store accepted it.
	spec, err := dpapi.CompileSpec(ctx, []byte(req.Body.Content))
	if err != nil {
		return nil, errUnprocessed(err.Error())
	}
	sum := sha256.Sum256([]byte(req.Body.Content))
	doc := store.OpenAPIDoc{
		ID: req.Id, Name: name, Version: spec.Version, SHA256: hex.EncodeToString(sum[:]),
		Body: req.Body.Content, UpdatedAt: h.s.Now().UTC().Truncate(time.Microsecond),
	}
	err = h.audited(ctx, "api_doc.put", "api_doc", req.Id, map[string]any{"sha256": doc.SHA256, "endpoints": len(spec.Endpoints)}, func(ctx context.Context, tx store.Tx) error {
		return tx.PutOpenAPIDoc(ctx, doc)
	})
	if err != nil {
		return nil, err
	}
	if _, err := dpapi.Specs.Set(ctx, req.Id, []byte(doc.Body)); err != nil { // compiled above; cannot fail
		return nil, fmt.Errorf("loading OpenAPI document into the data plane: %w", err)
	}
	return apigen.PutAPIDoc200JSONResponse(apiDocDTO(doc, len(spec.Endpoints))), nil
}

func (h *handlers) DeleteAPIDoc(ctx context.Context, req apigen.DeleteAPIDocRequestObject) (apigen.DeleteAPIDocResponseObject, error) {
	if used := h.usedBy(ctx, func(r config.Refs) []string { return r.OpenAPIDocs[req.Id] }); len(used) > 0 {
		return nil, errConflict("the OpenAPI document is in use by " + strings.Join(used, ", "))
	}
	err := h.audited(ctx, "api_doc.delete", "api_doc", req.Id, nil, func(ctx context.Context, tx store.Tx) error {
		return tx.DeleteOpenAPIDoc(ctx, req.Id)
	})
	if err != nil {
		return nil, err
	}
	dpapi.Specs.Delete(req.Id)
	return apigen.DeleteAPIDoc204Response{}, nil
}

func (h *handlers) ListAPIDocEndpoints(ctx context.Context, req apigen.ListAPIDocEndpointsRequestObject) (apigen.ListAPIDocEndpointsResponseObject, error) {
	spec := dpapi.Specs.Get(req.Id)
	if spec == nil {
		return nil, errNotFound("No such OpenAPI document.")
	}
	to := h.s.Now().UTC()
	if req.Params.To != nil {
		to = req.Params.To.UTC()
	}
	from := to.Add(-defaultEndpointWin)
	if req.Params.From != nil {
		from = req.Params.From.UTC()
	}
	if !from.Before(to) {
		return nil, errBadRequest("from must be before to.")
	}
	var schema, unknown []store.EndpointCount
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		if schema, err = tx.CountEventsByEndpoint(ctx, req.Params.Site, "api.schema", from, to, endpointCountRows); err != nil {
			return err
		}
		unknown, err = tx.CountEventsByEndpoint(ctx, req.Params.Site, "api.unknown_endpoint", from, to, endpointCountRows)
		return err
	}); err != nil {
		return nil, err
	}

	type key struct{ method, path string }
	violations := map[key]int64{}
	for _, c := range schema {
		if tmpl, ok := spec.Template(ctx, c.Method, c.Path); ok {
			violations[key{strings.ToUpper(c.Method), tmpl}] += c.Count
		}
	}
	out := apigen.APIEndpointList{Items: make([]apigen.APIEndpoint, 0, len(spec.Endpoints)), Undocumented: []apigen.APIUndocumented{}}
	for _, e := range spec.Endpoints {
		item := apigen.APIEndpoint{Method: e.Method, Path: e.Path, SchemaViolations: violations[key{e.Method, e.Path}]}
		if e.Summary != "" {
			item.Summary = &e.Summary
		}
		out.Items = append(out.Items, item)
	}
	for _, c := range unknown {
		out.Undocumented = append(out.Undocumented, apigen.APIUndocumented{Method: c.Method, Path: c.Path, Count: c.Count})
	}
	return apigen.ListAPIDocEndpoints200JSONResponse(out), nil
}

// --- CA bundles ---

func caBundleDTO(b store.CABundle) apigen.CABundle {
	subjects := b.Subjects
	if subjects == nil {
		subjects = []string{}
	}
	return apigen.CABundle{Id: b.ID, Name: b.Name, Subjects: subjects, FingerprintSha256: b.Fingerprint, NotAfter: b.NotAfter, CreatedAt: b.CreatedAt}
}

func (h *handlers) ListCABundles(ctx context.Context, _ apigen.ListCABundlesRequestObject) (apigen.ListCABundlesResponseObject, error) {
	var bs []store.CABundle
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		bs, err = tx.ListCABundles(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	out := apigen.CABundleList{Items: make([]apigen.CABundle, 0, len(bs))}
	for _, b := range bs {
		out.Items = append(out.Items, caBundleDTO(b))
	}
	return apigen.ListCABundles200JSONResponse(out), nil
}

var errCABundle = errors.New("invalid CA bundle")

// parseCABundle accepts only CA certificates. A private key in the upload is
// refused outright: the field exists for public material and a pasted key
// would otherwise sit in the database unencrypted.
func parseCABundle(pemData string, now time.Time) (subjects []string, fingerprint string, notAfter time.Time, normalised string, err error) {
	h := sha256.New()
	var out strings.Builder
	rest := []byte(pemData)
	n := 0
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if strings.Contains(blk.Type, "PRIVATE KEY") {
			return nil, "", time.Time{}, "", fmt.Errorf("%w: remove the private key; only CA certificates are accepted", errCABundle)
		}
		if blk.Type != "CERTIFICATE" {
			return nil, "", time.Time{}, "", fmt.Errorf("%w: unexpected PEM block %q", errCABundle, blk.Type)
		}
		c, perr := x509.ParseCertificate(blk.Bytes)
		if perr != nil {
			return nil, "", time.Time{}, "", fmt.Errorf("%w: %v", errCABundle, perr)
		}
		switch {
		case !c.IsCA || !c.BasicConstraintsValid:
			return nil, "", time.Time{}, "", fmt.Errorf("%w: %q is not a CA certificate", errCABundle, c.Subject.String())
		case now.After(c.NotAfter):
			return nil, "", time.Time{}, "", fmt.Errorf("%w: %q expired on %s", errCABundle, c.Subject.String(), c.NotAfter.UTC().Format(time.DateOnly))
		case now.Before(c.NotBefore):
			return nil, "", time.Time{}, "", fmt.Errorf("%w: %q is not valid yet", errCABundle, c.Subject.String())
		}
		if n++; n > maxCABundleCerts {
			return nil, "", time.Time{}, "", fmt.Errorf("%w: at most %d certificates", errCABundle, maxCABundleCerts)
		}
		subjects = append(subjects, c.Subject.String())
		h.Write(blk.Bytes)
		if notAfter.IsZero() || c.NotAfter.Before(notAfter) {
			notAfter = c.NotAfter
		}
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
	}
	if n == 0 {
		return nil, "", time.Time{}, "", fmt.Errorf("%w: no PEM certificate found", errCABundle)
	}
	slices.Sort(subjects)
	return subjects, hex.EncodeToString(h.Sum(nil)), notAfter.UTC().Truncate(time.Microsecond), out.String(), nil
}

func (h *handlers) UploadCABundle(ctx context.Context, req apigen.UploadCABundleRequestObject) (apigen.UploadCABundleResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	name := strings.TrimSpace(req.Body.Name)
	if name == "" || len(name) > 64 {
		return nil, errBadRequest("name must be 1-64 characters.")
	}
	now := h.s.Now().UTC().Truncate(time.Microsecond)
	subjects, fp, notAfter, normalised, err := parseCABundle(req.Body.CertificatesPem, now)
	if err != nil {
		return nil, errBadRequest(strings.TrimPrefix(err.Error(), errCABundle.Error()+": "))
	}
	id, err := ids.New(now)
	if err != nil {
		return nil, err
	}
	b := store.CABundle{ID: id, Name: name, Subjects: subjects, Fingerprint: fp, PEM: normalised, NotAfter: notAfter, CreatedAt: now}
	err = h.audited(ctx, "ca_bundle.upload", "ca_bundle", id, map[string]any{"fingerprint": fp}, func(ctx context.Context, tx store.Tx) error {
		return tx.InsertCABundle(ctx, b)
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return nil, errConflict("that CA bundle already exists")
	case err != nil:
		return nil, err
	}
	return apigen.UploadCABundle201JSONResponse(caBundleDTO(b)), nil
}

func (h *handlers) DeleteCABundle(ctx context.Context, req apigen.DeleteCABundleRequestObject) (apigen.DeleteCABundleResponseObject, error) {
	if used := h.usedBy(ctx, func(r config.Refs) []string { return r.CACerts[req.Id] }); len(used) > 0 {
		return nil, errConflict("the CA bundle is in use by " + strings.Join(used, ", "))
	}
	err := h.audited(ctx, "ca_bundle.delete", "ca_bundle", req.Id, nil, func(ctx context.Context, tx store.Tx) error {
		return tx.DeleteCABundle(ctx, req.Id)
	})
	if err != nil {
		return nil, err
	}
	return apigen.DeleteCABundle204Response{}, nil
}
