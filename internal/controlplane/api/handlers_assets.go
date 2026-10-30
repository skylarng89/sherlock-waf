package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/certstore"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// --- certificates ---

func certificateDTO(c store.Certificate) apigen.Certificate {
	hosts := c.Hosts
	if hosts == nil {
		hosts = []string{}
	}
	return apigen.Certificate{
		Id: c.ID, Name: c.Name, Hosts: hosts, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Issuer: c.Issuer,
		FingerprintSha256: c.Fingerprint, CreatedAt: c.CreatedAt,
	}
}

func (h *handlers) ListCertificates(ctx context.Context, _ apigen.ListCertificatesRequestObject) (apigen.ListCertificatesResponseObject, error) {
	var cs []store.Certificate
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		cs, err = tx.ListCertificates(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	out := apigen.CertificateList{Items: make([]apigen.Certificate, 0, len(cs))}
	for _, c := range cs {
		out.Items = append(out.Items, certificateDTO(c))
	}
	return apigen.ListCertificates200JSONResponse(out), nil
}

func (h *handlers) UploadCertificate(ctx context.Context, req apigen.UploadCertificateRequestObject) (apigen.UploadCertificateResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	name := strings.TrimSpace(b.Name)
	if name == "" || len(name) > 64 {
		return nil, errBadRequest("name must be 1-64 characters.")
	}
	var c store.Certificate
	err := h.audited(ctx, "certificate.upload", "certificate", "", nil, func(ctx context.Context, tx store.Tx) (err error) {
		c, err = certstore.Add(ctx, tx, h.s.Secrets, name, b.CertificatePem, b.PrivateKeyPem, h.s.Now())
		return err
	})
	switch {
	case errors.Is(err, certstore.ErrInvalid):
		return nil, errBadRequest(strings.TrimPrefix(err.Error(), certstore.ErrInvalid.Error()+": "))
	case errors.Is(err, store.ErrConflict):
		return nil, errConflict(fmt.Sprintf("a certificate named %q already exists", name))
	case err != nil:
		return nil, err
	}
	return apigen.UploadCertificate201JSONResponse(certificateDTO(c)), nil
}

func (h *handlers) DeleteCertificate(ctx context.Context, req apigen.DeleteCertificateRequestObject) (apigen.DeleteCertificateResponseObject, error) {
	if used := h.usedBy(ctx, func(r config.Refs) []string { return r.Certificates[req.Id] }); len(used) > 0 {
		return nil, errConflict("the certificate is in use by " + strings.Join(used, ", "))
	}
	err := h.audited(ctx, "certificate.delete", "certificate", req.Id, nil, func(ctx context.Context, tx store.Tx) error {
		return certstore.Remove(ctx, tx, req.Id)
	})
	if err != nil {
		return nil, err
	}
	if h.s.Certs != nil {
		h.s.Certs.Delete(req.Id)
	}
	return apigen.DeleteCertificate204Response{}, nil
}

// usedBy lists where the live configuration references an object.
func (h *handlers) usedBy(ctx context.Context, pick func(config.Refs) []string) []string {
	_, live, err := h.s.Config.Current(ctx)
	if err != nil {
		return nil // no configuration yet: nothing can reference it
	}
	return pick(live.References())
}

func (h *handlers) GetACMEStatus(ctx context.Context, _ apigen.GetACMEStatusRequestObject) (apigen.GetACMEStatusResponseObject, error) {
	out := apigen.ACMEStatusList{Items: []apigen.ACMEStatus{}}
	_, live, err := h.s.Config.Current(ctx)
	if errors.Is(err, configsvc.ErrNotFound) {
		return apigen.GetACMEStatus200JSONResponse(out), nil // no configuration yet
	}
	if err != nil {
		return nil, err
	}
	var uploaded map[string]store.Certificate
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		cs, err := tx.ListCertificates(ctx)
		uploaded = make(map[string]store.Certificate, len(cs))
		for _, c := range cs {
			uploaded[c.ID] = c
		}
		return err
	}); err != nil {
		return nil, err
	}
	for _, s := range live.Sites {
		for _, host := range s.Hosts {
			item := apigen.ACMEStatus{Site: s.ID, Host: host}
			switch {
			case s.TLS.Mode == config.TLSACME:
				exp, ok := acmeCertExpiry(h.s.DataDir, host)
				if ok {
					item.State, item.NotAfter = apigen.ACMEStatusStateIssued, &exp
				} else {
					item.State = apigen.ACMEStatusStatePending
					item.Detail = ptr("No certificate yet. The host must resolve to this node and ports 80 and 443 must be reachable from the internet.")
				}
			case s.TLS.Mode == config.TLSFile && s.TLS.CertID != "":
				c, ok := uploaded[s.TLS.CertID]
				if !ok {
					item.State, item.Detail = apigen.ACMEStatusStateFailed, ptr("The uploaded certificate no longer exists.")
				} else {
					item.State, item.NotAfter = apigen.ACMEStatusStateIssued, &c.NotAfter
					item.Detail = ptr("Uploaded certificate " + c.Name)
					if !slices.Contains(c.Hosts, host) && !wildcardCovers(c.Hosts, host) {
						item.State, item.Detail = apigen.ACMEStatusStateFailed, ptr("The uploaded certificate does not list this host.")
					}
				}
			default:
				item.State = apigen.ACMEStatusStateNotApplicable
			}
			out.Items = append(out.Items, item)
		}
	}
	return apigen.GetACMEStatus200JSONResponse(out), nil
}

func ptr[T any](v T) *T { return &v }

func wildcardCovers(names []string, host string) bool {
	_, rest, ok := strings.Cut(host, ".")
	return ok && slices.Contains(names, "*."+rest)
}

// acmeCertExpiry finds the certificate Caddy obtained for host under its
// storage layout (certificates/<issuer>/<host>/<host>.crt) and returns its expiry.
func acmeCertExpiry(dataDir, host string) (time.Time, bool) {
	if dataDir == "" || strings.ContainsAny(host, `/\`) || strings.HasPrefix(host, ".") {
		return time.Time{}, false
	}
	matches, _ := filepath.Glob(filepath.Join(dataDir, "certificates", "*", host, host+".crt"))
	var best time.Time
	for _, m := range matches {
		raw, err := os.ReadFile(m) //nolint:gosec // path built from the data dir and a validated host name
		if err != nil {
			continue
		}
		blk, _ := pem.Decode(raw)
		if blk == nil {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err == nil && c.NotAfter.After(best) {
			best = c.NotAfter
		}
	}
	return best, !best.IsZero()
}

// --- block pages ---

var blockPageID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (h *handlers) ListBlockPages(ctx context.Context, _ apigen.ListBlockPagesRequestObject) (apigen.ListBlockPagesResponseObject, error) {
	var ps []store.BlockPage
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		ps, err = tx.ListBlockPages(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	out := apigen.BlockPageList{Items: make([]apigen.BlockPage, 0, len(ps))}
	for _, p := range ps {
		out.Items = append(out.Items, apigen.BlockPage{Id: p.ID, UpdatedAt: p.UpdatedAt, SizeBytes: len(p.HTML)})
	}
	return apigen.ListBlockPages200JSONResponse(out), nil
}

func (h *handlers) PutBlockPage(ctx context.Context, req apigen.PutBlockPageRequestObject) (apigen.PutBlockPageResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	if !blockPageID.MatchString(req.Id) {
		return nil, errBadRequest("the id must be a slug: lower-case letters, digits and hyphens.")
	}
	if req.Id == config.DefaultBlockPageTemplate {
		return nil, errBadRequest(`"default" is the built-in page and cannot be replaced.`)
	}
	if err := blockpage.ValidateTemplate(req.Body.Html); err != nil {
		return nil, errUnprocessed(err.Error())
	}
	page := store.BlockPage{ID: req.Id, HTML: req.Body.Html, UpdatedAt: h.s.Now().UTC().Truncate(time.Microsecond)}
	err := h.audited(ctx, "block_page.put", "block_page", req.Id, map[string]any{"size_bytes": len(page.HTML)}, func(ctx context.Context, tx store.Tx) error {
		return tx.PutBlockPage(ctx, page)
	})
	if err != nil {
		return nil, err
	}
	if err := blockpage.SetTemplate(req.Id, page.HTML); err != nil { // validated above; cannot fail
		return nil, fmt.Errorf("loading block page into the data plane: %w", err)
	}
	return apigen.PutBlockPage200JSONResponse(apigen.BlockPage{Id: page.ID, UpdatedAt: page.UpdatedAt, SizeBytes: len(page.HTML)}), nil
}

func (h *handlers) DeleteBlockPage(ctx context.Context, req apigen.DeleteBlockPageRequestObject) (apigen.DeleteBlockPageResponseObject, error) {
	if used := h.usedBy(ctx, func(r config.Refs) []string { return r.BlockPages[req.Id] }); len(used) > 0 {
		return nil, errConflict("the block page is in use by " + strings.Join(used, ", "))
	}
	err := h.audited(ctx, "block_page.delete", "block_page", req.Id, nil, func(ctx context.Context, tx store.Tx) error {
		return tx.DeleteBlockPage(ctx, req.Id)
	})
	if err != nil {
		return nil, err
	}
	blockpage.DeleteTemplate(req.Id)
	return apigen.DeleteBlockPage204Response{}, nil
}

// --- stats ---

var steps = map[string]time.Duration{"1m": time.Minute, "5m": 5 * time.Minute, "1h": time.Hour, "1d": 24 * time.Hour}

const maxBuckets = 2000

func (h *handlers) GetTimeseries(ctx context.Context, req apigen.GetTimeseriesRequestObject) (apigen.GetTimeseriesResponseObject, error) {
	step := "1h"
	if req.Params.Step != nil {
		step = string(*req.Params.Step)
	}
	d, ok := steps[step]
	if !ok {
		return nil, errBadRequest("step must be one of 1m, 5m, 1h, 1d.")
	}
	from, to := req.Params.From.UTC(), req.Params.To.UTC()
	if !from.Before(to) {
		return nil, errBadRequest("from must be before to.")
	}
	if to.Sub(from)/d > maxBuckets {
		return nil, errBadRequest(fmt.Sprintf("that range has more than %d buckets at step %s; use a larger step or a shorter range.", maxBuckets, step))
	}
	var rows []store.Rollup
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		rows, err = tx.ListRollups(ctx, from, to)
		return err
	}); err != nil {
		return nil, err
	}
	site := ""
	if req.Params.Site != nil {
		site = *req.Params.Site
	}
	buckets := map[time.Time]map[string]int64{}
	for _, r := range rows {
		if site != "" && r.SiteID != site {
			continue
		}
		t := r.Bucket.UTC().Truncate(d)
		if buckets[t] == nil {
			buckets[t] = map[string]int64{}
		}
		buckets[t][r.Action] += r.Count
	}
	out := apigen.Timeseries{From: from, To: to, Step: step, Points: make([]struct {
		Counts map[string]int64 `json:"counts"`
		T      time.Time        `json:"t"`
	}, 0, len(buckets))}
	for t := from.Truncate(d); t.Before(to); t = t.Add(d) { // dense: empty buckets are zeros, so charts need no gap handling
		c := buckets[t]
		if c == nil {
			c = map[string]int64{}
		}
		out.Points = append(out.Points, struct {
			Counts map[string]int64 `json:"counts"`
			T      time.Time        `json:"t"`
		}{Counts: c, T: t})
	}
	return apigen.GetTimeseries200JSONResponse(out), nil
}
