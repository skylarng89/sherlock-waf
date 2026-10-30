package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/updater"
)

const (
	updateCheckTTL     = 5 * time.Minute
	updateCheckTimeout = 20 * time.Second
	updateApplyTimeout = 10 * time.Minute
)

// UpdateService is the updater as the API uses it. *updater.Updater implements it.
type UpdateService interface {
	Check(ctx context.Context) (updater.Status, error)
	Apply(ctx context.Context) (updater.Result, bool, error)
	Staged() (string, bool)
}

// updateCache keeps a successful check for updateCheckTTL so a dashboard
// cannot turn readers into a stream of outbound requests. Failures are not cached.
type updateCache struct {
	mu     sync.Mutex
	status updater.Status
	at     time.Time
}

func (h *handlers) GetUpdateStatus(ctx context.Context, _ apigen.GetUpdateStatusRequestObject) (apigen.GetUpdateStatusResponseObject, error) {
	if h.s.Update == nil {
		return nil, errUpdatesOff()
	}
	c := &h.s.updates
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || h.s.Now().Sub(c.at) > updateCheckTTL {
		ctx, cancel := context.WithTimeout(ctx, updateCheckTimeout)
		defer cancel()
		st, err := h.s.Update.Check(ctx)
		if err != nil {
			return nil, h.updateProblem(ctx, err)
		}
		c.status, c.at = st, h.s.Now()
	}
	st := c.status
	out := apigen.UpdateStatus{Current: st.Current, Latest: st.Latest, Available: st.Available, InContainer: updater.InContainer()}
	if st.CRS != "" {
		out.CrsVersion = &st.CRS
	}
	if st.Reason != "" {
		out.Reason = &st.Reason
	}
	if v, ok := h.s.Update.Staged(); ok {
		out.StagedVersion = &v
	}
	return apigen.GetUpdateStatus200JSONResponse(out), nil
}

func (h *handlers) ApplyUpdate(ctx context.Context, _ apigen.ApplyUpdateRequestObject) (apigen.ApplyUpdateResponseObject, error) {
	if h.s.Update == nil {
		return nil, errUpdatesOff()
	}
	if updater.InContainer() {
		return nil, errConflict("This node runs in a container: update by pulling the new image and recreating the container.")
	}
	ctx, cancel := context.WithTimeout(ctx, updateApplyTimeout)
	defer cancel()
	// The listener's 60 s write timeout would cut off the response of a slow download.
	if w := writerFrom(ctx); w != nil {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(updateApplyTimeout + 30*time.Second))
	}
	res, staged, err := h.s.Update.Apply(ctx)
	if err != nil {
		h.recordUpdate(ctx, "system.update_failed", map[string]any{"reason": err.Error()})
		return nil, h.updateProblem(ctx, err)
	}
	state, restart := "installed", "Restart sherlock to run the new version: `sudo systemctl restart sherlock`."
	if staged {
		state, restart = "staged", "The verified update is installed when the service restarts: `sudo systemctl restart sherlock`."
	}
	h.recordUpdate(ctx, "system.update", map[string]any{"from": res.From, "to": res.To, "state": state})
	h.s.updates.mu.Lock()
	h.s.updates.at = time.Time{} // the next status check must look again
	h.s.updates.mu.Unlock()
	return apigen.ApplyUpdate200JSONResponse(apigen.UpdateApplyResult{From: res.From, To: res.To, State: apigen.UpdateApplyResultState(state), Restart: restart}), nil
}

// recordUpdate audits an update action. A failed audit write is logged: the
// update has already been verified and staged, and refusing to say so helps nobody.
func (h *handlers) recordUpdate(ctx context.Context, action string, details map[string]any) {
	p := principalFrom(ctx)
	actor, id := audit.ActorUser, p.UserID
	if p.IsToken() {
		actor, id = audit.ActorToken, p.TokenID
	}
	if err := h.s.Audit.Record(context.WithoutCancel(ctx), h.s.Store, audit.Input{
		ActorType: actor, ActorID: id, IP: ipFrom(ctx), Action: action, ObjectType: "system", ObjectID: "update", Details: details,
	}); err != nil {
		h.s.log.Error("auditing update failed", "action", action, "error", err)
	}
}

func errUpdatesOff() *problem {
	return newProblem(501, "updates_disabled", "Updates unavailable", "This build has no release signing key, so updates are disabled.")
}

// updateProblem maps updater errors to problems without leaking URLs or paths.
func (h *handlers) updateProblem(ctx context.Context, err error) *problem {
	switch {
	case errors.Is(err, updater.ErrUpToDate):
		return errConflict("Already running the latest version.")
	case errors.Is(err, updater.ErrDowngrade), errors.Is(err, updater.ErrTooOld), errors.Is(err, updater.ErrNoArtifact), errors.Is(err, updater.ErrUnknownCurrent):
		return errUnprocessed(trimPrefix(err))
	case errors.Is(err, updater.ErrBadSignature), errors.Is(err, updater.ErrChecksum):
		h.s.log.WarnContext(ctx, "update verification failed", "error", err)
		return newProblem(502, "update_verification_failed", "Update verification failed", "The release could not be verified and was not installed.")
	}
	h.s.log.WarnContext(ctx, "update check failed", "error", err)
	return newProblem(502, "update_unavailable", "Update source unavailable", "The release source could not be reached or returned something unusable; see the server log.")
}

// trimPrefix drops the "updater: " package prefix; the sentinel messages are written to be shown.
func trimPrefix(err error) string { return strings.TrimPrefix(err.Error(), "updater: ") }

// ListBackups lists the node's own backups.
func (h *handlers) ListBackups(_ context.Context, _ apigen.ListBackupsRequestObject) (apigen.ListBackupsResponseObject, error) {
	files, err := ops.ListBackups(h.s.DataDir)
	if err != nil {
		return nil, err
	}
	items := make([]apigen.Backup, 0, len(files))
	for _, f := range files {
		items = append(items, apigen.Backup{Name: f.Name, Bytes: f.Bytes, CreatedAt: f.CreatedAt, Encrypted: f.Encrypted})
	}
	return apigen.ListBackups200JSONResponse(apigen.BackupList{Items: items}), nil
}
