//go:build sherlock_testhooks

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

func TestConcurrentPasswordChangeIsConflictNotOverwrite(t *testing.T) {
	h := newHarness(t)
	caller := h.mint(h.view, store.StageFull)

	const winner = "winner passphrase 123"
	winnerHash, err := h.hasher.Hash(t.Context(), winner)
	require.NoError(t, err)
	h.auth.SetAfterPasswordVerifyHook(func() {
		h.auth.SetAfterPasswordVerifyHook(nil)
		require.NoError(t, h.st.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
			return tx.SetUserPassword(ctx, h.view.ID, winnerHash)
		}))
	})

	r := caller.do("POST", "/auth/password", map[string]any{"current_password": pw, "new_password": freshPassword})
	require.Equal(t, http.StatusConflict, r.Status, string(r.Body))
	assert.Equal(t, "urn:sherlock:problem:conflict", r.JSON(t)["type"])

	_, err = h.auth.Login(t.Context(), "", "ua", "vic", winner)
	require.NoError(t, err, "the competing change stands")
	_, err = h.auth.Login(t.Context(), "", "ua", "vic", freshPassword)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials, "the refused change was never applied")
}
