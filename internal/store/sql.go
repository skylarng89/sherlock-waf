package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"

	"github.com/skylarng89/sherlock-waf/internal/store/db"
)

// sqlTx implements Tx over the sqlc-generated queries bound to a transaction.
type sqlTx struct{ q *db.Queries }

func micros(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}

func fromMicros(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.UnixMicro(n).UTC()
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// mapErr translates driver errors into the package's sentinels.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case isUnique(err):
		return ErrConflict
	}
	return err
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505"
	}
	var lite *sqlite.Error
	if errors.As(err, &lite) {
		// SQLITE_CONSTRAINT_UNIQUE (2067) and SQLITE_CONSTRAINT_PRIMARYKEY (1555).
		return lite.Code() == 2067 || lite.Code() == 1555
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func affected(n int64, err error) error {
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- KV

func (t sqlTx) GetKV(ctx context.Context, key string) (string, error) {
	v, err := t.q.GetKV(ctx, key)
	return v, mapErr(err)
}

func (t sqlTx) SetKV(ctx context.Context, key, value string) error {
	return mapErr(t.q.SetKV(ctx, db.SetKVParams{Key: key, Value: value}))
}

func (t sqlTx) DeleteKV(ctx context.Context, key string) error { return mapErr(t.q.DeleteKV(ctx, key)) }

// ---- Config

func (t sqlTx) ConfigHead(ctx context.Context) (string, error) {
	v, err := t.q.GetConfigHeadID(ctx)
	return v, mapErr(err)
}

func (t sqlTx) CompareAndSetConfigHead(ctx context.Context, expected, next string) (bool, error) {
	n, err := t.q.CompareAndSetConfigHead(ctx, db.CompareAndSetConfigHeadParams{NewID: next, ExpectedID: expected})
	return n == 1, mapErr(err)
}

func (t sqlTx) InsertConfigVersion(ctx context.Context, v ConfigVersion) error {
	return mapErr(t.q.InsertConfigVersion(ctx, db.InsertConfigVersionParams{
		ID: v.ID, ParentID: v.ParentID, CreatedAt: micros(v.CreatedAt), AuthorType: v.AuthorType, AuthorID: v.AuthorID,
		Source: v.Source, SchemaVersion: int64(v.SchemaVersion), Snapshot: string(v.Snapshot), Diff: string(v.Diff), Applied: boolInt(v.Applied),
	}))
}

func versionFromRow(r db.ConfigVersion) ConfigVersion {
	return ConfigVersion{
		ID: r.ID, ParentID: r.ParentID, CreatedAt: fromMicros(r.CreatedAt), AuthorType: r.AuthorType, AuthorID: r.AuthorID,
		Source: r.Source, SchemaVersion: int(r.SchemaVersion), Snapshot: []byte(r.Snapshot), Diff: []byte(r.Diff), Applied: r.Applied == 1,
	}
}

func (t sqlTx) GetConfigVersion(ctx context.Context, id string) (ConfigVersion, error) {
	r, err := t.q.GetConfigVersion(ctx, id)
	if err != nil {
		return ConfigVersion{}, mapErr(err)
	}
	return versionFromRow(r), nil
}

func (t sqlTx) ListConfigVersions(ctx context.Context, c Cursor, limit int) ([]ConfigVersion, error) {
	before := int64(math.MaxInt64)
	if !c.Time.IsZero() {
		before = c.Time.UnixMicro()
	}
	rows, err := t.q.ListConfigVersions(ctx, db.ListConfigVersionsParams{BeforeTs: before, BeforeID: cursorID(c), MaxRows: clampLimit(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]ConfigVersion, len(rows))
	for i, r := range rows {
		out[i] = versionFromRow(r)
	}
	return out, nil
}

// cursorID makes the "newest first" start (zero cursor) sort after every id.
func cursorID(c Cursor) string {
	if c.Time.IsZero() {
		return "\U0010FFFF"
	}
	return c.ID
}

func clampLimit(n int) int32 {
	switch {
	case n < 1:
		return 50
	case n > 1000:
		return 1000
	}
	return int32(n) //nolint:gosec // bounded above
}

// ---- Sites

func (t sqlTx) ReplaceSites(ctx context.Context, sites []Site) error {
	if err := t.q.DeleteAllSites(ctx); err != nil {
		return mapErr(err)
	}
	for _, s := range sites {
		if err := t.q.InsertSite(ctx, db.InsertSiteParams{ID: s.ID, Name: s.Name, Mode: s.Mode, Hosts: string(s.Hosts), UpdatedAt: micros(s.UpdatedAt)}); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func (t sqlTx) ListSites(ctx context.Context) ([]Site, error) {
	rows, err := t.q.ListSites(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Site, len(rows))
	for i, r := range rows {
		out[i] = Site{ID: r.ID, Name: r.Name, Mode: r.Mode, Hosts: []byte(r.Hosts), UpdatedAt: fromMicros(r.UpdatedAt)}
	}
	return out, nil
}

// ---- Secrets

func secretFromRow(r db.Secret) Secret {
	return Secret{ID: r.ID, Purpose: r.Purpose, KeyID: int(r.KeyID), Nonce: r.Nonce, Ciphertext: r.Ciphertext, CreatedAt: fromMicros(r.CreatedAt)}
}

func (t sqlTx) InsertSecret(ctx context.Context, s Secret) error {
	return mapErr(t.q.InsertSecret(ctx, db.InsertSecretParams{ID: s.ID, Purpose: s.Purpose, KeyID: int64(s.KeyID), Nonce: s.Nonce, Ciphertext: s.Ciphertext, CreatedAt: micros(s.CreatedAt)}))
}

func (t sqlTx) GetSecret(ctx context.Context, id string) (Secret, error) {
	r, err := t.q.GetSecret(ctx, id)
	if err != nil {
		return Secret{}, mapErr(err)
	}
	return secretFromRow(r), nil
}

func (t sqlTx) ListSecrets(ctx context.Context) ([]Secret, error) {
	rows, err := t.q.ListSecrets(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Secret, len(rows))
	for i, r := range rows {
		out[i] = secretFromRow(r)
	}
	return out, nil
}

func (t sqlTx) UpdateSecret(ctx context.Context, s Secret) error {
	return affected(t.q.UpdateSecret(ctx, db.UpdateSecretParams{ID: s.ID, KeyID: int64(s.KeyID), Nonce: s.Nonce, Ciphertext: s.Ciphertext}))
}

func (t sqlTx) DeleteSecret(ctx context.Context, id string) error {
	return mapErr(t.q.DeleteSecret(ctx, id))
}

func (t sqlTx) CountSecrets(ctx context.Context) (int, error) {
	n, err := t.q.CountSecrets(ctx)
	return int(n), mapErr(err)
}

// ---- Users

func userFromRow(r db.User) User {
	return User{
		ID: r.ID, Username: r.Username, PasswordHash: r.PasswordHash, Role: r.Role, MFASecretID: r.MfaSecretID,
		MFAEnabled: r.MfaEnabled == 1, MFALastStep: r.MfaLastStep, Disabled: r.Disabled == 1, FailedCount: int(r.FailedCount),
		LockedUntil: fromMicros(r.LockedUntil), LastLoginAt: fromMicros(r.LastLoginAt), CreatedAt: fromMicros(r.CreatedAt),
	}
}

func (t sqlTx) CreateUser(ctx context.Context, u User) error {
	return mapErr(t.q.InsertUser(ctx, db.InsertUserParams{ID: u.ID, Username: u.Username, PasswordHash: u.PasswordHash, Role: u.Role, CreatedAt: micros(u.CreatedAt)}))
}

func (t sqlTx) UserByID(ctx context.Context, id string) (User, error) {
	r, err := t.q.GetUserByID(ctx, id)
	if err != nil {
		return User{}, mapErr(err)
	}
	return userFromRow(r), nil
}

func (t sqlTx) UserByUsername(ctx context.Context, username string) (User, error) {
	r, err := t.q.GetUserByUsername(ctx, username)
	if err != nil {
		return User{}, mapErr(err)
	}
	return userFromRow(r), nil
}

func (t sqlTx) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := t.q.ListUsers(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]User, len(rows))
	for i, r := range rows {
		out[i] = userFromRow(r)
	}
	return out, nil
}

func (t sqlTx) CountUsers(ctx context.Context) (int, error) {
	n, err := t.q.CountUsers(ctx)
	return int(n), mapErr(err)
}

func (t sqlTx) SetUserPassword(ctx context.Context, id, hash string) error {
	return affected(t.q.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{ID: id, PasswordHash: hash}))
}

func (t sqlTx) SetUserRole(ctx context.Context, id, role string) error {
	return affected(t.q.UpdateUserRole(ctx, db.UpdateUserRoleParams{ID: id, Role: role}))
}

func (t sqlTx) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	return affected(t.q.SetUserDisabled(ctx, db.SetUserDisabledParams{ID: id, Disabled: boolInt(disabled)}))
}

func (t sqlTx) SetUserMFA(ctx context.Context, id, secretID string, enabled bool) error {
	return affected(t.q.SetUserMFA(ctx, db.SetUserMFAParams{ID: id, MfaSecretID: secretID, MfaEnabled: boolInt(enabled)}))
}

func (t sqlTx) AdvanceMFAStep(ctx context.Context, id string, step int64) (bool, error) {
	n, err := t.q.AdvanceUserMFAStep(ctx, db.AdvanceUserMFAStepParams{ID: id, Step: step})
	return n == 1, mapErr(err)
}

func (t sqlTx) RecordLoginFailure(ctx context.Context, id string, failed int, lockedUntil time.Time) error {
	return mapErr(t.q.RecordLoginFailure(ctx, db.RecordLoginFailureParams{ID: id, FailedCount: int64(failed), LockedUntil: micros(lockedUntil)}))
}

func (t sqlTx) RecordLoginSuccess(ctx context.Context, id string, at time.Time) error {
	return mapErr(t.q.RecordLoginSuccess(ctx, db.RecordLoginSuccessParams{ID: id, At: micros(at)}))
}

func (t sqlTx) UnlockUser(ctx context.Context, id string) error {
	return mapErr(t.q.UnlockUser(ctx, id))
}

func (t sqlTx) DeleteUser(ctx context.Context, id string) error {
	return affected(t.q.DeleteUser(ctx, id))
}

// ---- Sessions

func sessionFromRow(r db.Session) Session {
	return Session{
		ID: r.ID, UserID: r.UserID, Stage: r.Stage, CreatedAt: fromMicros(r.CreatedAt), LastSeenAt: fromMicros(r.LastSeenAt),
		ExpiresAt: fromMicros(r.ExpiresAt), IP: r.Ip, UserAgent: r.UserAgent, CSRFTokenHash: r.CsrfTokenHash,
	}
}

func (t sqlTx) CreateSession(ctx context.Context, s Session) error {
	return mapErr(t.q.InsertSession(ctx, db.InsertSessionParams{
		ID: s.ID, UserID: s.UserID, Stage: s.Stage, CreatedAt: micros(s.CreatedAt), LastSeenAt: micros(s.LastSeenAt),
		ExpiresAt: micros(s.ExpiresAt), Ip: s.IP, UserAgent: s.UserAgent, CsrfTokenHash: s.CSRFTokenHash,
	}))
}

func (t sqlTx) GetSession(ctx context.Context, id string) (Session, error) {
	r, err := t.q.GetSession(ctx, id)
	if err != nil {
		return Session{}, mapErr(err)
	}
	return sessionFromRow(r), nil
}

func (t sqlTx) TouchSession(ctx context.Context, id string, at time.Time) error {
	return mapErr(t.q.TouchSession(ctx, db.TouchSessionParams{ID: id, At: micros(at)}))
}

func (t sqlTx) DeleteSession(ctx context.Context, id string) error {
	return mapErr(t.q.DeleteSession(ctx, id))
}

func (t sqlTx) DeleteUserSessions(ctx context.Context, userID string) error {
	return mapErr(t.q.DeleteUserSessions(ctx, userID))
}

func (t sqlTx) DeleteExpiredSessions(ctx context.Context, now, idleBefore time.Time) (int, error) {
	n, err := t.q.DeleteExpiredSessions(ctx, db.DeleteExpiredSessionsParams{Now: micros(now), IdleBefore: micros(idleBefore)})
	return int(n), mapErr(err)
}

// ---- Tokens

func tokenFromRow(r db.ApiToken) Token {
	return Token{
		ID: r.ID, UserID: r.UserID, Name: r.Name, TokenHash: r.TokenHash, Scopes: []byte(r.Scopes), CIDRs: []byte(r.Cidrs),
		ExpiresAt: fromMicros(r.ExpiresAt), LastUsedAt: fromMicros(r.LastUsedAt), CreatedAt: fromMicros(r.CreatedAt),
	}
}

func (t sqlTx) CreateToken(ctx context.Context, k Token) error {
	return mapErr(t.q.InsertToken(ctx, db.InsertTokenParams{
		ID: k.ID, UserID: k.UserID, Name: k.Name, TokenHash: k.TokenHash, Scopes: string(k.Scopes), Cidrs: string(k.CIDRs),
		ExpiresAt: micros(k.ExpiresAt), CreatedAt: micros(k.CreatedAt),
	}))
}

func (t sqlTx) GetToken(ctx context.Context, id string) (Token, error) {
	r, err := t.q.GetToken(ctx, id)
	if err != nil {
		return Token{}, mapErr(err)
	}
	return tokenFromRow(r), nil
}

func tokensFromRows(rows []db.ApiToken) []Token {
	out := make([]Token, len(rows))
	for i, r := range rows {
		out[i] = tokenFromRow(r)
	}
	return out
}

func (t sqlTx) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := t.q.ListTokens(ctx)
	return tokensFromRows(rows), mapErr(err)
}

func (t sqlTx) ListTokensByUser(ctx context.Context, userID string) ([]Token, error) {
	rows, err := t.q.ListTokensByUser(ctx, userID)
	return tokensFromRows(rows), mapErr(err)
}

func (t sqlTx) TouchToken(ctx context.Context, id string, at time.Time) error {
	return mapErr(t.q.TouchToken(ctx, db.TouchTokenParams{ID: id, At: micros(at)}))
}

func (t sqlTx) DeleteToken(ctx context.Context, id string) error {
	return affected(t.q.DeleteToken(ctx, id))
}

// ---- Audit

func (t sqlTx) BumpAuditHead(ctx context.Context) (int64, string, error) {
	r, err := t.q.BumpAuditHead(ctx)
	return r.Seq, r.Hash, mapErr(err)
}

func (t sqlTx) SetAuditHeadHash(ctx context.Context, hash string) error {
	return mapErr(t.q.SetAuditHeadHash(ctx, hash))
}

func (t sqlTx) AuditHead(ctx context.Context) (int64, string, error) {
	r, err := t.q.GetAuditHead(ctx)
	return r.Seq, r.Hash, mapErr(err)
}

func (t sqlTx) InsertAudit(ctx context.Context, e AuditEntry) error {
	return mapErr(t.q.InsertAuditEntry(ctx, db.InsertAuditEntryParams{
		Seq: e.Seq, ID: e.ID, At: micros(e.At), ActorType: e.ActorType, ActorID: e.ActorID, Ip: e.IP, Action: e.Action,
		ObjectType: e.ObjectType, ObjectID: e.ObjectID, Details: string(e.Details), PrevHash: e.PrevHash, Hash: e.Hash,
	}))
}

func auditFromRow(r db.AuditLog) AuditEntry {
	return AuditEntry{
		Seq: r.Seq, ID: r.ID, At: fromMicros(r.At), ActorType: r.ActorType, ActorID: r.ActorID, IP: r.Ip, Action: r.Action,
		ObjectType: r.ObjectType, ObjectID: r.ObjectID, Details: []byte(r.Details), PrevHash: r.PrevHash, Hash: r.Hash,
	}
}

func (t sqlTx) ListAudit(ctx context.Context, beforeSeq int64, limit int) ([]AuditEntry, error) {
	if beforeSeq <= 0 {
		beforeSeq = math.MaxInt64
	}
	rows, err := t.q.ListAuditEntriesDesc(ctx, db.ListAuditEntriesDescParams{BeforeSeq: beforeSeq, MaxRows: clampLimit(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]AuditEntry, len(rows))
	for i, r := range rows {
		out[i] = auditFromRow(r)
	}
	return out, nil
}

func (t sqlTx) ListAuditAfter(ctx context.Context, afterSeq int64, limit int) ([]AuditEntry, error) {
	rows, err := t.q.ListAuditEntriesAsc(ctx, db.ListAuditEntriesAscParams{AfterSeq: afterSeq, MaxRows: clampLimit(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]AuditEntry, len(rows))
	for i, r := range rows {
		out[i] = auditFromRow(r)
	}
	return out, nil
}

// ---- Events

// padRuleIDs stores rule ids as " 942100 949110 " so one rule can be found with LIKE '% id %'.
func padRuleIDs(ids []string) string {
	if len(ids) == 0 {
		return " "
	}
	return " " + strings.Join(ids, " ") + " "
}

func eventFromRow(r db.Event) EventRow {
	return EventRow{
		ID: r.ID, TS: fromMicros(r.Ts), SiteID: r.SiteID, Action: r.Action, Mode: r.Mode, ClientIP: r.ClientIp,
		Method: r.Method, Host: r.Host, Path: r.Path, Status: int(r.Status), RuleIDs: strings.Fields(r.RuleIds), Body: []byte(r.Body), Country: r.Country,
	}
}

func (t sqlTx) InsertEvent(ctx context.Context, e EventRow) error {
	return mapErr(t.q.InsertEvent(ctx, db.InsertEventParams{
		ID: e.ID, Ts: micros(e.TS), SiteID: e.SiteID, Action: e.Action, Mode: e.Mode, ClientIp: e.ClientIP, Method: e.Method,
		Host: e.Host, Path: e.Path, Status: int64(e.Status), RuleIds: padRuleIDs(e.RuleIDs), Body: string(e.Body), Country: e.Country,
	}))
}

func (t sqlTx) GetEvent(ctx context.Context, id string) (EventRow, error) {
	r, err := t.q.GetEvent(ctx, id)
	if err != nil {
		return EventRow{}, mapErr(err)
	}
	return eventFromRow(r), nil
}

func nullInt(n int) sql.NullInt64 { return sql.NullInt64{Int64: int64(n), Valid: n != 0} }

// likeEscape makes the LIKE wildcards in user text literal (the queries use ESCAPE '\').
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func nullTime(t time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: micros(t), Valid: !t.IsZero()}
}

func (t sqlTx) ListEvents(ctx context.Context, f EventFilter, c Cursor, limit int) ([]EventRow, error) {
	before := int64(math.MaxInt64)
	if !c.Time.IsZero() {
		before = c.Time.UnixMicro()
	}
	rows, err := t.q.ListEvents(ctx, db.ListEventsParams{
		BeforeTs: before, BeforeID: cursorID(c), SiteID: nullStr(f.SiteID), Action: nullStr(f.Action), ClientIp: nullStr(f.ClientIP),
		RuleID: nullStr(f.RuleID), FromTs: nullTime(f.From), ToTs: nullTime(f.To), MaxRows: clampLimit(limit),
		Country: nullStr(f.Country), Method: nullStr(f.Method), Status: nullInt(f.Status), Mode: nullStr(f.Mode), Text: nullStr(likeEscape(f.Text)),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]EventRow, len(rows))
	for i, r := range rows {
		out[i] = eventFromRow(r)
	}
	return out, nil
}

func (t sqlTx) CountEvents(ctx context.Context) (int, error) {
	n, err := t.q.CountEvents(ctx)
	return int(n), mapErr(err)
}

// maxDeleteBatch bounds one retention delete; list endpoints use the smaller clampLimit.
const maxDeleteBatch = 100_000

func (t sqlTx) DeleteEventsBefore(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	if limit < 1 {
		limit = 10_000
	}
	n, err := t.q.DeleteEventsBefore(ctx, db.DeleteEventsBeforeParams{Cutoff: micros(cutoff), MaxRows: int32(min(limit, maxDeleteBatch))}) //nolint:gosec // bounded by maxDeleteBatch
	return int(n), mapErr(err)
}

func (t sqlTx) AddRollup(ctx context.Context, r Rollup) error {
	return mapErr(t.q.AddRollup(ctx, db.AddRollupParams{Bucket: micros(r.Bucket), SiteID: r.SiteID, Action: r.Action, Count: r.Count}))
}

func (t sqlTx) ListRollups(ctx context.Context, from, to time.Time) ([]Rollup, error) {
	rows, err := t.q.ListRollups(ctx, db.ListRollupsParams{FromBucket: micros(from), ToBucket: micros(to)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Rollup, len(rows))
	for i, r := range rows {
		out[i] = Rollup{Bucket: fromMicros(r.Bucket), SiteID: r.SiteID, Action: r.Action, Count: r.Count}
	}
	return out, nil
}

func (t sqlTx) DeleteRollupsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	n, err := t.q.DeleteRollupsBefore(ctx, micros(cutoff))
	return int(n), mapErr(err)
}

// ---- Certificates

func certificateFromRow(r db.Certificate) (Certificate, error) {
	var hosts []string
	if err := json.Unmarshal([]byte(r.Hosts), &hosts); err != nil {
		return Certificate{}, fmt.Errorf("certificate %s has unreadable hosts: %w", r.ID, err)
	}
	return Certificate{
		ID: r.ID, Name: r.Name, Hosts: hosts, NotBefore: fromMicros(r.NotBefore), NotAfter: fromMicros(r.NotAfter),
		Issuer: r.Issuer, Fingerprint: r.Fingerprint, ChainPEM: r.ChainPem, KeySecretID: r.KeySecretID, CreatedAt: fromMicros(r.CreatedAt),
	}, nil
}

func (t sqlTx) InsertCertificate(ctx context.Context, c Certificate) error {
	hosts, err := json.Marshal(append([]string{}, c.Hosts...))
	if err != nil {
		return fmt.Errorf("encoding certificate hosts: %w", err)
	}
	return mapErr(t.q.InsertCertificate(ctx, db.InsertCertificateParams{
		ID: c.ID, Name: c.Name, Hosts: string(hosts), NotBefore: micros(c.NotBefore), NotAfter: micros(c.NotAfter),
		Issuer: c.Issuer, Fingerprint: c.Fingerprint, ChainPem: c.ChainPEM, KeySecretID: c.KeySecretID, CreatedAt: micros(c.CreatedAt),
	}))
}

func (t sqlTx) GetCertificate(ctx context.Context, id string) (Certificate, error) {
	r, err := t.q.GetCertificate(ctx, id)
	if err != nil {
		return Certificate{}, mapErr(err)
	}
	return certificateFromRow(r)
}

func (t sqlTx) ListCertificates(ctx context.Context) ([]Certificate, error) {
	rows, err := t.q.ListCertificates(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Certificate, 0, len(rows))
	for _, r := range rows {
		c, err := certificateFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (t sqlTx) DeleteCertificate(ctx context.Context, id string) error {
	return affected(t.q.DeleteCertificate(ctx, id))
}

// ---- Block pages

func (t sqlTx) PutBlockPage(ctx context.Context, p BlockPage) error {
	return mapErr(t.q.UpsertBlockPage(ctx, db.UpsertBlockPageParams{ID: p.ID, Html: p.HTML, UpdatedAt: micros(p.UpdatedAt)}))
}

func (t sqlTx) GetBlockPage(ctx context.Context, id string) (BlockPage, error) {
	r, err := t.q.GetBlockPage(ctx, id)
	if err != nil {
		return BlockPage{}, mapErr(err)
	}
	return BlockPage{ID: r.ID, HTML: r.Html, UpdatedAt: fromMicros(r.UpdatedAt)}, nil
}

func (t sqlTx) ListBlockPages(ctx context.Context) ([]BlockPage, error) {
	rows, err := t.q.ListBlockPages(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]BlockPage, len(rows))
	for i, r := range rows {
		out[i] = BlockPage{ID: r.ID, HTML: r.Html, UpdatedAt: fromMicros(r.UpdatedAt)}
	}
	return out, nil
}

func (t sqlTx) DeleteBlockPage(ctx context.Context, id string) error {
	return affected(t.q.DeleteBlockPage(ctx, id))
}

// ---- Bans

func banFromRow(r db.Ban) Ban {
	return Ban{ID: r.ID, IP: r.Ip, SiteID: r.SiteID, Source: r.Source, Reason: r.Reason, CreatedBy: r.CreatedBy, CreatedAt: fromMicros(r.CreatedAt), Until: fromMicros(r.Until)}
}

func (t sqlTx) PutBan(ctx context.Context, b Ban) error {
	return mapErr(t.q.UpsertBan(ctx, db.UpsertBanParams{
		ID: b.ID, Ip: b.IP, SiteID: b.SiteID, Source: b.Source, Reason: b.Reason, CreatedBy: b.CreatedBy,
		CreatedAt: micros(b.CreatedAt), Until: micros(b.Until),
	}))
}

func (t sqlTx) GetBan(ctx context.Context, id string) (Ban, error) {
	r, err := t.q.GetBan(ctx, id)
	if err != nil {
		return Ban{}, mapErr(err)
	}
	return banFromRow(r), nil
}

func (t sqlTx) ListActiveBans(ctx context.Context, now time.Time) ([]Ban, error) {
	rows, err := t.q.ListActiveBans(ctx, micros(now))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Ban, len(rows))
	for i, r := range rows {
		out[i] = banFromRow(r)
	}
	return out, nil
}

func (t sqlTx) DeleteBan(ctx context.Context, id string) error {
	return affected(t.q.DeleteBan(ctx, id))
}

func (t sqlTx) DeleteExpiredBans(ctx context.Context, now time.Time) (int, error) {
	n, err := t.q.DeleteExpiredBans(ctx, micros(now))
	return int(n), mapErr(err)
}

// TopEventValues implements Events.
func (t sqlTx) TopEventValues(ctx context.Context, dim string, f EventFilter, limit int) ([]ValueCount, error) {
	if f.From.IsZero() || f.To.IsZero() {
		return nil, errors.New("store: a top-N listing needs a time range")
	}
	max := clampLimit(limit)
	from, to, site, action := micros(f.From), micros(f.To), nullStr(f.SiteID), nullStr(f.Action)
	var out []ValueCount
	switch dim {
	case DimIP:
		rows, err := t.q.TopEventIPs(ctx, db.TopEventIPsParams{FromTs: from, ToTs: to, SiteID: site, Action: action, MaxRows: max})
		for _, r := range rows {
			out = append(out, ValueCount{Value: r.Value, Count: r.N})
		}
		return out, mapErr(err)
	case DimPath:
		rows, err := t.q.TopEventPaths(ctx, db.TopEventPathsParams{FromTs: from, ToTs: to, SiteID: site, Action: action, MaxRows: max})
		for _, r := range rows {
			out = append(out, ValueCount{Value: r.Value, Count: r.N})
		}
		return out, mapErr(err)
	case DimCountry:
		rows, err := t.q.TopEventCountries(ctx, db.TopEventCountriesParams{FromTs: from, ToTs: to, SiteID: site, Action: action, MaxRows: max})
		for _, r := range rows {
			out = append(out, ValueCount{Value: r.Value, Count: r.N})
		}
		return out, mapErr(err)
	case DimSite:
		rows, err := t.q.TopEventSites(ctx, db.TopEventSitesParams{FromTs: from, ToTs: to, SiteID: site, Action: action, MaxRows: max})
		for _, r := range rows {
			out = append(out, ValueCount{Value: r.Value, Count: r.N})
		}
		return out, mapErr(err)
	case DimAction:
		rows, err := t.q.TopEventActions(ctx, db.TopEventActionsParams{FromTs: from, ToTs: to, SiteID: site, Action: action, MaxRows: max})
		for _, r := range rows {
			out = append(out, ValueCount{Value: r.Value, Count: r.N})
		}
		return out, mapErr(err)
	}
	return nil, fmt.Errorf("store: unknown dimension %q", dim)
}
