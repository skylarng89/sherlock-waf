package ops

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Backup archive layout (docs/architecture/data-model.md): a gzip-compressed tar
// holding manifest.json, db/sherlock.db (a consistent SQLite snapshot) and the
// data directory's files under data/. The manifest lists the SHA-256 of every
// other entry, so restore verifies the archive before it changes anything.
const (
	BackupManifestName = "manifest.json"
	backupDBEntry      = "db/sherlock.db"
	backupDataPrefix   = "data/"
	backupPrefix       = "sherlock-backup-"
	backupExt          = ".tar.gz"
	backupEncExt       = ".tar.gz.enc"
	BackupsDirName     = "backups"
	nodeKeyFile        = "node.key"
	sqliteFile         = "sherlock.db"

	maxRestoreFileBytes  = 32 << 30
	maxRestoreTotalBytes = 128 << 30
)

// BackupManifest describes an archive.
type BackupManifest struct {
	Schema     int               `json:"schema"`
	CreatedAt  time.Time         `json:"created_at"`
	Version    string            `json:"version"`
	Database   string            `json:"database"` // sqlite | none
	IncludeKey bool              `json:"includes_node_key"`
	Files      map[string]string `json:"files"` // entry name -> hex sha256
}

// BackupOptions controls CreateBackup.
type BackupOptions struct {
	DataDir string
	// Output is the archive path; empty means <data dir>/backups/sherlock-backup-<UTC time>.tar.gz.
	Output string
	// IncludeKey adds the node key; it requires Passphrase, which encrypts the whole archive.
	IncludeKey bool
	Passphrase string
	// FilesOnly skips the database (required for PostgreSQL, which is dumped with pg_dump).
	FilesOnly bool
	Version   string
	Now       func() time.Time
}

// BackupInfo reports a finished backup.
type BackupInfo struct {
	Path      string
	Bytes     int64
	Files     int
	Encrypted bool
}

// excluded reports whether a top-level data-dir entry stays out of a backup:
// runtime state, regenerable caches and the backups themselves.
func excluded(rel string) bool {
	top, _, _ := strings.Cut(rel, "/")
	switch top {
	// certs holds uploaded certificates materialised from the database on every compile, so a
	// backup need not carry their private keys in clear.
	case BackupsDirName, "updates", "geoip", "feeds", "locks", "certs", "sherlock.lock", "setup-token", nodeKeyFile:
		return true
	}
	return strings.HasPrefix(top, sqliteFile) || strings.Contains(top, ".jsonl") || strings.HasPrefix(top, ".restore-") || strings.HasPrefix(top, "pre-restore-")
}

// CreateBackup writes a backup of the node. It is safe on a running server: the
// database is copied with SQLite's VACUUM INTO and files are read as they are.
func CreateBackup(ctx context.Context, st store.Store, o BackupOptions) (_ BackupInfo, err error) {
	if o.IncludeKey && o.Passphrase == "" {
		return BackupInfo{}, errors.New("including the node key requires a passphrase: the archive is encrypted with it")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	now := o.Now().UTC()
	encrypted := o.Passphrase != ""
	if o.Output == "" {
		ext := backupExt
		if encrypted {
			ext = backupEncExt
		}
		o.Output = filepath.Join(o.DataDir, BackupsDirName, backupPrefix+now.Format("20060102T150405Z")+ext)
	}
	if _, err := os.Lstat(o.Output); err == nil {
		return BackupInfo{}, fmt.Errorf("%s already exists", o.Output)
	}
	if err := os.MkdirAll(filepath.Dir(o.Output), 0o700); err != nil {
		return BackupInfo{}, fmt.Errorf("creating backup dir: %w", err)
	}

	m := BackupManifest{Schema: 1, CreatedAt: now, Version: o.Version, Database: "none", IncludeKey: o.IncludeKey, Files: map[string]string{}}
	work, err := os.MkdirTemp(filepath.Dir(o.Output), ".backup-*")
	if err != nil {
		return BackupInfo{}, fmt.Errorf("creating work dir: %w", err)
	}
	defer os.RemoveAll(work) //nolint:errcheck // best-effort scratch cleanup

	var dbCopy string
	if !o.FilesOnly {
		if st.Dialect() != store.SQLite {
			return BackupInfo{}, errors.New("this node uses PostgreSQL: back the database up with pg_dump (see docs/user/backup-restore.md) and pass --files-only for the data directory")
		}
		dbCopy = filepath.Join(work, sqliteFile)
		if err := store.SnapshotSQLite(ctx, st, dbCopy); err != nil {
			return BackupInfo{}, err
		}
		m.Database = "sqlite"
	}

	partial := o.Output + ".partial"
	out, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen path
	if err != nil {
		return BackupInfo{}, fmt.Errorf("creating %s: %w", partial, err)
	}
	defer func() {
		if err != nil {
			_ = out.Close()
			_ = os.Remove(partial)
		}
	}()
	var sink io.Writer = out
	var enc io.WriteCloser
	if encrypted {
		if enc, err = newEncWriter(out, o.Passphrase); err != nil {
			return BackupInfo{}, err
		}
		sink = enc
	}
	gz := gzip.NewWriter(sink)
	tw := tar.NewWriter(gz)

	add := func(name, src string) error {
		f, err := os.Open(src) //nolint:gosec // data dir or work dir
		if err != nil {
			return err
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), ModTime: fi.ModTime(), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(tw, h), f)
		if err != nil {
			return err
		}
		if n != fi.Size() { // the file changed while it was read; take it on the next backup
			return fmt.Errorf("%s changed while being backed up", src)
		}
		m.Files[name] = hex.EncodeToString(h.Sum(nil))
		return nil
	}

	if dbCopy != "" {
		if err := add(backupDBEntry, dbCopy); err != nil {
			return BackupInfo{}, fmt.Errorf("adding database: %w", err)
		}
	}
	walkErr := filepath.WalkDir(o.DataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(o.DataDir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if o.IncludeKey && rel == nodeKeyFile {
			return add(backupDataPrefix+rel, p)
		}
		if excluded(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() { // symlinks and sockets are never followed into an archive
			return nil
		}
		return add(backupDataPrefix+rel, p)
	})
	if walkErr != nil {
		return BackupInfo{}, fmt.Errorf("adding data files: %w", walkErr)
	}

	mraw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return BackupInfo{}, err
	}
	if err = tw.WriteHeader(&tar.Header{Name: BackupManifestName, Mode: 0o600, Size: int64(len(mraw)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
		return BackupInfo{}, err
	}
	if _, err = tw.Write(mraw); err != nil {
		return BackupInfo{}, err
	}
	for _, c := range []func() error{tw.Close, gz.Close} {
		if err = c(); err != nil {
			return BackupInfo{}, err
		}
	}
	if enc != nil {
		if err = enc.Close(); err != nil {
			return BackupInfo{}, err
		}
	}
	if err = out.Sync(); err != nil {
		return BackupInfo{}, err
	}
	fi, err := out.Stat()
	if err != nil {
		return BackupInfo{}, err
	}
	if err = out.Close(); err != nil {
		return BackupInfo{}, err
	}
	if err = os.Rename(partial, o.Output); err != nil {
		return BackupInfo{}, fmt.Errorf("publishing backup: %w", err)
	}
	return BackupInfo{Path: o.Output, Bytes: fi.Size(), Files: len(m.Files), Encrypted: encrypted}, nil
}

// Backup creates a backup and audits it.
func (e *Env) Backup(ctx context.Context, o BackupOptions) (BackupInfo, error) {
	o.DataDir = e.DataDir
	info, err := CreateBackup(ctx, e.Store, o)
	if err != nil {
		return info, err
	}
	err = e.Audit.Record(ctx, e.Store, audit.Input{
		ActorType: audit.ActorSystem, ActorID: e.actorID(), Action: "backup.create", ObjectType: "backup", ObjectID: filepath.Base(info.Path),
		Details: map[string]any{"encrypted": info.Encrypted, "includes_node_key": o.IncludeKey},
	})
	return info, err
}

// BackupFile is one archive in the backups directory.
type BackupFile struct {
	Name      string    `json:"name"`
	Bytes     int64     `json:"bytes"`
	CreatedAt time.Time `json:"created_at"`
	Encrypted bool      `json:"encrypted"`
}

// ListBackups returns the node's own backups, newest first.
func ListBackups(dataDir string) ([]BackupFile, error) {
	entries, err := os.ReadDir(filepath.Join(dataDir, BackupsDirName))
	if errors.Is(err, fs.ErrNotExist) {
		return []BackupFile{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing backups: %w", err)
	}
	out := []BackupFile{}
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasPrefix(n, backupPrefix) || (!strings.HasSuffix(n, backupExt) && !strings.HasSuffix(n, backupEncExt)) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupFile{Name: n, Bytes: fi.Size(), CreatedAt: fi.ModTime().UTC(), Encrypted: strings.HasSuffix(n, backupEncExt)})
	}
	slices.SortFunc(out, func(a, b BackupFile) int { return strings.Compare(b.Name, a.Name) }) // names embed the UTC time
	return out, nil
}

// PruneBackups deletes all but the newest keep backups; keep < 1 deletes nothing.
func PruneBackups(dataDir string, keep int) (removed []string, err error) {
	if keep < 1 {
		return nil, nil
	}
	files, err := ListBackups(dataDir)
	if err != nil {
		return nil, err
	}
	for _, f := range files[min(keep, len(files)):] {
		if err := os.Remove(filepath.Join(dataDir, BackupsDirName, f.Name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, fmt.Errorf("removing old backup %s: %w", f.Name, err)
		}
		removed = append(removed, f.Name)
	}
	return removed, nil
}

// BackupJob runs the scheduled backup.
type BackupJob struct {
	Store   store.Store
	DataDir string
	Logger  *slog.Logger
	Version string
	// Every is the backup interval (default 24h) and Keep how many to retain (default 7).
	Every time.Duration
	Keep  int
	// Passphrase, when set, encrypts every scheduled backup (see EnvBackupPassphraseFile).
	Passphrase string
	// CheckEvery is how often the job looks whether a backup is due (default 15m).
	CheckEvery time.Duration
	Now        func() time.Time
}

func (j BackupJob) withDefaults() BackupJob {
	if j.Every <= 0 {
		j.Every = 24 * time.Hour
	}
	if j.Keep == 0 {
		j.Keep = 7
	}
	if j.CheckEvery <= 0 {
		j.CheckEvery = 15 * time.Minute
	}
	if j.Now == nil {
		j.Now = time.Now
	}
	if j.Logger == nil {
		j.Logger = slog.New(slog.DiscardHandler)
	}
	return j
}

// Run backs up when the newest backup is older than Every, checking each
// CheckEvery until ctx ends. A failed backup is logged and retried at the next check.
func (j BackupJob) Run(ctx context.Context) {
	j = j.withDefaults()
	if j.Store.Dialect() != store.SQLite {
		j.Logger.Info("scheduled backups are disabled on PostgreSQL; back the database up with pg_dump")
		return
	}
	first := min(time.Minute, j.CheckEvery) // let start-up settle before the first check
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		j.runOnce(ctx)
		t.Reset(j.CheckEvery)
	}
}

func (j BackupJob) runOnce(ctx context.Context) {
	j = j.withDefaults()
	files, err := ListBackups(j.DataDir)
	if err != nil {
		j.Logger.Error("listing backups failed", "error", err)
		return
	}
	if len(files) > 0 && j.Now().Sub(files[0].CreatedAt) < j.Every {
		return
	}
	info, err := CreateBackup(ctx, j.Store, BackupOptions{DataDir: j.DataDir, Version: j.Version, Now: j.Now, Passphrase: j.Passphrase})
	if err != nil {
		if ctx.Err() == nil {
			j.Logger.Error("scheduled backup failed", "error", err)
		}
		return
	}
	j.Logger.Info("backup written", "file", filepath.Base(info.Path), "bytes", info.Bytes)
	if err := audit.New(j.Logger).Record(ctx, j.Store, audit.Input{
		ActorType: audit.ActorSystem, ActorID: "system:backup", Action: "backup.create", ObjectType: "backup", ObjectID: filepath.Base(info.Path),
	}); err != nil {
		j.Logger.Error("auditing backup failed", "error", err)
	}
	removed, err := PruneBackups(j.DataDir, j.Keep)
	if err != nil {
		j.Logger.Error("pruning old backups failed", "error", err)
	}
	if len(removed) > 0 {
		j.Logger.Info("old backups removed", "count", len(removed))
	}
}

// --- verify and restore ---

// RestoreOptions controls Restore and VerifyBackup.
type RestoreOptions struct {
	DataDir    string
	Archive    string
	Passphrase string
	// Force replaces an existing database; the replaced state is moved to <data dir>/pre-restore-<time>/.
	Force bool
	// Postgres is set when the node's database is PostgreSQL: a SQLite snapshot cannot be restored into it.
	Postgres bool
	Logger   *slog.Logger
	Now      func() time.Time
}

// RestoreInfo reports what a verified or restored archive holds.
type RestoreInfo struct {
	Manifest     BackupManifest
	AuditEntries int
	MovedAside   string
}

// extract reads archive into dir, checking every entry against the manifest.
// Nothing outside dir is touched.
func extract(o RestoreOptions, dir string) (BackupManifest, error) {
	var m BackupManifest
	f, err := os.Open(o.Archive) //nolint:gosec // operator-supplied path
	if err != nil {
		return m, fmt.Errorf("opening backup: %w", err)
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	var src io.Reader = br
	if isEncrypted(br) {
		if o.Passphrase == "" {
			return m, errors.New("this backup is encrypted: provide the passphrase")
		}
		if src, err = newEncReader(br, o.Passphrase); err != nil {
			return m, err
		}
	}
	gz, err := gzip.NewReader(src)
	if err != nil {
		if errors.Is(err, ErrWrongPassphrase) {
			return m, err
		}
		return m, fmt.Errorf("backup is not a valid archive: %w", err)
	}
	tr := tar.NewReader(gz)
	got := map[string]string{}
	var total int64
	var haveManifest bool
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("reading backup (truncated or corrupt): %w", err)
		}
		name := h.Name
		if h.Typeflag != tar.TypeReg || !validEntryName(name) {
			return m, fmt.Errorf("backup contains an unsafe entry %q", name)
		}
		if h.Size < 0 || h.Size > maxRestoreFileBytes || total+h.Size > maxRestoreTotalBytes {
			return m, fmt.Errorf("backup entry %q is too large", name)
		}
		total += h.Size
		if name == BackupManifestName {
			raw, err := io.ReadAll(io.LimitReader(tr, 4<<20))
			if err != nil {
				return m, fmt.Errorf("reading manifest: %w", err)
			}
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&m); err != nil {
				return m, fmt.Errorf("decoding manifest: %w", err)
			}
			haveManifest = true
			continue
		}
		if _, dup := got[name]; dup {
			return m, fmt.Errorf("backup lists %q twice", name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return m, err
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // validated entry name under a private dir
		if err != nil {
			return m, err
		}
		hash := sha256.New()
		n, err := io.CopyN(io.MultiWriter(out, hash), tr, h.Size) // size was checked against the caps above
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil && n != h.Size {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return m, fmt.Errorf("reading backup entry %q (truncated or corrupt): %w", name, err)
		}
		got[name] = hex.EncodeToString(hash.Sum(nil))
	}
	if !haveManifest {
		return m, errors.New("backup has no manifest (truncated?)")
	}
	if m.Schema != 1 {
		return m, fmt.Errorf("backup schema %d is not supported by this version", m.Schema)
	}
	for name, want := range m.Files {
		if got[name] != want {
			return m, fmt.Errorf("backup entry %q is missing or its checksum does not match", name)
		}
	}
	for name := range got {
		if _, ok := m.Files[name]; !ok {
			return m, fmt.Errorf("backup contains %q, which its manifest does not list", name)
		}
	}
	if m.Database == "sqlite" && got[backupDBEntry] == "" {
		return m, errors.New("backup claims a database but holds none")
	}
	return m, nil
}

func validEntryName(name string) bool {
	if name == "" || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	return name == BackupManifestName || name == backupDBEntry || (strings.HasPrefix(name, backupDataPrefix) && len(name) > len(backupDataPrefix) && !strings.Contains(name, ".."))
}

// verifyStaged checks the extracted database: SQLite integrity, then the audit
// hash chain on a throw-away copy (opening applies migrations, which must not
// alter the file that will be installed).
func verifyStaged(ctx context.Context, dir string, m BackupManifest, log *slog.Logger) (int, error) {
	if m.Database != "sqlite" {
		return 0, nil
	}
	db := filepath.Join(dir, filepath.FromSlash(backupDBEntry))
	if err := store.CheckSQLiteFile(ctx, db); err != nil {
		return 0, err
	}
	cp := filepath.Join(dir, "verify.db")
	if err := copyFileMode(db, cp); err != nil {
		return 0, err
	}
	st, err := store.OpenSQLite(ctx, cp)
	if err != nil {
		return 0, fmt.Errorf("opening restored database (is it from a newer version?): %w", err)
	}
	defer st.Close()
	rep, err := audit.Verify(ctx, st)
	if err != nil {
		return 0, err
	}
	if rep.Problem != nil {
		return rep.Entries, fmt.Errorf("the backup's audit chain is broken: %w (checked %d entries)", *rep.Problem, rep.Entries)
	}
	return rep.Entries, nil
}

func copyFileMode(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // staged file
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // staged file
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// VerifyBackup checks an archive end to end without touching the data directory:
// decryption, structure, every checksum, database integrity and the audit chain.
func VerifyBackup(ctx context.Context, o RestoreOptions) (RestoreInfo, error) {
	scratch, err := os.MkdirTemp("", "sherlock-verify-*")
	if err != nil {
		return RestoreInfo{}, err
	}
	defer os.RemoveAll(scratch) //nolint:errcheck // scratch cleanup
	m, err := extract(o, scratch)
	if err != nil {
		return RestoreInfo{}, err
	}
	n, err := verifyStaged(ctx, scratch, m, o.Logger)
	return RestoreInfo{Manifest: m, AuditEntries: n}, err
}

// Restore installs a verified backup into the data directory. The caller must
// hold the data-dir lock (no server running). Everything is extracted and
// verified in a staging directory under the data dir first; only then are
// existing files moved aside (Force) and the new ones renamed into place.
func Restore(ctx context.Context, o RestoreOptions) (RestoreInfo, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(o.DataDir, 0o700); err != nil {
		return RestoreInfo{}, fmt.Errorf("creating data dir: %w", err)
	}
	stage, err := os.MkdirTemp(o.DataDir, ".restore-*")
	if err != nil {
		return RestoreInfo{}, fmt.Errorf("creating staging dir: %w", err)
	}
	defer os.RemoveAll(stage) //nolint:errcheck // staging cleanup

	m, err := extract(o, stage)
	if err != nil {
		return RestoreInfo{}, err
	}
	if o.Postgres && m.Database == "sqlite" {
		return RestoreInfo{}, errors.New("this node uses PostgreSQL but the backup holds a SQLite database; restore the database with pg_restore and use a files-only backup for the data directory")
	}
	n, err := verifyStaged(ctx, stage, m, o.Logger)
	if err != nil {
		return RestoreInfo{}, err
	}
	info := RestoreInfo{Manifest: m, AuditEntries: n}

	// Plan the moves, then check for conflicts before changing anything.
	type move struct{ from, to string }
	var moves []move
	if m.Database == "sqlite" {
		moves = append(moves, move{filepath.Join(stage, filepath.FromSlash(backupDBEntry)), filepath.Join(o.DataDir, sqliteFile)})
	}
	for name := range m.Files {
		if rel, ok := strings.CutPrefix(name, backupDataPrefix); ok {
			moves = append(moves, move{filepath.Join(stage, filepath.FromSlash(name)), filepath.Join(o.DataDir, filepath.FromSlash(rel))})
		}
	}
	slices.SortFunc(moves, func(a, b move) int { return strings.Compare(a.to, b.to) })
	var conflicts []string
	for _, mv := range moves {
		if _, err := os.Lstat(mv.to); err == nil {
			conflicts = append(conflicts, mv.to)
		}
	}
	if m.Database == "sqlite" {
		for _, sfx := range []string{"-wal", "-shm"} {
			if _, err := os.Lstat(filepath.Join(o.DataDir, sqliteFile+sfx)); err == nil {
				conflicts = append(conflicts, filepath.Join(o.DataDir, sqliteFile+sfx))
			}
		}
	}
	if len(conflicts) > 0 {
		if !o.Force {
			return RestoreInfo{}, fmt.Errorf("the data directory already holds state that the restore would replace (%s); pass --force to move it aside to pre-restore-*", filepath.Base(conflicts[0]))
		}
		aside := filepath.Join(o.DataDir, "pre-restore-"+o.Now().UTC().Format("20060102T150405Z"))
		for _, c := range conflicts {
			rel, _ := filepath.Rel(o.DataDir, c)
			dst := filepath.Join(aside, rel)
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return RestoreInfo{}, err
			}
			if err := os.Rename(c, dst); err != nil {
				return RestoreInfo{}, fmt.Errorf("moving %s aside: %w", rel, err)
			}
		}
		info.MovedAside = aside
	}
	for _, mv := range moves {
		if err := os.MkdirAll(filepath.Dir(mv.to), 0o700); err != nil {
			return info, err
		}
		if err := os.Rename(mv.from, mv.to); err != nil {
			return info, fmt.Errorf("installing %s: %w", filepath.Base(mv.to), err)
		}
	}

	if m.Database == "sqlite" {
		// Record the restore in the restored audit chain so it is visible, and
		// prove the installed database opens.
		st, err := store.OpenSQLite(ctx, filepath.Join(o.DataDir, sqliteFile))
		if err != nil {
			return info, fmt.Errorf("opening the restored database: %w", err)
		}
		defer st.Close()
		if err := audit.New(o.Logger).Record(ctx, st, audit.Input{
			ActorType: audit.ActorSystem, ActorID: "cli:restore", Action: "backup.restore", ObjectType: "backup", ObjectID: filepath.Base(o.Archive),
			Details: map[string]any{"backup_created_at": m.CreatedAt, "backup_version": m.Version},
		}); err != nil {
			return info, fmt.Errorf("auditing the restore: %w", err)
		}
	}
	return info, nil
}
