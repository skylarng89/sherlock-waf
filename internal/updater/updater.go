// Package updater verifies and installs signed Sherlock releases.
//
// Trust rests on one thing: the Ed25519 release public key compiled into the
// binary. A release is a signed manifest (see ParseManifest) that lists the
// SHA-256 of every archive; an archive is installed only if the manifest
// signature verifies, the archive hash matches, the version is newer than the
// running one, and the running version is allowed to upgrade to it. Nothing
// else (a download URL, a file in the data directory, a cosign bundle) is
// trusted, so the same checks run offline on a --bundle file, and again as root
// when a staged update is applied. See ADR-0017.
//
// The updater never executes or interprets bytes before they are verified, and
// it makes no network request except through the SSRF-safe netx client.
package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/netx"
)

// DefaultBaseURL serves the assets of the latest GitHub release.
const DefaultBaseURL = "https://github.com/skylarng89/sherlock-waf/releases/latest/download"

const (
	maxArchiveBytes = 512 << 20
	maxBinaryBytes  = 768 << 20
	binaryName      = "sherlock"
	backupSuffix    = ".bak"
	newSuffix       = ".new"
)

// Errors a caller may want to tell apart.
var (
	ErrUpToDate       = errors.New("updater: already running the latest version")
	ErrDowngrade      = errors.New("updater: release is older than the running version; downgrades are refused")
	ErrTooOld         = errors.New("updater: the running version is below the release's min_upgrade_from; upgrade through an intermediate release")
	ErrUnknownCurrent = errors.New("updater: the running build has no release version (development build); updates are disabled")
	ErrNoArtifact     = errors.New("updater: the release has no archive for this platform")
	ErrChecksum       = errors.New("updater: archive checksum does not match the signed manifest")
	ErrNoBackup       = errors.New("updater: there is no previous binary to roll back to")
	ErrNotWritable    = errors.New("updater: the installed binary's directory is not writable by this process")
)

// Options configures an Updater.
type Options struct {
	// Key verifies manifests; nil means the embedded release key.
	Key ed25519.PublicKey
	// CurrentVersion is the running version (BuildInfo.Version).
	CurrentVersion string
	// ExePath is the binary to replace; empty means the running executable.
	ExePath string
	// DataDir holds staged updates.
	DataDir string
	// BaseURL serves release-manifest.json, its signature and the archives.
	BaseURL string
	// HTTP overrides the SSRF-safe client (tests only).
	HTTP *http.Client
	// AllowHTTP permits a plain-http BaseURL (tests only).
	AllowHTTP bool
	// GOOS and GOARCH select the archive; empty means the running platform.
	GOOS, GOARCH string
	// SelfTest checks a new binary before it replaces the old one; nil runs
	// `<binary> version` and expects the manifest version in its output.
	SelfTest func(ctx context.Context, binary, version string) error
	Log      *slog.Logger
}

// Updater verifies and installs releases.
type Updater struct {
	o   Options
	key ed25519.PublicKey
}

// New validates o and returns an Updater. Without a release key every
// operation would be unverifiable, so New fails closed with ErrNoReleaseKey.
func New(o Options) (*Updater, error) {
	key := o.Key
	if key == nil {
		var err error
		if key, err = ReleaseKey(); err != nil {
			return nil, err
		}
	}
	if o.BaseURL == "" {
		o.BaseURL = DefaultBaseURL
	}
	o.BaseURL = strings.TrimRight(o.BaseURL, "/")
	if !strings.HasPrefix(o.BaseURL, "https://") && !o.AllowHTTP {
		return nil, errors.New("updater: the release URL must use https")
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.GOARCH == "" {
		o.GOARCH = runtime.GOARCH
	}
	if o.ExePath == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("updater: locating the running binary: %w", err)
		}
		if o.ExePath, err = filepath.EvalSymlinks(exe); err != nil {
			return nil, fmt.Errorf("updater: resolving the running binary: %w", err)
		}
	}
	if o.HTTP == nil {
		o.HTTP = netx.NewClient(netx.Options{Timeout: 5 * time.Minute})
	}
	if o.SelfTest == nil {
		o.SelfTest = runVersion
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &Updater{o: o, key: key}, nil
}

// ArtefactName is the archive for version on this updater's platform.
func (u *Updater) ArtefactName(version string) string {
	return fmt.Sprintf("sherlock_%s_%s_%s.tar.gz", strings.TrimPrefix(version, "v"), u.o.GOOS, u.o.GOARCH)
}

// Bundle is the three files an offline update consists of.
type Bundle struct {
	Manifest, Signature, Archive []byte
}

// Verified is a bundle whose signature, version policy and checksum all passed.
// It is only constructed by VerifyBundle.
type Verified struct {
	Manifest *Manifest
	Artefact string
	bundle   Bundle
}

// Status is the result of a check.
type Status struct {
	Current   string
	Latest    string
	Available bool
	CRS       string
	// Reason explains why an available release cannot be installed from here.
	Reason string
}

// Evaluate applies the version policy to a verified manifest.
func (u *Updater) Evaluate(m *Manifest) error {
	cur, err := ParseVersion(u.o.CurrentVersion)
	if err != nil {
		return ErrUnknownCurrent
	}
	next, err := ParseVersion(m.Version)
	if err != nil {
		return err
	}
	switch c := next.Compare(cur); {
	case c < 0:
		return ErrDowngrade
	case c == 0:
		return ErrUpToDate
	}
	if m.MinUpgradeFrom != "" {
		min, err := ParseVersion(m.MinUpgradeFrom)
		if err != nil {
			return err
		}
		if cur.Compare(min) < 0 {
			return fmt.Errorf("%w (running %s, needs at least %s)", ErrTooOld, cur, min)
		}
	}
	if _, ok := m.Artefacts[u.ArtefactName(m.Version)]; !ok {
		return fmt.Errorf("%w (%s/%s)", ErrNoArtifact, u.o.GOOS, u.o.GOARCH)
	}
	return nil
}

func (u *Updater) fetch(ctx context.Context, name string, limit int64) ([]byte, error) {
	b, err := netx.Get(ctx, u.o.HTTP, u.o.BaseURL+"/"+name, limit, nil)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}
	return b, nil
}

// Latest downloads and verifies the current release manifest.
func (u *Updater) Latest(ctx context.Context) (*Manifest, []byte, []byte, error) {
	raw, err := u.fetch(ctx, ManifestName, maxManifestBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	sig, err := u.fetch(ctx, SignatureName, 1<<10)
	if err != nil {
		return nil, nil, nil, err
	}
	m, err := ParseManifest(raw, sig, u.key)
	return m, raw, sig, err
}

// Check reports whether a newer release is installable. A release that exists
// but cannot be installed (too old to upgrade directly) is Available with Reason.
func (u *Updater) Check(ctx context.Context) (Status, error) {
	m, _, _, err := u.Latest(ctx)
	if err != nil {
		return Status{}, err
	}
	st := Status{Current: u.o.CurrentVersion, Latest: m.Version, CRS: m.CRSVersion}
	switch err := u.Evaluate(m); {
	case err == nil:
		st.Available = true
	case errors.Is(err, ErrUpToDate), errors.Is(err, ErrDowngrade):
	case errors.Is(err, ErrTooOld), errors.Is(err, ErrNoArtifact):
		st.Available, st.Reason = true, err.Error()
	default:
		return st, err
	}
	return st, nil
}

// VerifyBundle runs every check on b. The archive bytes are hashed and later
// extracted from the same in-memory copy, so a file swapped after verification
// cannot be installed.
func (u *Updater) VerifyBundle(b Bundle) (*Verified, error) {
	m, err := ParseManifest(b.Manifest, b.Signature, u.key)
	if err != nil {
		return nil, err
	}
	if err := u.Evaluate(m); err != nil {
		return nil, err
	}
	name := u.ArtefactName(m.Version)
	want, err := hex.DecodeString(m.Artefacts[name])
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("updater: manifest checksum for %s is malformed", name)
	}
	got := sha256.Sum256(b.Archive)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return nil, ErrChecksum
	}
	return &Verified{Manifest: m, Artefact: name, bundle: b}, nil
}

// LoadBundle reads an offline bundle: the release archive and its signed
// manifest. Empty manifest or signature paths default to the files beside the archive.
func LoadBundle(archive, manifest, signature string) (Bundle, error) {
	dir := filepath.Dir(archive)
	if manifest == "" {
		manifest = filepath.Join(dir, ManifestName)
	}
	if signature == "" {
		signature = filepath.Join(dir, SignatureName)
	}
	var b Bundle
	var err error
	if b.Archive, err = readCapped(archive, maxArchiveBytes); err != nil {
		return b, err
	}
	if b.Manifest, err = readCapped(manifest, maxManifestBytes); err != nil {
		return b, err
	}
	b.Signature, err = readCapped(signature, 1<<10)
	return b, err
}

func readCapped(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, limit)
	}
	return b, nil
}

// Download fetches the latest release (manifest, signature, archive) and verifies it.
func (u *Updater) Download(ctx context.Context) (*Verified, error) {
	m, raw, sig, err := u.Latest(ctx)
	if err != nil {
		return nil, err
	}
	if err := u.Evaluate(m); err != nil {
		return nil, err
	}
	archive, err := u.fetch(ctx, u.ArtefactName(m.Version), maxArchiveBytes)
	if err != nil {
		return nil, err
	}
	return u.VerifyBundle(Bundle{Manifest: raw, Signature: sig, Archive: archive})
}

// Result describes what Install did.
type Result struct {
	From, To string
	Backup   string
}

// Install replaces the binary: the verified archive's binary is written beside
// the old one, self-tested, the old one is hard-linked to <exe>.bak, and the
// new one is renamed over it, so the executable path never names a missing or
// half-written file. Roll back with Rollback.
func (u *Updater) Install(ctx context.Context, v *Verified) (Result, error) {
	exe := u.o.ExePath
	staged := exe + newSuffix
	bin, err := extractBinary(v.bundle.Archive)
	if err != nil {
		return Result{}, err
	}
	if err := writeFileSync(staged, bin, 0o755); err != nil {
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
			return Result{}, fmt.Errorf("%w: %s", ErrNotWritable, filepath.Dir(exe))
		}
		return Result{}, fmt.Errorf("writing new binary: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(staged)
		}
	}()
	if err := u.o.SelfTest(ctx, staged, strings.TrimPrefix(v.Manifest.Version, "v")); err != nil {
		return Result{}, fmt.Errorf("the new binary failed its self-test, nothing was changed: %w", err)
	}
	backup := exe + backupSuffix
	_ = os.Remove(backup)
	if err := os.Link(exe, backup); err != nil { // not every filesystem links
		if err := copyFile(exe, backup, 0o755); err != nil {
			return Result{}, fmt.Errorf("backing up the current binary: %w", err)
		}
	}
	if err := os.Rename(staged, exe); err != nil {
		return Result{}, fmt.Errorf("replacing the binary: %w", err)
	}
	cleanup = false
	syncDir(filepath.Dir(exe))
	u.o.Log.Info("binary replaced", "from", u.o.CurrentVersion, "to", v.Manifest.Version)
	return Result{From: u.o.CurrentVersion, To: v.Manifest.Version, Backup: backup}, nil
}

// Rollback puts the binary saved by the last Install back.
func (u *Updater) Rollback() error {
	backup := u.o.ExePath + backupSuffix
	if _, err := os.Stat(backup); err != nil {
		return ErrNoBackup
	}
	// Rename (not copy) keeps the swap atomic; the backup is consumed.
	if err := os.Rename(backup, u.o.ExePath); err != nil {
		return fmt.Errorf("restoring the previous binary: %w", err)
	}
	syncDir(filepath.Dir(u.o.ExePath))
	return nil
}

// Apply is the online path: download, verify, and either install (when this
// process may write the binary) or stage for the privileged apply step.
func (u *Updater) Apply(ctx context.Context) (Result, bool, error) {
	v, err := u.Download(ctx)
	if err != nil {
		return Result{}, false, err
	}
	return u.InstallOrStage(ctx, v)
}

// InstallOrStage installs v, or stages it when the binary is not writable.
func (u *Updater) InstallOrStage(ctx context.Context, v *Verified) (res Result, staged bool, err error) {
	res, err = u.Install(ctx, v)
	if errors.Is(err, ErrNotWritable) {
		if err := u.Stage(v); err != nil {
			return Result{}, false, err
		}
		return Result{From: u.o.CurrentVersion, To: v.Manifest.Version}, true, nil
	}
	return res, false, err
}

func (u *Updater) stagedDir() string { return filepath.Join(u.o.DataDir, "updates", "staged") }

// Stage stores a verified bundle for ApplyStaged. The staged files are not
// trusted: ApplyStaged verifies them again, because the directory belongs to
// the unprivileged service user.
func (u *Updater) Stage(v *Verified) error {
	if u.o.DataDir == "" {
		return errors.New("updater: no data directory to stage into")
	}
	parent := filepath.Dir(u.stagedDir())
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("creating updates dir: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, "stage-*")
	if err != nil {
		return fmt.Errorf("creating staging dir: %w", err)
	}
	for name, data := range map[string][]byte{ManifestName: v.bundle.Manifest, SignatureName: v.bundle.Signature, v.Artefact: v.bundle.Archive} {
		if err := writeFileSync(filepath.Join(tmp, name), data, 0o600); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("staging %s: %w", name, err)
		}
	}
	if err := os.RemoveAll(u.stagedDir()); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("clearing previous staged update: %w", err)
	}
	if err := os.Rename(tmp, u.stagedDir()); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("publishing staged update: %w", err)
	}
	return nil
}

// Staged reports the version of a staged update, if any (unverified: for display).
func (u *Updater) Staged() (string, bool) {
	raw, err := os.ReadFile(filepath.Join(u.stagedDir(), ManifestName)) //nolint:gosec // data dir
	if err != nil {
		return "", false
	}
	m := struct {
		Version string `json:"version"`
	}{}
	if json.Unmarshal(raw, &m) != nil {
		return "", false
	}
	return m.Version, true
}

// ApplyStaged verifies the staged bundle from scratch and installs it. A
// staged update that no longer passes (tampered, or no longer newer than the
// running binary) is deleted and reported. Returns (Result{}, nil) when nothing is staged.
func (u *Updater) ApplyStaged(ctx context.Context) (Result, bool, error) {
	dir := u.stagedDir()
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return Result{}, false, nil
	}
	manifest, err := readCapped(filepath.Join(dir, ManifestName), maxManifestBytes)
	if err != nil {
		return Result{}, true, err
	}
	sig, err := readCapped(filepath.Join(dir, SignatureName), 1<<10)
	if err != nil {
		return Result{}, true, err
	}
	m, err := ParseManifest(manifest, sig, u.key)
	if err != nil {
		_ = os.RemoveAll(dir)
		return Result{}, true, fmt.Errorf("discarding staged update: %w", err)
	}
	archive, err := readCapped(filepath.Join(dir, u.ArtefactName(m.Version)), maxArchiveBytes)
	if err != nil {
		_ = os.RemoveAll(dir)
		return Result{}, true, fmt.Errorf("discarding staged update: %w", err)
	}
	v, err := u.VerifyBundle(Bundle{Manifest: manifest, Signature: sig, Archive: archive})
	if err != nil {
		_ = os.RemoveAll(dir)
		return Result{}, true, fmt.Errorf("discarding staged update: %w", err)
	}
	res, err := u.Install(ctx, v)
	if err != nil {
		return Result{}, true, err
	}
	_ = os.RemoveAll(dir)
	return res, true, nil
}

// extractBinary returns the `sherlock` file of a release archive. Anything
// truncated or oversized is an error; other entries are ignored, never written.
func extractBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytesReader(archive))
	if err != nil {
		return nil, fmt.Errorf("updater: archive is not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("updater: archive does not contain the sherlock binary")
		}
		if err != nil {
			return nil, fmt.Errorf("updater: reading archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg || path.Base(h.Name) != binaryName || h.Size <= 0 || h.Size > maxBinaryBytes {
			continue
		}
		bin, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil || int64(len(bin)) != h.Size {
			return nil, errors.New("updater: archive is truncated")
		}
		return bin, nil
	}
}

func runVersion(ctx context.Context, binary, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "version").Output() //nolint:gosec // a binary whose archive checksum was verified against the signed manifest
	if err != nil {
		return fmt.Errorf("running version: %w", err)
	}
	if !strings.Contains(string(out), "sherlock "+version) {
		return fmt.Errorf("it reports %q, not version %s", strings.TrimSpace(string(out)), version)
	}
	return nil
}

func writeFileSync(p string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) //nolint:gosec // see callers
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src) //nolint:gosec // the running binary
	if err != nil {
		return err
	}
	return writeFileSync(dst, b, mode)
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { //nolint:gosec // parent of the binary
		_ = d.Sync()
		_ = d.Close()
	}
}
