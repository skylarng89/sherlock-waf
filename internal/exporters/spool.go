package exporters

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Spool defaults. The segment size bounds how much a drop-oldest eviction
// discards at once and how long a crash-damaged tail can be.
const (
	DefaultSpoolBytes   = 256 << 20
	DefaultSegmentBytes = 4 << 20
	// MaxRecordBytes bounds one spooled record. An event is a few KB; anything
	// larger is a bug or an attack and is refused rather than spooled.
	MaxRecordBytes = 1 << 20

	headerBytes = 8 // uint32 length, uint32 CRC-32C of the payload
	segSuffix   = ".seg"
	cursorFile  = "cursor"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrRecordTooLarge is returned by Append for a record over MaxRecordBytes.
var ErrRecordTooLarge = errors.New("exporters: record exceeds the spool record limit")

// SpoolOptions bounds a Spool; zero values use the defaults.
type SpoolOptions struct {
	// MaxBytes caps the bytes on disk. When exceeded, the oldest segment is
	// deleted and its unsent records are counted as dropped.
	MaxBytes int64
	// SegmentBytes is the size at which a new segment file starts.
	SegmentBytes int64
}

type segment struct {
	id      uint64
	size    int64 // valid bytes
	records int   // records in the segment
}

type position struct {
	seg uint64
	off int64
}

// Spool is a bounded, append-only, segmented on-disk queue with a persisted read
// cursor: the exporter's durable backlog during a SIEM outage. Delivery is
// at-least-once. If the process dies between a successful send and the cursor
// write, the batch is sent again.
//
// All methods are safe for concurrent use. Disk I/O happens under the lock, but
// only the exporter's own goroutines call into it, never the request path.
type Spool struct {
	dir  string
	opts SpoolOptions

	mu       sync.Mutex
	segs     []segment // ascending id; the last one is active
	active   *os.File
	cur      position // first unacknowledged record
	pending  int      // records at or after cur
	total    int64
	dropped  uint64
	nextID   uint64
	closed   bool
	cursorOK position // last persisted cursor, to skip redundant writes
}

// OpenSpool opens (creating if needed) the spool in dir. A torn record at the
// tail of the last segment, left by a crash, is truncated.
func OpenSpool(dir string, opts SpoolOptions) (*Spool, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultSpoolBytes
	}
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = DefaultSegmentBytes
	}
	opts.SegmentBytes = min(opts.SegmentBytes, opts.MaxBytes)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating spool directory: %w", err)
	}
	s := &Spool{dir: dir, opts: opts}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func segName(id uint64) string { return fmt.Sprintf("%020d%s", id, segSuffix) }

func (s *Spool) load() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("reading spool directory: %w", err)
	}
	var ids []uint64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, segSuffix) {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(name, segSuffix), 10, 64)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		size, n, err := scanSegment(filepath.Join(s.dir, segName(id)))
		if err != nil {
			return fmt.Errorf("scanning spool segment %d: %w", id, err)
		}
		s.segs = append(s.segs, segment{id: id, size: size, records: n})
		s.total += size
		s.nextID = id + 1
	}

	s.cur = s.readCursor()
	s.cursorOK = s.cur
	s.normaliseCursor()
	s.recount()

	if len(s.segs) == 0 {
		return s.startSegment()
	}
	last := s.segs[len(s.segs)-1]
	f, err := os.OpenFile(filepath.Join(s.dir, segName(last.id)), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening active spool segment: %w", err)
	}
	s.active = f
	return nil
}

// scanSegment validates a segment and returns its valid size and record count.
// A bad record is a torn write (last segment) or corruption (older ones); the
// data after it cannot be framed reliably, so the segment is cut there.
func scanSegment(path string) (size int64, records int, err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // path is built from the spool's own directory and a numeric id
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	var hdr [headerBytes]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			break
		}
		n := binary.BigEndian.Uint32(hdr[0:4])
		if n > MaxRecordBytes {
			break
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}
		if crc32.Checksum(payload, crcTable) != binary.BigEndian.Uint32(hdr[4:8]) {
			break
		}
		size += headerBytes + int64(n)
		records++
	}
	if size < fi.Size() {
		if err := f.Truncate(size); err != nil {
			return 0, 0, fmt.Errorf("truncating damaged tail: %w", err)
		}
	}
	return size, records, nil
}

func (s *Spool) readCursor() position {
	b, err := os.ReadFile(filepath.Join(s.dir, cursorFile))
	if err != nil {
		return position{}
	}
	var p position
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d %d", &p.seg, &p.off); err != nil {
		return position{}
	}
	return p
}

// normaliseCursor puts the cursor on a segment that still exists and an offset
// inside it. A cursor older than the oldest segment (those were evicted) moves
// to the oldest one.
func (s *Spool) normaliseCursor() {
	if len(s.segs) == 0 {
		s.cur = position{}
		return
	}
	first := s.segs[0]
	if s.cur.seg < first.id {
		s.cur = position{seg: first.id}
		return
	}
	i := s.index(s.cur.seg)
	if i < 0 {
		s.cur = position{seg: first.id}
		return
	}
	if s.cur.off > s.segs[i].size {
		s.cur.off = s.segs[i].size
	}
}

func (s *Spool) index(id uint64) int {
	for i := range s.segs {
		if s.segs[i].id == id {
			return i
		}
	}
	return -1
}

// recount derives pending from the cursor. It scans the cursor segment from
// the cursor offset, because per-segment counts do not say how many of a
// partly read segment remain.
func (s *Spool) recount() {
	s.pending = 0
	i := s.index(s.cur.seg)
	if i < 0 {
		return
	}
	s.pending = s.recordsFrom(s.segs[i], s.cur.off)
	for _, sg := range s.segs[i+1:] {
		s.pending += sg.records
	}
}

func (s *Spool) recordsFrom(sg segment, off int64) int {
	if off <= 0 {
		return sg.records
	}
	f, err := os.Open(filepath.Join(s.dir, segName(sg.id)))
	if err != nil {
		return sg.records
	}
	defer f.Close()
	r := bufio.NewReader(io.NewSectionReader(f, off, sg.size-off))
	n := 0
	var hdr [headerBytes]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return n
		}
		if _, err := r.Discard(int(binary.BigEndian.Uint32(hdr[0:4]))); err != nil {
			return n
		}
		n++
	}
}

func (s *Spool) startSegment() error {
	f, err := os.OpenFile(filepath.Join(s.dir, segName(s.nextID)), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("creating spool segment: %w", err)
	}
	if s.active != nil {
		_ = s.active.Sync()
		_ = s.active.Close()
	}
	s.active = f
	s.segs = append(s.segs, segment{id: s.nextID})
	if len(s.segs) == 1 {
		s.cur = position{seg: s.nextID}
	}
	s.nextID++
	return nil
}

// Append adds records to the spool. When the spool exceeds its byte cap the
// oldest segments are deleted; the number of unsent records lost that way is
// returned so the caller can count it.
func (s *Spool) Append(recs ...[]byte) (evicted int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errors.New("exporters: spool is closed")
	}
	var (
		pend    []byte
		pendRec int
	)
	flush := func() error {
		if pendRec == 0 {
			return nil
		}
		act := &s.segs[len(s.segs)-1]
		if _, err := s.active.Write(pend); err != nil {
			// A short write leaves a torn record; the next open truncates it.
			return fmt.Errorf("writing spool records: %w", err)
		}
		act.size += int64(len(pend))
		act.records += pendRec
		s.total += int64(len(pend))
		s.pending += pendRec
		pend, pendRec = pend[:0], 0
		evicted += s.evictLocked()
		return nil
	}
	for _, rec := range recs {
		if len(rec) > MaxRecordBytes {
			if err := flush(); err != nil {
				return evicted, err
			}
			return evicted, ErrRecordTooLarge
		}
		act := s.segs[len(s.segs)-1]
		if size := act.size + int64(len(pend)); size > 0 && size+headerBytes+int64(len(rec)) > s.opts.SegmentBytes {
			if err := flush(); err != nil {
				return evicted, err
			}
			if err := s.startSegment(); err != nil {
				return evicted, err
			}
		}
		var hdr [headerBytes]byte
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(rec))) //nolint:gosec // bounded by MaxRecordBytes
		binary.BigEndian.PutUint32(hdr[4:8], crc32.Checksum(rec, crcTable))
		pend = append(append(pend, hdr[:]...), rec...)
		pendRec++
	}
	if err := flush(); err != nil {
		return evicted, err
	}
	return evicted, nil
}

// evictLocked deletes the oldest segments while the spool is over its cap,
// always keeping the active segment.
func (s *Spool) evictLocked() int {
	lost := 0
	for s.total > s.opts.MaxBytes && len(s.segs) > 1 {
		old := s.segs[0]
		unsent := 0
		switch {
		case s.cur.seg == old.id:
			unsent = s.recordsFrom(old, s.cur.off)
		case s.cur.seg < old.id:
			unsent = old.records
		}
		if err := os.Remove(filepath.Join(s.dir, segName(old.id))); err != nil && !errors.Is(err, os.ErrNotExist) {
			break // retry on the next append; never lose track of a file we could not delete
		}
		s.segs = s.segs[1:]
		s.total -= old.size
		s.pending -= unsent
		lost += unsent
		s.dropped += uint64(unsent) //nolint:gosec // non-negative count
		if s.cur.seg <= old.id {
			s.cur = position{seg: s.segs[0].id}
		}
	}
	return lost
}

// Batch is a run of records read from the spool, to be acknowledged once the
// destination has accepted them.
type Batch struct {
	Records [][]byte
	end     position
}

// Len is the number of records.
func (b Batch) Len() int { return len(b.Records) }

// Next returns up to maxRecords records (and no more than maxBytes of payload,
// but at least one) starting at the cursor, without consuming them. It returns
// an empty Batch when the spool is drained.
func (s *Spool) Next(maxRecords int, maxBytes int) (Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b Batch
	if s.closed {
		return b, errors.New("exporters: spool is closed")
	}
	pos := s.cur
	bytesRead := 0
	for len(b.Records) < maxRecords {
		i := s.index(pos.seg)
		if i < 0 {
			break
		}
		sg := s.segs[i]
		if pos.off >= sg.size {
			if i == len(s.segs)-1 {
				break
			}
			pos = position{seg: s.segs[i+1].id}
			continue
		}
		rec, n, err := s.readAt(sg, pos.off)
		if err != nil {
			return Batch{}, err
		}
		if len(b.Records) > 0 && bytesRead+len(rec) > maxBytes {
			break
		}
		b.Records = append(b.Records, rec)
		bytesRead += len(rec)
		pos.off += n
	}
	b.end = pos
	return b, nil
}

func (s *Spool) readAt(sg segment, off int64) ([]byte, int64, error) {
	f, err := os.Open(filepath.Join(s.dir, segName(sg.id)))
	if err != nil {
		return nil, 0, fmt.Errorf("opening spool segment: %w", err)
	}
	defer f.Close()
	var hdr [headerBytes]byte
	if _, err := f.ReadAt(hdr[:], off); err != nil {
		return nil, 0, fmt.Errorf("reading spool header: %w", err)
	}
	n := int64(binary.BigEndian.Uint32(hdr[0:4]))
	if n > MaxRecordBytes || off+headerBytes+n > sg.size {
		return nil, 0, fmt.Errorf("spool segment %d is corrupt at offset %d", sg.id, off)
	}
	payload := make([]byte, n)
	if _, err := f.ReadAt(payload, off+headerBytes); err != nil {
		return nil, 0, fmt.Errorf("reading spool record: %w", err)
	}
	if crc32.Checksum(payload, crcTable) != binary.BigEndian.Uint32(hdr[4:8]) {
		return nil, 0, fmt.Errorf("spool segment %d fails its checksum at offset %d", sg.id, off)
	}
	return payload, headerBytes + n, nil
}

// Ack consumes b and persists the new cursor. Fully read segments are deleted.
// Acknowledging a batch the eviction already overtook is harmless.
func (s *Spool) Ack(b Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(b.Records) == 0 || s.closed {
		return nil
	}
	if b.end.seg < s.cur.seg || (b.end.seg == s.cur.seg && b.end.off <= s.cur.off) {
		return nil
	}
	s.cur = b.end
	s.pending = max(0, s.pending-len(b.Records))
	// Delete segments wholly behind the cursor (never the active one).
	for len(s.segs) > 1 && s.segs[0].id < s.cur.seg {
		old := s.segs[0]
		if err := os.Remove(filepath.Join(s.dir, segName(old.id))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing acknowledged spool segment: %w", err)
		}
		s.segs = s.segs[1:]
		s.total -= old.size
	}
	return s.writeCursorLocked()
}

func (s *Spool) writeCursorLocked() error {
	if s.cur == s.cursorOK {
		return nil
	}
	tmp := filepath.Join(s.dir, cursorFile+".tmp")
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %d\n", s.cur.seg, s.cur.off)), 0o600); err != nil {
		return fmt.Errorf("writing spool cursor: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, cursorFile)); err != nil {
		return fmt.Errorf("committing spool cursor: %w", err)
	}
	s.cursorOK = s.cur
	return nil
}

// Sync flushes the active segment to stable storage.
func (s *Spool) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.active == nil {
		return nil
	}
	return s.active.Sync()
}

// SpoolStats is a point-in-time view of a Spool.
type SpoolStats struct {
	Bytes   int64
	Pending int
	Dropped uint64 // records lost to the byte cap since the spool opened
}

// MaxBytes is the effective byte cap after defaults are applied.
func (s *Spool) MaxBytes() int64 { return s.opts.MaxBytes }

// Stats returns the current sizes and counters.
func (s *Spool) Stats() SpoolStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SpoolStats{Bytes: s.total, Pending: s.pending, Dropped: s.dropped}
}

// Close syncs and closes the spool. The data stays on disk for the next open.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.writeCursorLocked()
	if s.active != nil {
		if e := s.active.Sync(); err == nil {
			err = e
		}
		if e := s.active.Close(); err == nil {
			err = e
		}
	}
	return err
}
