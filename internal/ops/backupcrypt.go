package ops

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypted backups: magic, 16-byte salt, then chunks of up to 64 KiB, each
// "uint32 length || XChaCha20-Poly1305 ciphertext". The key is argon2id of the
// passphrase and salt (the same parameters as password hashing), so it is
// unique per file and the nonce can simply count chunks. The AAD marks the
// final chunk, so a file cut at a chunk boundary fails to open.
const (
	encMagic     = "SHBK1\n"
	encChunk     = 64 << 10
	encSaltBytes = 16
	maxEncFrame  = encChunk + chacha20poly1305.Overhead
)

// ErrWrongPassphrase covers a wrong passphrase and a damaged encrypted backup:
// AEAD cannot tell them apart.
var ErrWrongPassphrase = errors.New("backup: wrong passphrase or damaged file")

func deriveBackupKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 2, chacha20poly1305.KeySize)
}

func chunkNonce(n uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	binary.BigEndian.PutUint64(nonce, n)
	return nonce
}

type encWriter struct {
	w    io.Writer
	aead cipher.AEAD
	buf  []byte
	n    uint64
}

func newEncWriter(w io.Writer, passphrase string) (io.WriteCloser, error) {
	salt := make([]byte, encSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	aead, err := chacha20poly1305.NewX(deriveBackupKey(passphrase, salt))
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(append([]byte(encMagic), salt...)); err != nil {
		return nil, err
	}
	return &encWriter{w: w, aead: aead}, nil
}

func (e *encWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		// Flush only when more data follows, so the last chunk is always held back for Close.
		if len(e.buf) == encChunk {
			if err := e.flush(false); err != nil {
				return 0, err
			}
		}
		k := min(encChunk-len(e.buf), len(p))
		e.buf = append(e.buf, p[:k]...)
		p = p[k:]
	}
	return total, nil
}

func (e *encWriter) flush(final bool) error {
	flag := byte(0)
	if final {
		flag = 1
	}
	ct := e.aead.Seal(nil, chunkNonce(e.n), e.buf, []byte{flag})
	e.n++
	e.buf = e.buf[:0]
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct))) //nolint:gosec // bounded by maxEncFrame
	if _, err := e.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := e.w.Write(ct)
	return err
}

func (e *encWriter) Close() error { return e.flush(true) }

type encReader struct {
	r     *bufio.Reader
	aead  cipher.AEAD
	n     uint64
	plain []byte
	done  bool
}

// isEncrypted peeks at the magic.
func isEncrypted(br *bufio.Reader) bool {
	b, err := br.Peek(len(encMagic))
	return err == nil && string(b) == encMagic
}

func newEncReader(br *bufio.Reader, passphrase string) (io.Reader, error) {
	hdr := make([]byte, len(encMagic)+encSaltBytes)
	if _, err := io.ReadFull(br, hdr); err != nil || string(hdr[:len(encMagic)]) != encMagic {
		return nil, ErrWrongPassphrase
	}
	aead, err := chacha20poly1305.NewX(deriveBackupKey(passphrase, hdr[len(encMagic):]))
	if err != nil {
		return nil, err
	}
	return &encReader{r: br, aead: aead}, nil
}

func (e *encReader) Read(p []byte) (int, error) {
	for len(e.plain) == 0 {
		if e.done {
			return 0, io.EOF
		}
		var hdr [4]byte
		if _, err := io.ReadFull(e.r, hdr[:]); err != nil {
			return 0, errors.New("backup: encrypted file is truncated")
		}
		size := binary.BigEndian.Uint32(hdr[:])
		if size < chacha20poly1305.Overhead || size > maxEncFrame {
			return 0, ErrWrongPassphrase
		}
		ct := make([]byte, size)
		if _, err := io.ReadFull(e.r, ct); err != nil {
			return 0, errors.New("backup: encrypted file is truncated")
		}
		// The last chunk is flagged; any other chunk must be followed by more data.
		_, peekErr := e.r.Peek(1)
		final := peekErr != nil // nothing follows
		flag := byte(0)
		if final {
			flag = 1
		}
		pt, err := e.aead.Open(nil, chunkNonce(e.n), ct, []byte{flag})
		if err != nil {
			if final {
				// Could be a truncated stream whose cut chunk was not final.
				if _, err2 := e.aead.Open(nil, chunkNonce(e.n), ct, []byte{0}); err2 == nil {
					return 0, errors.New("backup: encrypted file is truncated")
				}
			}
			return 0, ErrWrongPassphrase
		}
		e.n++
		e.done = final
		e.plain = pt
	}
	n := copy(p, e.plain)
	e.plain = e.plain[n:]
	return n, nil
}
