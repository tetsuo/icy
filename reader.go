package icy

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
)

// A Reader reads length-prefixed frames from an underlying reader and decrypts them.
type Reader struct {
	rd  io.Reader
	dec cipher.AEAD
	n   [24]byte
	buf []byte
	off int
	end int
	hdr [4]byte
}

// NewReader returns a new Reader reading from rd.
func NewReader(rd io.Reader, dec cipher.AEAD, nonce [24]byte) *Reader {
	return &Reader{rd: rd, dec: dec, n: nonce}
}

// Read reads and decrypts the next frame from the underlying reader.
func (r *Reader) Read(p []byte) (int, error) {
	if r.off < r.end {
		n := copy(p, r.buf[r.off:r.end])
		r.off += n
		return n, nil
	}

	if _, err := io.ReadFull(r.rd, r.hdr[:3]); err != nil {
		return 0, err
	}

	n := int(binary.LittleEndian.Uint32(r.hdr[:]))
	if n > MaxFrameSize {
		return 0, ErrFrameTooLarge
	}

	// buf is a high-water mark buffer: it grows to the largest frame seen
	// on this connection and never shrinks
	if cap(r.buf) < n {
		r.buf = make([]byte, n)
	}
	r.buf = r.buf[:n]

	if _, err := io.ReadFull(r.rd, r.buf); err != nil {
		return 0, err
	}

	pt, err := r.dec.Open(r.buf[:0], r.n[:], r.buf, nil)
	if err != nil {
		return 0, ErrDecrypt
	}
	incrementNonce(r.n[:])

	m := copy(p, pt)
	r.off = m
	r.end = len(pt)
	return m, nil
}
