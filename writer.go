package icy

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
)

// A Writer encrypts data and writes it as length-prefixed frames to an underlying writer.
type Writer struct {
	n   [24]byte
	buf []byte
	enc cipher.AEAD
	wd  *bufio.Writer
}

// NewWriter returns a new Writer writing to wd.
func NewWriter(wd *bufio.Writer, enc cipher.AEAD, nonce [24]byte) *Writer {
	return &Writer{wd: wd, enc: enc, n: nonce}
}

// Write encrypts p and writes it as a length-prefixed frame.
func (w *Writer) Write(p []byte) (int, error) {
	pl := len(p) + w.enc.Overhead()
	if pl > MaxFrameSize {
		return 0, ErrFrameTooLarge
	}

	// buf is a high-water mark buffer: it grows to the largest frame seen
	// on this connection and never shrinks
	need := 3 + pl
	if cap(w.buf) < need {
		w.buf = make([]byte, need)
	}
	frame := w.buf[:need]

	// PutUint32 writes 4 bytes; frame[3] is always 0 for pl <= MaxFrameSize
	// and is immediately overwritten by Seal below
	binary.LittleEndian.PutUint32(frame, uint32(pl))
	w.enc.Seal(frame[3:3], w.n[:], p, nil)
	incrementNonce(w.n[:])

	if _, err := w.wd.Write(frame); err != nil {
		return 0, err
	}
	return len(p), w.wd.Flush()
}
