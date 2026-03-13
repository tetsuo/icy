package icy

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"github.com/tetsuo/noise"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const MaxFrameSize = 0xFFFFFF // 16MB

var (
	ErrFrameTooLarge       = errors.New("icy: frame too large")
	ErrDecrypt             = errors.New("icy: decrypt failed")
	ErrHandshakeIncomplete = errors.New("icy: handshake incomplete")
	ErrInvalidHeader       = errors.New("icy: invalid header")
	ErrSessionIDMismatch   = errors.New("icy: session ID mismatch")

	nsInit = mustHash("tetsuo/icy", 0)
	nsResp = mustHash("tetsuo/icy", 1)
)

// Config holds configuration for the Noise handshake.
type Config struct {
	Pattern         *noise.HandshakePattern
	KeyPair         *noise.KeyPair
	RemotePublicKey []byte
}

// Session holds the state of an established Noise session.
type Session struct {
	enc, dec cipher.AEAD
	en, dn   [24]byte
	pk, rpk  []byte
	hh       []byte
}

// Enc returns the AEAD cipher for encrypting outgoing messages.
func (s *Session) Enc() cipher.AEAD {
	return s.enc
}

// Dec returns the AEAD cipher for decrypting incoming messages.
func (s *Session) Dec() cipher.AEAD {
	return s.dec
}

// EncNonce returns the current nonce for encryption.
func (s *Session) EncNonce() [24]byte {
	return s.en
}

// DecNonce returns the current nonce for decryption.
func (s *Session) DecNonce() [24]byte {
	return s.dn
}

// PublicKey returns the local static public key.
func (s *Session) PublicKey() []byte {
	return s.pk
}

// RemotePublicKey returns the remote static public key.
func (s *Session) RemotePublicKey() []byte {
	return s.rpk
}

// HandshakeHash returns the handshake hash, useful for channel binding.
func (s *Session) HandshakeHash() []byte {
	return s.hh
}

// Negotiate performs a Noise handshake and returns a Session.
func Negotiate(initiator bool, rw io.ReadWriter, cfg *Config) (*Session, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	pat := cfg.Pattern
	if pat == nil {
		pat = noise.PatternXX
	}

	ns, err := noise.NewNoiseState(pat, initiator, &noise.Config{
		StaticKeypair: cfg.KeyPair,
	})
	if err != nil {
		return nil, err
	}
	if err := ns.Initialize(nil, cfg.RemotePublicKey); err != nil {
		return nil, err
	}

	if initiator {
		msg, err := ns.Send(nil)
		if err != nil {
			return nil, err
		}
		if err := writeFrame(rw, msg); err != nil {
			return nil, err
		}
		frame, err := readFrame(rw)
		if err != nil {
			return nil, err
		}
		if _, err := ns.Recv(frame); err != nil {
			return nil, err
		}
		msg, err = ns.Send(nil)
		if err != nil {
			return nil, err
		}
		if err := writeFrame(rw, msg); err != nil {
			return nil, err
		}
	} else {
		frame, err := readFrame(rw)
		if err != nil {
			return nil, err
		}
		if _, err := ns.Recv(frame); err != nil {
			return nil, err
		}
		msg, err := ns.Send(nil)
		if err != nil {
			return nil, err
		}
		if err := writeFrame(rw, msg); err != nil {
			return nil, err
		}
		frame, err = readFrame(rw)
		if err != nil {
			return nil, err
		}
		if _, err := ns.Recv(frame); err != nil {
			return nil, err
		}
	}

	if !ns.IsComplete() {
		return nil, ErrHandshakeIncomplete
	}

	tx, rx := ns.Tx(), ns.Rx()
	if tx == nil || rx == nil {
		return nil, ErrHandshakeIncomplete
	}

	s := &Session{
		hh:  ns.Hash(),
		pk:  ns.StaticPublicKey(),
		rpk: ns.RemoteStaticPublicKey(),
	}

	s.enc, err = chacha20poly1305.NewX(tx.Key()[:32])
	if err != nil {
		return nil, err
	}
	s.dec, err = chacha20poly1305.NewX(rx.Key()[:32])
	if err != nil {
		return nil, err
	}

	if _, err := rand.Read(s.en[:]); err != nil {
		return nil, err
	}

	sid := sessionID(s.hh, initiator)
	hdr := make([]byte, 56)
	copy(hdr[:32], sid)
	copy(hdr[32:], s.en[:])

	var rhdr []byte
	if initiator {
		if err := writeFrame(rw, hdr); err != nil {
			return nil, err
		}
		rhdr, err = readFrame(rw)
		if err != nil {
			return nil, err
		}
	} else {
		rhdr, err = readFrame(rw)
		if err != nil {
			return nil, err
		}
		if err := writeFrame(rw, hdr); err != nil {
			return nil, err
		}
	}

	if len(rhdr) != 56 {
		return nil, ErrInvalidHeader
	}

	expected := sessionID(s.hh, !initiator)
	if subtle.ConstantTimeCompare(rhdr[:32], expected) != 1 {
		return nil, ErrSessionIDMismatch
	}

	copy(s.dn[:], rhdr[32:])
	return s, nil
}

func sessionID(hh []byte, initiator bool) []byte {
	ns := nsResp
	if initiator {
		ns = nsInit
	}
	h, _ := blake2b.New256(nil)
	h.Write(ns)
	h.Write(hh)
	return h.Sum(nil)
}

func incrementNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

func writeFrame(w io.Writer, data []byte) error {
	if len(data) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(data)))
	buf := make([]byte, 3+len(data))
	copy(buf, hdr[:3])
	copy(buf[3:], data)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:3]); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint32(hdr[:]))
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func mustHash(s string, i byte) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	h.Write([]byte(s))
	h.Write([]byte{i})
	return h.Sum(nil)
}
