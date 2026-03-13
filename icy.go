// Package icy implements a secure, pipelined transport using the Noise Protocol and XChaCha20-Poly1305.
package icy

import (
	"bufio"
	"io"
	"net/textproto"
)

// Conn represents a secure, bidirectional transport for encrypted communication.
// It implements [io.ReadWriteCloser] and embeds [textproto.Pipeline] for concurrent
// request/response pipelining over a Noise-authenticated channel.
type Conn struct {
	Reader
	Writer
	textproto.Pipeline
	conn io.ReadWriteCloser
	pk   []byte
	rpk  []byte
	hh   []byte
}

// NewConn performs a Noise handshake over rwc and returns a new encrypted Conn using rwc for I/O.
func NewConn(initiator bool, rwc io.ReadWriteCloser, cfg *Config) (*Conn, error) {
	s, err := Negotiate(initiator, rwc, cfg)
	if err != nil {
		rwc.Close()
		return nil, err
	}
	r := NewReader(bufio.NewReader(rwc), s.dec, s.dn)
	w := NewWriter(bufio.NewWriter(rwc), s.enc, s.en)
	return &Conn{
		Reader: *r,
		Writer: *w,
		conn:   rwc,
		pk:     s.pk,
		rpk:    s.rpk,
		hh:     s.hh,
	}, nil
}

// Send writes data after waiting its turn in the pipeline. It returns the id of the request,
// for use with StartResponse and EndResponse.
func (c *Conn) Send(p []byte) (id uint, err error) {
	id = c.Next()
	c.StartRequest(id)
	_, err = c.Write(p)
	c.EndRequest(id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// PublicKey returns the local static public key.
func (c *Conn) PublicKey() []byte { return c.pk }

// RemotePublicKey returns the remote static public key.
func (c *Conn) RemotePublicKey() []byte { return c.rpk }

// HandshakeHash returns the handshake hash.
func (c *Conn) HandshakeHash() []byte { return c.hh }
