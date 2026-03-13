package icy_test

import (
	"bufio"
	crand "crypto/rand"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/tetsuo/icy"
	"golang.org/x/crypto/chacha20poly1305"
)

func BenchmarkRoundTrip_64B(b *testing.B)  { benchRoundTrip(b, 64) }
func BenchmarkRoundTrip_4KB(b *testing.B)  { benchRoundTrip(b, 4*1024) }
func BenchmarkRoundTrip_64KB(b *testing.B) { benchRoundTrip(b, 64*1024) }
func BenchmarkRoundTrip_1MB(b *testing.B)  { benchRoundTrip(b, 1024*1024) }

func benchRoundTrip(b *testing.B, size int) {
	a, z := net.Pipe()

	var s1, s2 *icy.Conn
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s1, _ = icy.NewConn(true, a, nil)
	}()
	go func() {
		defer wg.Done()
		s2, _ = icy.NewConn(false, z, nil)
	}()
	wg.Wait()

	if s1 == nil || s2 == nil {
		b.Fatal("setup failed")
	}
	defer s1.Close()
	defer s2.Close()

	data := make([]byte, size)
	buf := make([]byte, size+128)

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	errc := make(chan error, 1)
	go func() {
		for i := 0; i < b.N; i++ {
			if _, err := s2.Read(buf); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()

	for i := 0; i < b.N; i++ {
		if _, err := s1.Write(data); err != nil {
			b.Fatal(err)
		}
	}

	if err := <-errc; err != nil {
		b.Fatal(err)
	}
}

func BenchmarkWriter_64B(b *testing.B)  { benchWriter(b, 64) }
func BenchmarkWriter_4KB(b *testing.B)  { benchWriter(b, 4*1024) }
func BenchmarkWriter_64KB(b *testing.B) { benchWriter(b, 64*1024) }
func BenchmarkWriter_1MB(b *testing.B)  { benchWriter(b, 1024*1024) }

func benchWriter(b *testing.B, size int) {
	b.Helper()
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := crand.Read(key); err != nil {
		b.Fatal(err)
	}
	enc, err := chacha20poly1305.NewX(key)
	if err != nil {
		b.Fatal(err)
	}
	var nonce [24]byte
	bw := bufio.NewWriterSize(io.Discard, 64*1024)
	w := icy.NewWriter(bw, enc, nonce)
	data := make([]byte, size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(data); err != nil {
			b.Fatal(err)
		}
	}
}
