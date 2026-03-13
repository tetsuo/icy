package icy_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/tetsuo/icy"
	"github.com/tetsuo/noise"
)

// pipe creates a bidirectional in-memory connection
type memPipe struct {
	*io.PipeReader
	*io.PipeWriter
}

func (p *memPipe) Close() error {
	p.PipeReader.Close()
	p.PipeWriter.Close()
	return nil
}

func newPipe() (*memPipe, *memPipe) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	a := &memPipe{PipeReader: r1, PipeWriter: w2}
	b := &memPipe{PipeReader: r2, PipeWriter: w1}

	return a, b
}

// TestIcyBasic tests basic encrypted communication
func TestIcyBasic(t *testing.T) {
	rawA, rawB := newPipe()

	var streamA, streamB *icy.Conn
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2)

	// Create streams concurrently (they need to handshake together)
	go func() {
		defer wg.Done()
		streamA, errA = icy.NewConn(true, rawA, nil)
	}()

	go func() {
		defer wg.Done()
		streamB, errB = icy.NewConn(false, rawB, nil)
	}()

	wg.Wait()

	if errA != nil {
		t.Fatalf("Failed to create stream A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("Failed to create stream B: %v", errB)
	}

	defer streamA.Close()
	defer streamB.Close()

	// Verify handshake completed
	if !bytes.Equal(streamA.RemotePublicKey(), streamB.PublicKey()) {
		t.Error("Public key mismatch A->B")
	}
	if !bytes.Equal(streamB.RemotePublicKey(), streamA.PublicKey()) {
		t.Error("Public key mismatch B->A")
	}
	if !bytes.Equal(streamA.HandshakeHash(), streamB.HandshakeHash()) {
		t.Error("Handshake hash mismatch")
	}

	// Send message A -> B
	message := []byte("Hello from A")

	sendDone := make(chan error, 1)
	go func() {
		_, err := streamA.Write(message)
		sendDone <- err
	}()

	received := make([]byte, 1024)
	n, err := streamB.Read(received)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if err := <-sendDone; err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	if !bytes.Equal(message, received[:n]) {
		t.Errorf("Message mismatch: got %q, want %q", received[:n], message)
	}

	// Send message B -> A
	message2 := []byte("Hello from B")

	go func() {
		_, err := streamB.Write(message2)
		sendDone <- err
	}()

	n, err = streamA.Read(received)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if err := <-sendDone; err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	if !bytes.Equal(message2, received[:n]) {
		t.Errorf("Message mismatch: got %q, want %q", received[:n], message2)
	}
}

// TestIcyMultipleMessages tests sending multiple messages
func TestIcyMultipleMessages(t *testing.T) {
	rawA, rawB := newPipe()

	var streamA, streamB *icy.Conn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		streamA, _ = icy.NewConn(true, rawA, nil)
	}()

	go func() {
		defer wg.Done()
		streamB, _ = icy.NewConn(false, rawB, nil)
	}()

	wg.Wait()

	if streamA == nil || streamB == nil {
		t.Fatal("Failed to create streams")
	}

	defer streamA.Close()
	defer streamB.Close()

	// Send multiple messages
	messages := []string{
		"First message",
		"Second message",
		"Third message with more data",
		"After message",
	}

	go func() {
		for _, msg := range messages {
			streamA.Write([]byte(msg))
		}
	}()

	// Receive messages
	buf := make([]byte, 1024)
	for i, expected := range messages {
		n, err := streamB.Read(buf)
		if err != nil {
			t.Fatalf("Failed to read message %d: %v", i, err)
		}
		if string(buf[:n]) != expected {
			t.Errorf("Message %d mismatch: got %q, want %q", i, buf[:n], expected)
		}
	}
}

// TestIcyLargeData tests large data transfer
func TestIcyLargeData(t *testing.T) {
	rawA, rawB := newPipe()

	var streamA, streamB *icy.Conn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		streamA, _ = icy.NewConn(true, rawA, nil)
	}()

	go func() {
		defer wg.Done()
		streamB, _ = icy.NewConn(false, rawB, nil)
	}()

	wg.Wait()

	if streamA == nil || streamB == nil {
		t.Fatal("Failed to create streams")
	}

	defer streamA.Close()
	defer streamB.Close()

	// Generate data
	data := make([]byte, 100*1024) // 100KB
	rand.Read(data)

	// Send
	errCh := make(chan error, 1)
	go func() {
		_, err := streamA.Write(data)
		errCh <- err
	}()

	// Receive
	received := make([]byte, len(data))
	n, err := streamB.Read(received)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	if !bytes.Equal(data, received[:n]) {
		t.Error("Large data mismatch")
	}
}

// TestIcyWithTCP tests over real TCP connection
func TestIcyWithTCP(t *testing.T) {
	// Start server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		stream, err := icy.NewConn(false, conn, nil)
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()

		// Echo server
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			serverDone <- err
			return
		}

		if _, err := stream.Write(buf[:n]); err != nil {
			serverDone <- err
			return
		}

		serverDone <- nil
	}()

	// Connect client
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	stream, err := icy.NewConn(true, conn, nil)
	if err != nil {
		t.Fatalf("Failed to create client stream: %v", err)
	}
	defer stream.Close()

	// Send message
	message := []byte("TCP test message")

	sendCh := make(chan error, 1)
	go func() {
		_, err := stream.Write(message)
		sendCh <- err
	}()

	// Read echo
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if err := <-sendCh; err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	if !bytes.Equal(message, buf[:n]) {
		t.Errorf("Echo mismatch: got %q, want %q", buf[:n], message)
	}

	// Check server error
	if err := <-serverDone; err != nil {
		t.Errorf("Server error: %v", err)
	}
}

// TestIcyWithCustomKeys tests using custom keypairs
func TestIcyWithCustomKeys(t *testing.T) {
	curve := noise.DefaultCurve

	// Generate static keys
	keypairA, _ := curve.GenerateKeyPair(nil)
	keypairB, _ := curve.GenerateKeyPair(nil)

	rawA, rawB := newPipe()

	configA := &icy.Config{
		KeyPair: keypairA,
	}
	configB := &icy.Config{
		KeyPair: keypairB,
	}

	var streamA, streamB *icy.Conn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		streamA, _ = icy.NewConn(true, rawA, configA)
	}()

	go func() {
		defer wg.Done()
		streamB, _ = icy.NewConn(false, rawB, configB)
	}()

	wg.Wait()

	if streamA == nil || streamB == nil {
		t.Fatal("Failed to create streams")
	}

	defer streamA.Close()
	defer streamB.Close()

	// Verify keys
	if !bytes.Equal(streamA.PublicKey(), keypairA.PublicKey) {
		t.Error("Stream A public key mismatch")
	}
	if !bytes.Equal(streamB.PublicKey(), keypairB.PublicKey) {
		t.Error("Stream B public key mismatch")
	}
}

// TestIcyConcurrent tests concurrent operations
func TestIcyConcurrent(t *testing.T) {
	rawA, rawB := newPipe()

	var streamA, streamB *icy.Conn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		streamA, _ = icy.NewConn(true, rawA, nil)
	}()

	go func() {
		defer wg.Done()
		streamB, _ = icy.NewConn(false, rawB, nil)
	}()

	wg.Wait()

	if streamA == nil || streamB == nil {
		t.Fatal("Failed to create streams")
	}

	defer streamA.Close()
	defer streamB.Close()

	const numMessages = 50

	// Bidirectional communication
	var wg2 sync.WaitGroup
	wg2.Add(4)

	// A sends to B
	go func() {
		defer wg2.Done()
		for i := 0; i < numMessages; i++ {
			msg := []byte{byte(i)}
			streamA.Write(msg)
		}
	}()

	// B receives from A
	go func() {
		defer wg2.Done()
		buf := make([]byte, 1024)
		for i := 0; i < numMessages; i++ {
			n, err := streamB.Read(buf)
			if err != nil {
				t.Errorf("B read failed: %v", err)
				return
			}
			if n != 1 || buf[0] != byte(i) {
				t.Errorf("B received wrong data: got %d, want %d", buf[0], i)
				return
			}
		}
	}()

	// B sends to A
	go func() {
		defer wg2.Done()
		for i := 0; i < numMessages; i++ {
			msg := []byte{byte(i + 100)}
			streamB.Write(msg)
		}
	}()

	// A receives from B
	go func() {
		defer wg2.Done()
		buf := make([]byte, 1024)
		for i := range numMessages {
			n, err := streamA.Read(buf)
			if err != nil {
				t.Errorf("A read failed: %v", err)
				return
			}
			if n != 1 || buf[0] != byte(i+100) {
				t.Errorf("A received wrong data: got %d, want %d", buf[0], i+100)
				return
			}
		}
	}()

	wg2.Wait()
}

// TestIcyPartialReads tests that partial reads don't lose data
func TestIcyPartialReads(t *testing.T) {
	// Create pipes
	initiatorConn, responderConn := net.Pipe()
	defer initiatorConn.Close()
	defer responderConn.Close()

	// Setup streams
	var wg sync.WaitGroup
	wg.Add(2)

	var initiator, responder *icy.Conn
	var initErr, respErr error

	go func() {
		defer wg.Done()
		initiator, initErr = icy.NewConn(true, initiatorConn, nil)
	}()

	go func() {
		defer wg.Done()
		responder, respErr = icy.NewConn(false, responderConn, nil)
	}()

	wg.Wait()

	if initErr != nil {
		t.Fatalf("Initiator handshake failed: %v", initErr)
	}
	if respErr != nil {
		t.Fatalf("Responder handshake failed: %v", respErr)
	}

	defer initiator.Close()
	defer responder.Close()

	// Test: Send 1000 bytes, but read only 10 bytes at a time
	message := make([]byte, 1000)
	for i := range message {
		message[i] = byte(i % 256)
	}

	// Send message
	go func() {
		if _, err := initiator.Write(message); err != nil {
			t.Errorf("Write failed: %v", err)
		}
	}()

	// Read in small chunks
	received := make([]byte, 0, 1000)
	buf := make([]byte, 10) // Small buffer

	for len(received) < 1000 {
		n, err := responder.Read(buf)
		if err != nil {
			t.Fatalf("Read failed after %d bytes: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	// Verify all data received correctly
	if !bytes.Equal(message, received) {
		t.Errorf("Data mismatch! Expected %d bytes, got %d bytes", len(message), len(received))
		// Show first difference
		for i := 0; i < len(message) && i < len(received); i++ {
			if message[i] != received[i] {
				t.Errorf("First difference at byte %d: expected %d, got %d", i, message[i], received[i])
				break
			}
		}
	}
}
