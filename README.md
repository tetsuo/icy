# icy

icy (I-See-You) provides encrypted channels for two-way communication. It performs a Noise handshake to establish symmetric keys, then encrypts all subsequent traffic using XChaCha20-Poly1305.

```
go get github.com/tetsuo/icy
```

## Usage

```go
// server
ln, _ := net.Listen("tcp", ":9000")
raw, _ := ln.Accept()
conn, err := icy.NewConn(false, raw, nil)

// client
raw, _ := net.Dial("tcp", "localhost:9000")
conn, err := icy.NewConn(true, raw, nil)
```

`conn` implements `io.ReadWriteCloser`. Each `Write` is framed and encrypted; each `Read` decrypts one frame. Frames are limited to 16 MB.

```go
conn.Write([]byte("hello"))

buf := make([]byte, 4096)
n, err := conn.Read(buf)
```

For concurrent request/response pipelining, use `Send` + `StartResponse`/`EndResponse`:

```go
id, err := conn.Send(payload) // thread-safe write, returns sequence id
conn.StartResponse(id)
n, err := conn.Read(buf)
conn.EndResponse(id)
```

### Config

```go
cfg := &icy.Config{
    Pattern:         noise.PatternXX, // default
    KeyPair:         kp,              // generated if nil
    RemotePublicKey: remotePub,       // required for IK/XK patterns
}
conn, err := icy.NewConn(true, raw, cfg)
```

### Keys and handshake hash

```go
conn.PublicKey()        // local static public key
conn.RemotePublicKey()  // remote static public key
conn.HandshakeHash()    // handshake hash, useful for channel binding
```

## Wire format

```
[b0 b1 b2][ciphertext...]
```

3-byte little-endian length prefix, followed by the XChaCha20-Poly1305 ciphertext (plaintext + 16-byte tag).
