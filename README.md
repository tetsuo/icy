# icy

icy (I-See-You) provides secure, authenticated streaming encryption. It uses a Noise handshake to establish symmetric keys, then encrypts all traffic with XChaCha20-Poly1305.

## Installation

```sh
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

## CLI usage

`icy` command is an encrypted netcat clone for testing and ad-hoc file transfer.:

```sh
go install github.com/tetsuo/icy/cmd/icy@latest
```

Start a server:

```sh
icy -v -l 4242
```

Send some data:

```sh
printf 'Hello, world!\n' | icy -v localhost 4242
```

```sh
icy host port        connect to host:port
icy -l port          listen for a connection
icy -k -l port       listen, keep accepting connections
icy -v ...           print key fingerprints and handshake hash
```

Server outputs:

```
listening on [::]:4242
local  e5dd025706a01f7608081c62121d67c28abcea65c079711a216600c55cc4df4c
remote dab0c97f5ab8252731dcc670aa63a298b3b032a6b8eafca0cd750cef36d47d26
hash   1eb97ba65a3508d312f67436ecc61e7971f1d290bc97bfa6b9e9c73cf2b195afeb9514669b176c212ee75a1837263c0abd5f41f42216749b31393738b664f4d7
Hello, world!
```

Client outputs:

```
local  dab0c97f5ab8252731dcc670aa63a298b3b032a6b8eafca0cd750cef36d47d26
remote e5dd025706a01f7608081c62121d67c28abcea65c079711a216600c55cc4df4c
hash   1eb97ba65a3508d312f67436ecc61e7971f1d290bc97bfa6b9e9c73cf2b195afeb9514669b176c212ee75a1837263c0abd5f41f42216749b31393738b664f4d7
```

Pipe anything through it:

```sh
# receiver
icy -l 9000 > file.bin

# sender
icy localhost 9000 < file.bin
```
