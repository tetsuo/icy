package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/tetsuo/icy"
)

const usage = "icy: encrypted netcat\n" +
	"\nusage:\n" +
	"  icy host port      connect to host:port\n" +
	"  icy -l port        listen for a connection\n" +
	"  icy -l -k port     listen, keep accepting connections\n" +
	"\nflags:\n" +
	"  -l   listen mode\n" +
	"  -k   keep listening (with -l)\n" +
	"  -v   print key fingerprints and handshake hash to stderr\n"

func main() {
	listen := flag.Bool("l", false, "listen mode")
	keep := flag.Bool("k", false, "keep accepting connections")
	verbose := flag.Bool("v", false, "print key fingerprints and handshake hash")

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	var err error
	if *listen {
		if flag.NArg() != 1 {
			flag.Usage()
			os.Exit(2)
		}
		err = serve(":"+flag.Arg(0), *keep, *verbose)
	} else {
		if flag.NArg() != 2 {
			flag.Usage()
			os.Exit(2)
		}
		err = dial(net.JoinHostPort(flag.Arg(0), flag.Arg(1)), *verbose)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(addr string, keep, verbose bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	fmt.Fprintf(os.Stderr, "listening on %s\n", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if err := session(conn, false, verbose); err != nil {
			return err
		}
		if !keep {
			return nil
		}
	}
}

func dial(addr string, verbose bool) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	return session(conn, true, verbose)
}

func session(raw net.Conn, initiator bool, verbose bool) error {
	sc, err := icy.NewConn(initiator, raw, nil)
	if err != nil {
		raw.Close()
		return fmt.Errorf("handshake: %w", err)
	}
	defer sc.Close()

	if verbose {
		fmt.Fprintf(os.Stderr, "local  %x\n", sc.PublicKey())
		fmt.Fprintf(os.Stderr, "remote %x\n", sc.RemotePublicKey())
		fmt.Fprintf(os.Stderr, "hash   %x\n", sc.HandshakeHash())
	}

	return relay(sc)
}

func relay(sc *icy.Conn) error {
	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(sc, os.Stdin)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(os.Stdout, sc)
		errc <- err
	}()

	err := <-errc
	sc.Close()
	if err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, io.ErrClosedPipe) &&
		!errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, syscall.EPIPE) &&
		!errors.Is(err, syscall.ECONNRESET) {
		return err
	}
	return nil
}
