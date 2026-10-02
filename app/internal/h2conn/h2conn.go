// Package h2conn runs cleartext HTTP/2 with prior knowledge over a single
// net.Conn the caller already holds, as either end, on net/http alone.
//
// net/http's HTTP/2 entry points are address-oriented: Transport.NewClientConn
// dials, and Server.Serve accepts from a net.Listener. The BuildKit tunnels
// this package exists for hand over a connection that is already established
// (hijacked from an HTTP/1.1 upgrade, dialed and upgraded by hand, or a child
// process's stdio), so each function here adapts one such connection to the
// shape net/http expects. Nothing in this package negotiates: both ends must
// already agree the connection speaks HTTP/2.
//
// Because this is net/http's own HTTP/2, GODEBUG=http2server=0 and
// GODEBUG=http2client=0 switch off Serve and NewClientConn respectively, as
// they do for every other net/http server and client in the process.
package h2conn

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// clientConnAddress is the address NewClientConn hands to net/http. It is
// never resolved or dialed: the Transport's only dialer returns the caller's
// connection. The .invalid TLD (RFC 2606) keeps that obvious in any error
// text or trace that surfaces it.
const clientConnAddress = "h2conn.invalid:80"

// DefaultPrefaceTimeout bounds how long Serve waits for the peer's HTTP/2
// client preface when ServerConfig.PrefaceTimeout is zero.
const DefaultPrefaceTimeout = 10 * time.Second

var errConnAlreadyUsed = errors.New("h2conn: connection was already handed to the HTTP/2 client")

// NewClientConn starts an HTTP/2 client on conn and returns once the client
// preface and initial SETTINGS have been written. config may be nil.
//
// The returned connection sends every request on conn regardless of the
// request's URL, which still needs a non-empty host. Closing it closes conn.
// The caller still owns conn when NewClientConn fails and should close it.
func NewClientConn(conn net.Conn, config *http.HTTP2Config) (*http.ClientConn, error) {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)

	transport := &http.Transport{
		// Unencrypted HTTP/2 without HTTP/1 is what makes net/http speak
		// HTTP/2 with prior knowledge instead of attempting an upgrade.
		Protocols: &protocols,
		HTTP2:     config,
		// Proxy stays nil: an HTTP_PROXY in the environment must never
		// redirect a tunnel that is already connected.
		DialContext: dialOnce(conn),
	}
	return transport.NewClientConn(context.Background(), "http", clientConnAddress)
}

// dialOnce returns a Transport dialer that yields conn to the first dial and
// refuses every later one, so the Transport can never hand the same
// connection to two HTTP/2 clients.
func dialOnce(conn net.Conn) func(context.Context, string, string) (net.Conn, error) {
	var handed atomic.Bool
	return func(context.Context, string, string) (net.Conn, error) {
		if handed.Swap(true) {
			return nil, errConnAlreadyUsed
		}
		return conn, nil
	}
}

// ServerConfig is what Serve needs to run an HTTP/2 server on one connection.
type ServerConfig struct {
	// Handler receives one request per HTTP/2 stream, including "OPTIONS *".
	Handler http.Handler

	// MaxConcurrentStreams is advertised to the peer as
	// SETTINGS_MAX_CONCURRENT_STREAMS. Zero selects net/http's default.
	MaxConcurrentStreams int

	// IdleTimeout closes the connection, with a GOAWAY, after this long
	// without an open stream. Zero or negative disables it.
	IdleTimeout time.Duration

	// ReadIdleTimeout sends a PING after this long without receiving a
	// frame, and closes the connection if the peer does not answer. Zero
	// disables the health check.
	ReadIdleTimeout time.Duration

	// MaxHeaderBytes bounds a request's header block. Zero selects
	// http.DefaultMaxHeaderBytes.
	MaxHeaderBytes int

	// PrefaceTimeout bounds the wait for the peer's client preface. Zero
	// selects DefaultPrefaceTimeout. It is enforced with a read deadline, so
	// it only binds on a conn whose SetReadDeadline works.
	PrefaceTimeout time.Duration
}

// Serve serves HTTP/2 on conn and blocks until that connection is finished:
// the peer went away, a timeout fired, or something closed conn. conn is
// closed by the time Serve returns.
//
// ctx is the base context for every request and is not a cancellation
// signal for the connection; close conn to stop serving.
//
// The peer must send the client preface before Serve writes anything, which
// every prior-knowledge client does. A connection that sends something else,
// or nothing within PrefaceTimeout, is closed without a response.
func Serve(ctx context.Context, conn net.Conn, config ServerConfig) {
	defer conn.Close()

	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)

	prefaceTimeout := config.PrefaceTimeout
	if prefaceTimeout == 0 {
		prefaceTimeout = DefaultPrefaceTimeout
	}

	listener := &singleConnListener{conn: plainConn{conn}, done: make(chan struct{})}
	server := &http.Server{
		Handler:   config.Handler,
		Protocols: &protocols,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: config.MaxConcurrentStreams,
			SendPingTimeout:      config.ReadIdleTimeout,
		},
		IdleTimeout:    config.IdleTimeout,
		MaxHeaderBytes: config.MaxHeaderBytes,
		// With HTTP/1 off, the only header read net/http does itself is the
		// client preface, so this is the preface timeout and nothing else.
		ReadHeaderTimeout: prefaceTimeout,
		// Hand "OPTIONS *" to Handler like any other stream, so the caller's
		// own policy and audit see it instead of net/http answering 200.
		DisableGeneralOptionsHandler: true,
		BaseContext:                  func(net.Listener) context.Context { return ctx },
		ConnState: func(_ net.Conn, state http.ConnState) {
			// Both are terminal states, so either one means the connection's
			// serving goroutine is done with it.
			if state == http.StateClosed || state == http.StateHijacked {
				listener.finish()
			}
		},
	}
	// Serve returns once the listener reports closed, which finish arranges
	// when the one connection reaches a terminal state.
	_ = server.Serve(listener)
}

// plainConn narrows a connection to the net.Conn method set. net/http treats
// any connection with a ConnectionState method as TLS and negotiates the
// protocol through ALPN, which a tunnel carried inside an already-upgraded
// TLS connection never offered: with HTTP/1 off, net/http would close it
// without serving a single stream.
type plainConn struct {
	net.Conn
}

// singleConnListener is a net.Listener that yields one connection and then
// blocks until that connection is finished, so http.Server.Serve returns
// exactly when there is nothing left to serve.
type singleConnListener struct {
	conn     net.Conn
	accepted atomic.Bool
	done     chan struct{}
	once     sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted.Swap(true) {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.finish()
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func (l *singleConnListener) finish() {
	l.once.Do(func() { close(l.done) })
}
