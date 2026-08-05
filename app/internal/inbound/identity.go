// Package inbound stamps every accepted connection with a non-spoofable
// listener identity — which configured listener (main or admin) the
// connection arrived on — and threads it through the request context.
//
// Sockguard's multi-listener support (#149) runs ONE shared handler chain
// across every main http.Server; the listener-admission middleware and the
// observability layers (access log, audit log, metrics) need to know which
// listener a given request came in on without trusting anything a client can
// send. Identity is derived exclusively from which net.Listener accepted the
// connection — via http.Server.ConnContext, invoked once per accepted
// connection before any request line is even read — so it can never be
// influenced by a header, query parameter, or other request content.
package inbound

import (
	"context"
	"net"
)

// Role distinguishes a main (Docker-API) listener from the dedicated admin
// listener. Only main-role identities are subject to listener-admission
// (allowed_profiles) scoping; a request that somehow carries an admin-role
// identity on the main chain (or vice versa) indicates wiring corruption and
// must fail closed rather than be silently reinterpreted.
type Role string

const (
	// RoleMain identifies a Docker-API listener — one of Config.Listen
	// (legacy) or an entry in Config.Listeners.
	RoleMain Role = "main"
	// RoleAdmin identifies the dedicated admin listener (admin.listen).
	RoleAdmin Role = "admin"
)

// Network distinguishes the transport a listener was bound on.
type Network string

const (
	NetworkUnix Network = "unix"
	NetworkTCP  Network = "tcp"
)

// Identity is the immutable, server-injected description of the listener a
// connection was accepted on.
type Identity struct {
	// Name is the configured listener name: an explicit listeners[*].name,
	// the synthesized "default" for the legacy singular listen: block, or
	// "admin" for the dedicated admin listener.
	Name string
	// Role is RoleMain or RoleAdmin.
	Role Role
	// Network is NetworkUnix or NetworkTCP.
	Network Network
}

type identityContextKey struct{}

// WithIdentity returns a copy of ctx carrying identity.
func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

// FromContext extracts the Identity stamped by WithIdentity, if any.
func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

// ConnContext composes a per-listener identity-stamping ConnContext with an
// existing one (e.g. clientacl.ConnContext, which captures unix peer
// credentials from the accepted net.Conn). Identity is stamped FIRST, then
// next runs on the resulting context, so unix-peer-credential extraction and
// every downstream consumer can rely on both being present. next may be nil,
// in which case only identity stamping occurs.
func ConnContext(identity Identity, next func(context.Context, net.Conn) context.Context) func(context.Context, net.Conn) context.Context {
	return func(ctx context.Context, conn net.Conn) context.Context {
		ctx = WithIdentity(ctx, identity)
		if next != nil {
			ctx = next(ctx, conn)
		}
		return ctx
	}
}
