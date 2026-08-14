package inbound_test

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/clientacl"
	"github.com/codeswhat/sockguard/app/internal/inbound"
)

type inboundTestContextKey struct{}

func TestIdentityContextRoundTrip(t *testing.T) {
	t.Parallel()

	want := inbound.Identity{Name: "ci", Role: inbound.RoleMain, Network: inbound.NetworkUnix}
	base := context.WithValue(context.Background(), inboundTestContextKey{}, "preserved")
	ctx := inbound.WithIdentity(base, want)
	got, ok := inbound.FromContext(ctx)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("FromContext() = (%#v, %v), want (%#v, true)", got, ok, want)
	}
	if got := ctx.Value(inboundTestContextKey{}); got != "preserved" {
		t.Fatalf("parent context value = %#v, want preserved", got)
	}
}

func TestIdentityContextAbsent(t *testing.T) {
	t.Parallel()

	if got, ok := inbound.FromContext(context.Background()); ok || got != (inbound.Identity{}) {
		t.Fatalf("FromContext(empty) = (%#v, %v), want zero,false", got, ok)
	}
}

func TestConnContextStampsIdentityBeforeNext(t *testing.T) {
	t.Parallel()

	want := inbound.Identity{Name: "ops", Role: inbound.RoleMain, Network: inbound.NetworkTCP}
	called := false
	next := func(ctx context.Context, _ net.Conn) context.Context {
		called = true
		got, ok := inbound.FromContext(ctx)
		if !ok || got != want {
			t.Fatalf("next observed identity = (%#v, %v), want (%#v, true)", got, ok, want)
		}
		return context.WithValue(ctx, inboundTestContextKey{}, "next")
	}

	ctx := inbound.ConnContext(want, next)(context.Background(), nil)
	if !called {
		t.Fatal("next ConnContext was not called")
	}
	if got := ctx.Value(inboundTestContextKey{}); got != "next" {
		t.Fatalf("next context value = %#v, want next", got)
	}
	if got, ok := inbound.FromContext(ctx); !ok || got != want {
		t.Fatalf("identity after next = (%#v, %v), want (%#v, true)", got, ok, want)
	}
}

func TestConnContextComposesWithClientACLAndNil(t *testing.T) {
	t.Parallel()

	want := inbound.Identity{Name: "admin", Role: inbound.RoleAdmin, Network: inbound.NetworkTCP}
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	for _, tc := range []struct {
		name string
		next func(context.Context, net.Conn) context.Context
	}{
		{name: "clientacl", next: clientacl.ConnContext},
		{name: "nil", next: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := context.WithValue(context.Background(), inboundTestContextKey{}, tc.name)
			ctx := inbound.ConnContext(want, tc.next)(base, server)
			if got, ok := inbound.FromContext(ctx); !ok || got != want {
				t.Fatalf("FromContext() = (%#v, %v), want (%#v, true)", got, ok, want)
			}
			if got := ctx.Value(inboundTestContextKey{}); got != tc.name {
				t.Fatalf("context propagation = %#v, want %q", got, tc.name)
			}
		})
	}
}
