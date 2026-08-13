package reload

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/config"
)

func TestListenerConfigFieldInventoryPinsReloadContract(t *testing.T) {
	t.Parallel()
	var got []string
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, prefix string) {
		for i := range typ.NumField() {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("mapstructure"), ",")[0]
			if field.Anonymous {
				walk(field.Type, prefix)
				continue
			}
			path := prefix + name
			if field.Type.Kind() == reflect.Struct {
				walk(field.Type, path+".")
				continue
			}
			got = append(got, path)
		}
	}
	walk(reflect.TypeOf(config.ListenerConfig{}), "")
	sort.Strings(got)
	want := []string{
		"address", "allowed_profiles", "insecure_allow_plain_tcp",
		"insecure_allow_unauthenticated_clients", "name", "socket", "socket_gid",
		"socket_mode", "socket_uid", "tls.cert_file", "tls.client_ca_file",
		"tls.common_names", "tls.dns_names", "tls.ip_addresses", "tls.key_file",
		"tls.public_key_sha256_pins", "tls.uri_sans",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListenerConfig field inventory = %v, want %v; classify every new field as immutable or the sole mutable allowed_profiles field", got, want)
	}
}

func reloadListenerConfig() config.Config {
	cfg := config.Defaults()
	uid, gid := 1000, 1000
	cfg.Listeners = []config.ListenerConfig{
		{
			Name: "ci",
			ListenConfig: config.ListenConfig{
				Socket:     "/run/ci.sock",
				SocketMode: config.GroupReadableListenSocketMode,
				SocketUID:  &uid,
				SocketGID:  &gid,
			},
			AllowedProfiles: []string{"ci"},
		},
		{
			Name: "ops",
			ListenConfig: config.ListenConfig{
				Address:                             "127.0.0.1:2376",
				SocketMode:                          config.HardenedListenSocketMode,
				InsecureAllowPlainTCP:               true,
				InsecureAllowUnauthenticatedClients: true,
				TLS: config.ListenTLSConfig{
					CertFile:            "server.crt",
					KeyFile:             "server.key",
					ClientCAFile:        "ca.crt",
					CommonNames:         []string{"ops"},
					DNSNames:            []string{"ops.example"},
					IPAddresses:         []string{"127.0.0.1"},
					URISANs:             []string{"spiffe://example/ops"},
					PublicKeySHA256Pins: []string{"sha256:abc"},
				},
			},
			AllowedProfiles: []string{"ops"},
		},
	}
	return cfg
}

func cloneReloadListeners(cfg config.Config) config.Config {
	clone := cfg
	clone.Listeners = append([]config.ListenerConfig(nil), cfg.Listeners...)
	for i := range clone.Listeners {
		clone.Listeners[i].AllowedProfiles = append([]string(nil), cfg.Listeners[i].AllowedProfiles...)
		clone.Listeners[i].TLS.CommonNames = append([]string(nil), cfg.Listeners[i].TLS.CommonNames...)
		clone.Listeners[i].TLS.DNSNames = append([]string(nil), cfg.Listeners[i].TLS.DNSNames...)
		clone.Listeners[i].TLS.IPAddresses = append([]string(nil), cfg.Listeners[i].TLS.IPAddresses...)
		clone.Listeners[i].TLS.URISANs = append([]string(nil), cfg.Listeners[i].TLS.URISANs...)
		clone.Listeners[i].TLS.PublicKeySHA256Pins = append([]string(nil), cfg.Listeners[i].TLS.PublicKeySHA256Pins...)
	}
	return clone
}

func TestImmutableDiffListenersAllowsOnlyAllowlistChangesAndReordering(t *testing.T) {
	t.Parallel()

	base := reloadListenerConfig()
	allowlist := cloneReloadListeners(base)
	allowlist.Listeners[0].AllowedProfiles = []string{"ci", "ops"}
	if got := ImmutableDiff(&base, &allowlist); len(got) != 0 {
		t.Fatalf("ImmutableDiff(allowed_profiles change) = %v, want empty", got)
	}

	reordered := cloneReloadListeners(base)
	reordered.Listeners[0], reordered.Listeners[1] = reordered.Listeners[1], reordered.Listeners[0]
	if got := ImmutableDiff(&base, &reordered); len(got) != 0 {
		t.Fatalf("ImmutableDiff(reorder) = %v, want empty", got)
	}
}

func TestImmutableDiffListenersReportsEveryImmutableFieldPath(t *testing.T) {
	t.Parallel()

	base := reloadListenerConfig()
	one := 1
	tests := []struct {
		name string
		edit func(*config.ListenerConfig)
		want string
	}{
		{name: "socket", edit: func(l *config.ListenerConfig) { l.Socket = "/run/new.sock" }, want: "listeners.ci.socket"},
		{name: "address", edit: func(l *config.ListenerConfig) { l.Address = "127.0.0.1:9999" }, want: "listeners.ops.address"},
		{name: "socket_mode", edit: func(l *config.ListenerConfig) { l.SocketMode = config.HardenedListenSocketMode }, want: "listeners.ci.socket_mode"},
		{name: "socket_uid", edit: func(l *config.ListenerConfig) { l.SocketUID = &one }, want: "listeners.ci.socket_uid"},
		{name: "socket_gid", edit: func(l *config.ListenerConfig) { l.SocketGID = &one }, want: "listeners.ci.socket_gid"},
		{name: "plain ack", edit: func(l *config.ListenerConfig) { l.InsecureAllowPlainTCP = false }, want: "listeners.ops.insecure_allow_plain_tcp"},
		{name: "unauthenticated ack", edit: func(l *config.ListenerConfig) { l.InsecureAllowUnauthenticatedClients = false }, want: "listeners.ops.insecure_allow_unauthenticated_clients"},
		{name: "tls cert", edit: func(l *config.ListenerConfig) { l.TLS.CertFile = "new.crt" }, want: "listeners.ops.tls.cert_file"},
		{name: "tls key", edit: func(l *config.ListenerConfig) { l.TLS.KeyFile = "new.key" }, want: "listeners.ops.tls.key_file"},
		{name: "tls client ca", edit: func(l *config.ListenerConfig) { l.TLS.ClientCAFile = "new-ca.crt" }, want: "listeners.ops.tls.client_ca_file"},
		{name: "tls common names", edit: func(l *config.ListenerConfig) { l.TLS.CommonNames = []string{"new"} }, want: "listeners.ops.tls.common_names"},
		{name: "tls dns names", edit: func(l *config.ListenerConfig) { l.TLS.DNSNames = []string{"new.example"} }, want: "listeners.ops.tls.dns_names"},
		{name: "tls IPs", edit: func(l *config.ListenerConfig) { l.TLS.IPAddresses = []string{"192.0.2.1"} }, want: "listeners.ops.tls.ip_addresses"},
		{name: "tls URI SANs", edit: func(l *config.ListenerConfig) { l.TLS.URISANs = []string{"spiffe://new"} }, want: "listeners.ops.tls.uri_sans"},
		{name: "tls pins", edit: func(l *config.ListenerConfig) { l.TLS.PublicKeySHA256Pins = []string{"sha256:new"} }, want: "listeners.ops.tls.public_key_sha256_pins"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneReloadListeners(base)
			idx := 0
			if tc.want[:len("listeners.ops.")] == "listeners.ops." {
				idx = 1
			}
			tc.edit(&candidate.Listeners[idx])
			if got := ImmutableDiff(&base, &candidate); !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("ImmutableDiff() = %v, want [%s]", got, tc.want)
			}
		})
	}
}

func TestImmutableDiffListenersRejectsSetAndModeChanges(t *testing.T) {
	t.Parallel()

	base := reloadListenerConfig()
	tests := []struct {
		name string
		edit func(*config.Config)
		want []string
	}{
		{
			name: "add",
			edit: func(c *config.Config) {
				c.Listeners = append(c.Listeners, config.ListenerConfig{Name: "extra"})
			},
			want: []string{"listeners.extra: added"},
		},
		{
			name: "remove",
			edit: func(c *config.Config) { c.Listeners = c.Listeners[:1] },
			want: []string{"listeners.ops: removed"},
		},
		{
			name: "rename",
			edit: func(c *config.Config) { c.Listeners[0].Name = "builders" },
			want: []string{"listeners.builders: added", "listeners.ci: removed"},
		},
		{
			name: "explicit to legacy",
			edit: func(c *config.Config) { c.Listeners = nil },
			want: []string{"listeners: switching between legacy listen: and explicit listeners: requires a restart"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneReloadListeners(base)
			tc.edit(&candidate)
			if got := ImmutableDiff(&base, &candidate); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ImmutableDiff() = %v, want %v", got, tc.want)
			}
		})
	}

	legacy := config.Defaults()
	explicit := legacy
	explicit.Listeners = []config.ListenerConfig{{
		Name:            config.DefaultListenerName,
		ListenConfig:    legacy.Listen,
		AllowedProfiles: []string{config.WildcardProfile},
	}}
	want := []string{"listeners: switching between legacy listen: and explicit listeners: requires a restart"}
	if got := ImmutableDiff(&legacy, &explicit); !reflect.DeepEqual(got, want) {
		t.Fatalf("ImmutableDiff(legacy to explicit) = %v, want %v", got, want)
	}
}
