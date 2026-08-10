package buildkitproxy

import "testing"

func TestClassifyRegisteredMethods(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("registry is empty")
	}
	for m, want := range registry {
		t.Run(m.Endpoint.String()+"/"+m.Service+"/"+m.Method, func(t *testing.T) {
			if want == Deny {
				t.Fatalf("registry entry for %s/%s.%s is Deny — Deny entries add nothing over Classify's default and must not be registered; see DeniedExamples", m.Endpoint, m.Service, m.Method)
			}
			got := Classify(m.Endpoint, m.Service, m.Method)
			if got != want {
				t.Errorf("Classify(%s, %q, %q) = %s, want %s", m.Endpoint, m.Service, m.Method, got, want)
			}
		})
	}
}

func TestClassifyDeniedExamples(t *testing.T) {
	if len(DeniedExamples) == 0 {
		t.Fatal("DeniedExamples is empty")
	}
	for _, ex := range DeniedExamples {
		t.Run(ex.Endpoint.String()+"/"+ex.Service+"/"+ex.Method, func(t *testing.T) {
			got := Classify(ex.Endpoint, ex.Service, ex.Method)
			if got != Deny {
				t.Errorf("Classify(%s, %q, %q) = %s, want %s (documented deny-by-default example)", ex.Endpoint, ex.Service, ex.Method, got, Deny)
			}
		})
	}
}

func TestClassifyUnknownMethodDenies(t *testing.T) {
	cases := []struct {
		name     string
		endpoint Endpoint
		service  string
		method   string
	}{
		{"unknown service on grpc endpoint", EndpointGRPC, "moby.buildkit.v1.NotAService", "DoStuff"},
		{"unknown service on session endpoint", EndpointSession, "moby.notreal.v1.Bogus", "Whatever"},
		{"unknown method on a real mediated service", EndpointGRPC, "moby.buildkit.v1.Control", "TotallyMadeUp"},
		{"unknown method on a real deny-example service", EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", "TotallyMadeUp"},
		{"known method on the wrong endpoint", EndpointSession, "moby.buildkit.v1.Control", "Solve"},
		{"empty service and method", EndpointGRPC, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.endpoint, tc.service, tc.method)
			if got != Deny {
				t.Errorf("Classify(%s, %q, %q) = %s, want %s", tc.endpoint, tc.service, tc.method, got, Deny)
			}
		})
	}
}

func TestDispositionString(t *testing.T) {
	cases := map[Disposition]string{
		Deny:              "deny",
		Mediate:           "mediate",
		Passthrough:       "passthrough",
		Disposition(1000): "unknown",
	}
	for d, want := range cases {
		if got := d.String(); got != want {
			t.Errorf("Disposition(%d).String() = %q, want %q", d, got, want)
		}
	}
}

func TestEndpointString(t *testing.T) {
	cases := map[Endpoint]string{
		EndpointGRPC:    "/grpc",
		EndpointSession: "/session",
		Endpoint(1000):  "unknown",
	}
	for e, want := range cases {
		if got := e.String(); got != want {
			t.Errorf("Endpoint(%d).String() = %q, want %q", e, got, want)
		}
	}
}

func TestServiceAdmitted(t *testing.T) {
	cases := []struct {
		name     string
		endpoint Endpoint
		service  string
		want     bool
	}{
		{"grpc Control has admitted methods", EndpointGRPC, "moby.buildkit.v1.Control", true},
		{"grpc Health has admitted methods", EndpointGRPC, "grpc.health.v1.Health", true},
		{"session Auth has admitted methods", EndpointSession, "moby.filesync.v1.Auth", true},
		{"session Secrets has admitted methods", EndpointSession, "moby.buildkit.secrets.v1.Secrets", true},
		{"session SSH has admitted methods", EndpointSession, "moby.sshforward.v1.SSH", true},
		{"session FileSync has admitted methods", EndpointSession, "moby.filesync.v1.FileSync", true},
		{"session FileSend has admitted methods", EndpointSession, "moby.filesync.v1.FileSend", true},
		{"session Upload has admitted methods", EndpointSession, "moby.upload.v1.Upload", true},
		{"session LLBBridge is fully denied", EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", false},
		{"session Exporter is fully denied", EndpointSession, "moby.exporter.v1.Exporter", false},
		{"unknown service", EndpointSession, "moby.notreal.v1.Bogus", false},
		{"known service on wrong endpoint", EndpointSession, "moby.buildkit.v1.Control", false},
		{"empty service", EndpointGRPC, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ServiceAdmitted(tc.endpoint, tc.service); got != tc.want {
				t.Errorf("ServiceAdmitted(%s, %q) = %v, want %v", tc.endpoint, tc.service, got, tc.want)
			}
		})
	}
}

// TestServiceAdmittedByPolicy pins CodeRabbit's finding: the plain,
// policy-blind ServiceAdmitted isn't enough to decide what a session
// advertisement rewrite should keep, because a service can be
// registry-admitted (ServiceAdmitted true) while the resolved Policy still
// denies every one of its methods. ServiceAdmittedByPolicy must require both.
func TestServiceAdmittedByPolicy(t *testing.T) {
	cases := []struct {
		name     string
		endpoint Endpoint
		service  string
		policy   Policy
		want     bool
	}{
		{"admitted service allowed by policy", EndpointSession, "moby.filesync.v1.Auth", allowAllPolicy, true},
		{"admitted service NOT allowed by policy", EndpointSession, "moby.filesync.v1.Auth", Policy{}, false},
		{"registered service whose only registered method the policy denies", EndpointSession, "moby.filesync.v1.FileSync", Policy{Session: SessionPolicy{Auth: AuthPolicy{Allow: true}}}, false},
		{"fully-denied service, even under a fully-permissive policy", EndpointSession, "moby.buildkit.v1.frontend.LLBBridge", allowAllPolicy, false},
		{"unknown service", EndpointSession, "moby.notreal.v1.Bogus", allowAllPolicy, false},
		{"known service on the wrong endpoint", EndpointSession, "moby.buildkit.v1.Control", allowAllPolicy, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ServiceAdmittedByPolicy(tc.endpoint, tc.service, tc.policy); got != tc.want {
				t.Errorf("ServiceAdmittedByPolicy(%s, %q, policy) = %v, want %v", tc.endpoint, tc.service, got, tc.want)
			}
		})
	}
}

// TestNoOverlapBetweenRegistryAndDeniedExamples guards against the registry
// and DeniedExamples silently disagreeing about the same method — which
// would mean either an accidental duplicate deny row (harmless) or, worse,
// a method someone believes is denied (per DeniedExamples) that is actually
// registered as Mediate/Passthrough (a real policy bug Classify would mask
// because map lookup only ever returns one answer).
func TestNoOverlapBetweenRegistryAndDeniedExamples(t *testing.T) {
	for _, ex := range DeniedExamples {
		key := method{ex.Endpoint, ex.Service, ex.Method}
		if d, ok := registry[key]; ok {
			t.Errorf("%s/%s.%s is listed in both registry (%s) and DeniedExamples", ex.Endpoint, ex.Service, ex.Method, d)
		}
	}
}
