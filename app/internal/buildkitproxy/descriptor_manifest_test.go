package buildkitproxy

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	bkauth "github.com/codeswhat/sockguard/app/internal/buildkitproto/auth"
	bkcontrol "github.com/codeswhat/sockguard/app/internal/buildkitproto/control"
	bkfilesync "github.com/codeswhat/sockguard/app/internal/buildkitproto/filesync"
	bkhealth "github.com/codeswhat/sockguard/app/internal/buildkitproto/health"
	bksecrets "github.com/codeswhat/sockguard/app/internal/buildkitproto/secrets"
	bksshforward "github.com/codeswhat/sockguard/app/internal/buildkitproto/sshforward"
	bkupload "github.com/codeswhat/sockguard/app/internal/buildkitproto/upload"
)

// vendoredFileDescriptors lists every generated buildkitproto file whose
// service/method definitions this test treats as ground truth — i.e. every
// vendored proto that actually declares a gRPC service (fsutiltypes,
// sourcepolicy, and pb are message-only and have no service to check).
var vendoredFileDescriptors = []protoreflect.FileDescriptor{
	bkcontrol.File_github_com_moby_buildkit_api_services_control_control_proto,
	bkhealth.File_grpc_health_v1_health_proto,
	bkauth.File_github_com_moby_buildkit_session_auth_auth_proto,
	bksecrets.File_github_com_moby_buildkit_session_secrets_secrets_proto,
	bksshforward.File_github_com_moby_buildkit_session_sshforward_ssh_proto,
	bkfilesync.File_github_com_moby_buildkit_session_filesync_filesync_proto,
	bkupload.File_github_com_moby_buildkit_session_upload_upload_proto,
}

// realMethods walks every vendored file descriptor that declares a service
// and returns the set of fully-qualified "service.method" full names it
// actually defines — the ground truth registry.go and DeniedExamples are
// checked against for every service that has one.
func realMethods(t *testing.T) map[string]bool {
	t.Helper()
	out := make(map[string]bool)
	for _, fd := range vendoredFileDescriptors {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			svc := services.Get(i)
			methods := svc.Methods()
			for j := 0; j < methods.Len(); j++ {
				out[string(svc.FullName())+"."+string(methods.Get(j).Name())] = true
			}
		}
	}
	return out
}

// realServices is the set of fully-qualified service names the vendored
// descriptors actually declare — used to scope the cross-check to services
// this phase vendored messages for. registry.go/DeniedExamples entries for
// services with NO vendored descriptor (LLBBridge, Exporter, PolicyVerifier,
// containerd content, OTLP trace) are intentionally out of scope here; see
// PROVENANCE.md's "Deliberately NOT vendored" section for why.
func realServices(t *testing.T) map[string]bool {
	t.Helper()
	out := make(map[string]bool)
	for _, fd := range vendoredFileDescriptors {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			out[string(services.Get(i).FullName())] = true
		}
	}
	return out
}

// descriptorTrimExceptions lists (service, method) pairs that are real
// upstream RPCs on a service buildkitproto DOES vendor a descriptor for, but
// whose message types were deliberately left out of that vendored
// descriptor (see control.proto's file header and PROVENANCE.md: only
// Solve/Status and their transitive types were generated for
// moby.buildkit.v1.Control — Info/ListWorkers are Passthrough and never
// need a decoded message, so no InfoRequest/ListWorkersRequest were
// vendored). Without this exception list, TestRegistryMatchesVendoredDescriptors
// would demand a full-service vendoring this phase's own trim deliberately
// avoids — see "Only generate messages actually needed" in the issue #185
// phase 1 scope.
var descriptorTrimExceptions = map[string]bool{
	"moby.buildkit.v1.Control.Info":               true,
	"moby.buildkit.v1.Control.ListWorkers":        true,
	"moby.buildkit.v1.Control.Session":            true,
	"moby.buildkit.v1.Control.Prune":              true,
	"moby.buildkit.v1.Control.DiskUsage":          true,
	"moby.buildkit.v1.Control.ListenBuildHistory": true,
	"moby.buildkit.v1.Control.UpdateBuildHistory": true,
}

// TestRegistryMatchesVendoredDescriptors is #185 phase 1's descriptor-vs-
// registry golden test: for every service buildkitproto actually vendored a
// descriptor for, every method registry.go or DeniedExamples names for that
// service must be a real RPC on that service (unless explicitly excepted
// above), and conversely — every real RPC on that service must be
// classified somewhere (Mediate/Passthrough in registry, or Deny in
// DeniedExamples). This catches typos in either table AND upstream method
// renames/removals a future compatibility bump would otherwise let slide
// silently, tying the "committed descriptor manifest" (registry.go +
// DeniedExamples) to the generated code it must stay in sync with.
func TestRegistryMatchesVendoredDescriptors(t *testing.T) {
	services := realServices(t)
	methods := realMethods(t)

	claimed := make(map[string]string) // "service.method" -> where it's claimed
	for m, d := range registry {
		if !services[m.Service] {
			continue // out of scope: no vendored descriptor for this service
		}
		full := m.Service + "." + m.Method
		if descriptorTrimExceptions[full] {
			continue
		}
		if !methods[full] {
			t.Errorf("registry claims %s (%s) but no such method exists on the vendored %s descriptor", full, d, m.Service)
		}
		claimed[full] = "registry"
	}
	for _, ex := range DeniedExamples {
		if !services[ex.Service] {
			continue
		}
		full := ex.Service + "." + ex.Method
		if descriptorTrimExceptions[full] {
			continue
		}
		if !methods[full] {
			t.Errorf("DeniedExamples claims %s but no such method exists on the vendored %s descriptor", full, ex.Service)
		}
		if prev, ok := claimed[full]; ok {
			t.Errorf("%s is claimed by both %s and DeniedExamples", full, prev)
		}
		claimed[full] = "DeniedExamples"
	}

	for full := range methods {
		if _, ok := claimed[full]; !ok {
			t.Errorf("%s exists on a vendored descriptor but is classified nowhere (add it to registry or DeniedExamples)", full)
		}
	}
}
