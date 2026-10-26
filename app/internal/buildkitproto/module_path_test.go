package buildkitproto_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/auth"
	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/control"
	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/filesync"
	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/fsutiltypes"
	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/gateway"
	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/health"
	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/secrets"
	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/sshforward"
	_ "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/upload"
)

func TestGeneratedDescriptorModulePaths(t *testing.T) {
	count := 0
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		options, ok := fd.Options().(*descriptorpb.FileOptions)
		if !ok || !strings.HasPrefix(options.GetGoPackage(), "github.com/codeswhat/sockguard/") {
			return true
		}
		count++
		if !strings.HasPrefix(options.GetGoPackage(), "github.com/codeswhat/sockguard/v2/app/internal/buildkitproto/") {
			t.Errorf("%s: generated go_package = %q, want the v2 module path", fd.Path(), options.GetGoPackage())
		}
		return true
	})
	if count != 14 {
		t.Fatalf("checked %d generated descriptors, want all 14", count)
	}
}
