package buildkitproxy

import "testing"

func TestValidateFsutilPath(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		maxLen     int
		wantDenied bool
		wantCode   int
		wantReason string
	}{
		{
			name:       "empty path is rejected",
			path:       "",
			wantDenied: true,
			wantCode:   grpcCodeInvalidArgument,
			wantReason: "buildkit_path_rejected",
		},
		{
			name:       "ordinary relative path is admitted",
			path:       "src/main.go",
			wantDenied: false,
		},
		{
			name:       "single path segment is admitted",
			path:       "Dockerfile",
			wantDenied: false,
		},
		{
			name:       "absolute path is rejected",
			path:       "/etc/passwd",
			wantDenied: true,
			wantCode:   grpcCodePermissionDenied,
			wantReason: "buildkit_path_rejected",
		},
		{
			name:       "leading .. traversal is rejected",
			path:       "../escape",
			wantDenied: true,
			wantCode:   grpcCodePermissionDenied,
			wantReason: "buildkit_path_rejected",
		},
		{
			name:       "embedded .. traversal is rejected",
			path:       "a/../../escape",
			wantDenied: true,
			wantCode:   grpcCodePermissionDenied,
			wantReason: "buildkit_path_rejected",
		},
		{
			name:       "trailing .. traversal is rejected",
			path:       "a/b/..",
			wantDenied: true,
			wantCode:   grpcCodePermissionDenied,
			wantReason: "buildkit_path_rejected",
		},
		{
			name:       "a filename merely containing dots is fine (not a .. segment)",
			path:       "a/..b../c",
			wantDenied: false,
		},
		{
			name:       "embedded NUL byte is rejected",
			path:       "a\x00b",
			wantDenied: true,
			wantCode:   grpcCodePermissionDenied,
			wantReason: "buildkit_path_rejected",
		},
		{
			name:       "path exceeding maxLen is rejected",
			path:       "abcdefghij",
			maxLen:     5,
			wantDenied: true,
			wantCode:   grpcCodeResourceExhausted,
			wantReason: "buildkit_path_rejected",
		},
		{
			name:       "path exactly at maxLen is admitted",
			path:       "abcde",
			maxLen:     5,
			wantDenied: false,
		},
		{
			name:       "maxLen <= 0 disables the length cap",
			path:       "a-very-long-path-that-would-otherwise-be-rejected",
			maxLen:     0,
			wantDenied: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := validateFsutilPath(tc.path, tc.maxLen)
			if tc.wantDenied {
				if d == nil {
					t.Fatal("validateFsutilPath() = nil, want a denial")
				}
				if d.code != tc.wantCode {
					t.Errorf("code = %d, want %d", d.code, tc.wantCode)
				}
				if d.reasonCode != tc.wantReason {
					t.Errorf("reasonCode = %q, want %q", d.reasonCode, tc.wantReason)
				}
				return
			}
			if d != nil {
				t.Fatalf("validateFsutilPath() = %+v, want nil (admitted)", d)
			}
		})
	}
}
