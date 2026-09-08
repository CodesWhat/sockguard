package buildkitrunner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFrontendCommandIsolation(t *testing.T) {
	opts := Options{Image: "docker.io/example/frontend@sha256:" + strings.Repeat("a", 64), RuntimeContext: "isolated", FrontendOptions: []string{"context=https://example.com/context", "build-arg:MESSAGE=hello world"}}
	args, err := frontendArgs(opts, "sockguard-test", "[]")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	for _, pair := range []string{"--context\nisolated", "--network\nnone", "--read-only", "--cap-drop\nALL", "--security-opt\nno-new-privileges", "--pids-limit\n128", "--memory\n512m", "--cpus\n1", "BUILDKIT_SESSION_ID="} {
		if !strings.Contains(joined, pair) {
			t.Fatalf("missing isolation constraint: %s", pair)
		}
	}
	if args[len(args)-1] != opts.Image {
		t.Fatal("frontend reference is not the final Docker argument")
	}
	for _, arg := range args {
		if arg == "-v" || arg == "--volume" || arg == "--mount" || arg == "--privileged" {
			t.Fatalf("unsafe runtime argument: %s", arg)
		}
	}
}

func TestFrontendRejectsMutableImageAndInvalidOptions(t *testing.T) {
	valid := Options{Image: "example/frontend@sha256:" + strings.Repeat("a", 64), RuntimeContext: "isolated"}
	for _, image := range []string{"example/frontend:latest", "--privileged", "example/frontend@sha256:abc", "example/frontend@sha256:" + strings.Repeat("A", 64)} {
		opts := valid
		opts.Image = image
		if _, err := frontendArgs(opts, "name", "[]"); err == nil {
			t.Fatalf("invalid image admitted: %s", image)
		}
	}
	for _, options := range [][]string{{"context=x", "context=y"}, {"context"}, {"=value"}, {"key=bad\x00value"}} {
		opts := valid
		opts.FrontendOptions = options
		if _, err := frontendArgs(opts, "name", "[]"); err == nil {
			t.Fatalf("ambiguous options admitted: %v", options)
		}
	}
	valid.RuntimeContext = ""
	if _, err := frontendArgs(valid, "name", "[]"); err == nil {
		t.Fatal("implicit runtime context admitted")
	}
}

func TestFrontendImagePreflight(t *testing.T) {
	for _, tc := range []struct {
		name         string
		wantErr      string
		wantCommands string
	}{
		{"cached", "", "image inspect,run,rm,container ls"},
		{"volumes", "declares volumes", "image inspect"},
		{"missing", "", "image inspect,pull,image inspect,run,rm,container ls"},
		{"pull-failure", "pull frontend image", "image inspect,pull"},
		{"inspect-failure", "inspect frontend image", "image inspect,pull,image inspect"},
		{"malformed", "volume count", "image inspect"},
		{"negative", "volume count", "image inspect"},
		{"multiple", "volume count", "image inspect"},
		{"empty", "volume count", "image inspect"},
		{"canceled", "context canceled", "image inspect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			script := `#!/bin/sh
printf '%s\t' "$@" >> "$FRONTEND_CALLS"
printf '\n' >> "$FRONTEND_CALLS"
shift 2
case "$1 $2" in
  'image inspect')
    case "$FRONTEND_CASE" in
      volumes) echo 1;;
      malformed) echo unknown;;
      negative) echo -1;;
      multiple) printf '0\n0\n';;
      empty) :;;
      canceled) exec sleep 30;;
      missing|pull-failure|inspect-failure)
        if [ ! -f "$FRONTEND_CALLS.pulled" ] || [ "$FRONTEND_CASE" = inspect-failure ]; then exit 1; fi
        echo 0;;
      *) echo 0;;
    esac;;
  'pull '*)
    if [ "$FRONTEND_CASE" = pull-failure ]; then exit 1; fi
    touch "$FRONTEND_CALLS.pulled";;
  'run '*) exec cat;;
  'rm '*) :;;
  'container ls') :;;
  *) exit 2;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("FRONTEND_CALLS", log)
			t.Setenv("FRONTEND_CASE", tc.name)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			canceled := make(chan struct{})
			if tc.name == "canceled" {
				go func() {
					defer close(canceled)
					for {
						if calls, err := os.ReadFile(log); err == nil && strings.HasSuffix(string(calls), "\n") {
							cancel()
							return
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(time.Millisecond):
						}
					}
				}()
			} else {
				close(canceled)
			}
			opts := Options{Image: "example/frontend@sha256:" + strings.Repeat("a", 64), RuntimeContext: "isolated"}
			p, err := startFrontend(ctx, opts, "sockguard-test", "[]")
			if p != nil {
				// Wait until the asynchronous runtime has recorded its launch.
				for {
					calls, _ := os.ReadFile(log)
					if strings.Contains(string(calls), "\trun\t") {
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(time.Millisecond):
					}
				}
				if closeErr := p.close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			<-canceled
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("error = %v, want %q", err, tc.wantErr)
			}
			calls, readErr := os.ReadFile(log)
			if readErr != nil {
				t.Fatal(readErr)
			}
			var commands []string
			for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
				args := strings.Split(strings.TrimSuffix(line, "\t"), "\t")
				if len(args) < 3 || args[0] != "--context" || args[1] != opts.RuntimeContext {
					t.Fatalf("lost runtime context: %q", line)
				}
				command := args[2]
				if command == "image" || command == "container" {
					command += " " + args[3]
				}
				commands = append(commands, command)
				if command == "image inspect" || command == "pull" || command == "run" {
					if args[len(args)-1] != opts.Image {
						t.Errorf("changed pinned image: %q", line)
					}
				}
				if command == "run" && !strings.Contains(line, "\t--pull=never\t") {
					t.Error("run can acquire an unchecked image")
				}
			}
			if got := strings.Join(commands, ","); got != tc.wantCommands {
				t.Errorf("commands = %s, want %s", got, tc.wantCommands)
			}
		})
	}
}
