package buildkitrunner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var pinnedFrontend = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
var frontendOptionName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$`)

func frontendArgs(opts Options, name, workers string) ([]string, error) {
	if !pinnedFrontend.MatchString(opts.Image) {
		return nil, errors.New("frontend image must be pinned as repository@sha256:<64 lowercase hex digits>")
	}
	if opts.RuntimeContext == "" {
		return nil, errors.New("an explicit Docker runtime context is required")
	}
	if len(opts.FrontendOptions) > 64 {
		return nil, errors.New("at most 64 frontend options are supported")
	}
	args := []string{"--context", opts.RuntimeContext, "run", "--pull=never", "--rm", "-i", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", "--cpus", "1", "--env", "BUILDKIT_SESSION_ID=", "--env", "BUILDKIT_WORKERS=" + workers, "--env", "BUILDKIT_EXPORTEDPRODUCT=sockguard"}
	seen := map[string]bool{}
	for i, opt := range opts.FrontendOptions {
		key, _, ok := strings.Cut(opt, "=")
		if !ok || !frontendOptionName.MatchString(key) || strings.ContainsRune(opt, 0) || len(opt) > 8192 || seen[key] {
			return nil, fmt.Errorf("invalid or duplicate frontend option %q", key)
		}
		seen[key] = true
		args = append(args, "--env", fmt.Sprintf("BUILDKIT_FRONTEND_OPT_%d=%s", i, opt))
	}
	return append(args, opts.Image), nil
}

type pipeConn struct {
	read  *os.File
	write *os.File
	once  sync.Once
	err   error
}

func (c *pipeConn) Read(p []byte) (int, error)  { return c.read.Read(p) }
func (c *pipeConn) Write(p []byte) (int, error) { return c.write.Write(p) }
func (c *pipeConn) Close() error {
	c.once.Do(func() { c.err = errors.Join(c.read.Close(), c.write.Close()) })
	return c.err
}
func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddress("runner") }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddress("frontend") }
func (c *pipeConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return c.read.SetReadDeadline(t) }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return c.write.SetWriteDeadline(t) }

type pipeAddress string

func (a pipeAddress) Network() string { return "pipe" }
func (a pipeAddress) String() string  { return string(a) }

type frontendProcess struct {
	cmd  *exec.Cmd
	conn *pipeConn
	done chan struct{}
	err  error
	opts Options
	name string
}

func startFrontend(ctx context.Context, opts Options, name, workers string) (*frontendProcess, error) {
	args, err := frontendArgs(opts, name, workers)
	if err != nil {
		return nil, err
	}
	if err := preflightFrontendImage(ctx, opts); err != nil {
		return nil, err
	}
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = stdinRead.Close() }()
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		_ = stdinWrite.Close()
		return nil, err
	}
	defer func() { _ = stdoutWrite.Close() }()
	conn := &pipeConn{read: stdoutRead, write: stdinWrite}
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed Docker executable; frontendArgs validates the pinned image and constructs separate arguments without a shell.
	cmd.Stdin = stdinRead
	cmd.Stdout = stdoutWrite
	cmd.Stderr = opts.Stderr
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	process := &frontendProcess{cmd: cmd, conn: conn, done: make(chan struct{}), opts: opts, name: name}
	go func() { process.err = cmd.Wait(); _ = conn.Close(); close(process.done) }()
	return process, nil
}

func preflightFrontendImage(ctx context.Context, opts Options) error {
	inspect := func() ([]byte, error) {
		cmd := exec.CommandContext(ctx, "docker", "--context", opts.RuntimeContext, "image", "inspect", "--format", "{{len .Config.Volumes}}", opts.Image) // #nosec G204 -- fixed Docker command; runtime context is explicit operator input and the validated digest-pinned image is a separate argument, with no shell.
		cmd.WaitDelay = 2 * time.Second
		return cmd.Output()
	}
	output, err := inspect()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pull := exec.CommandContext(ctx, "docker", "--context", opts.RuntimeContext, "pull", opts.Image) // #nosec G204 -- fixed Docker command; runtime context is explicit operator input and the validated digest-pinned image is a separate argument, with no shell.
		pull.WaitDelay = 2 * time.Second
		pull.Stdout, pull.Stderr = opts.Stderr, opts.Stderr
		if err := pull.Run(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("pull frontend image: %w", err)
		}
		output, err = inspect()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("inspect frontend image: %w", err)
	}
	count, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid frontend image volume count: %w", err)
	}
	if count != 0 {
		return errors.New("frontend image declares volumes; writable image volumes are not allowed")
	}
	return nil
}

func (p *frontendProcess) close() error {
	_ = p.conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	remove := exec.CommandContext(ctx, "docker", "--context", p.opts.RuntimeContext, "rm", "-f", p.name) // #nosec G204 -- fixed Docker command; runtime context is explicit operator input and the container name is generated internally, with no shell.
	remove.WaitDelay = time.Second
	// --rm can win the race; verify the owned name is absent either way.
	_ = remove.Run()
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	<-p.done
	verifyCtx, stopVerify := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopVerify()
	inspect := exec.CommandContext(verifyCtx, "docker", "--context", p.opts.RuntimeContext, "container", "ls", "--all", "--filter", "name=^/"+p.name+"$", "--format", "{{.ID}}") // #nosec G204 -- fixed Docker command; runtime context is explicit operator input and the container name is generated internally, with no shell.
	inspect.WaitDelay = time.Second
	output, err := inspect.Output()
	if err != nil {
		return fmt.Errorf("verify frontend container cleanup: %w", err)
	}
	if strings.TrimSpace(string(output)) != "" {
		return fmt.Errorf("frontend container %s survived cleanup", p.name)
	}
	return nil
}
