package filter

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"testing"
	"unicode/utf8"
)

// fuzzBindRemapPaths turns arbitrary fuzz strings into a from/to pair the
// config validator would accept: absolute, clean, not the root, no ':' or ',',
// no control characters, and neither containing the other. Validation rejects
// every other pair, so the remap contract only has to hold for these.
func fuzzBindRemapPaths(rawFrom, rawTo string) (from, to string, ok bool) {
	for _, p := range []string{rawFrom, rawTo} {
		if strings.ContainsAny(p, ":,") || containsFuzzControl(p) {
			return "", "", false
		}
	}
	from = path.Clean("/" + rawFrom)
	to = path.Clean("/" + rawTo)
	if from == "/" || to == "/" || bindPathHasPrefix(from, to) || bindPathHasPrefix(to, from) {
		return "", "", false
	}
	return from, to, true
}

func containsFuzzControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// FuzzRemapBindSourcePath checks remap_bind_source's lexical rewrite. A
// rewritten source must stay under the mapped host prefix, must be a clean
// path with no ".." component, must never be rewritten a second time, and an
// unmatched source must come back untouched. Bind specs keep their target and
// options byte for byte.
func FuzzRemapBindSourcePath(f *testing.F) {
	f.Add("/builds", "/srv/runner/builds", "/builds/job1/src")
	f.Add("/builds", "/srv/runner/builds", "/builds")
	f.Add("/builds", "/srv/runner/builds", "/builds2/x")
	f.Add("/builds", "/srv/runner/builds", "/builds/../etc")
	f.Add("/builds", "/srv/runner/builds", "/x/../builds/a")
	f.Add("/builds", "/srv/runner/builds", "/builds/a/../../etc")
	f.Add("/builds", "/srv/runner/builds", "/builds//a/./b/")
	f.Add("/builds", "/srv/runner/builds", "/builds/a\nb")
	f.Add("/builds", "/srv/runner/builds", "named-volume")
	f.Add("/builds", "/srv/runner/builds", "./builds/a")
	f.Add("/a/b", "/c", "/a/b/c/d")
	f.Add("/a/b", "/c", "/a")

	f.Fuzz(func(t *testing.T, rawFrom, rawTo, source string) {
		from, to, ok := fuzzBindRemapPaths(rawFrom, rawTo)
		if !ok {
			t.Skip()
		}

		next, matched, err := remapBindSourcePath(source, from, to)
		if err != nil {
			if next != "" || matched {
				t.Fatalf("error result carried a value: next=%q matched=%v err=%v", next, matched, err)
			}
			if !strings.HasPrefix(source, "/") {
				t.Fatalf("a non-absolute source %q must never be refused: %v", source, err)
			}
			return
		}
		if !matched {
			if next != source {
				t.Fatalf("unmatched source was rewritten: %q -> %q", source, next)
			}
			return
		}

		if !strings.HasPrefix(source, "/") {
			t.Fatalf("non-absolute source %q was rewritten to %q", source, next)
		}
		if !bindPathHasPrefix(next, to) {
			t.Fatalf("rewritten source %q escapes the mapped prefix %q (source %q)", next, to, source)
		}
		if path.Clean(next) != next {
			t.Fatalf("rewritten source %q is not a clean path (source %q)", next, source)
		}
		for _, seg := range strings.Split(next, "/") {
			if seg == ".." {
				t.Fatalf("rewritten source %q has a '..' component (source %q)", next, source)
			}
		}
		if containsFuzzControl(next) {
			t.Fatalf("rewritten source %q carries a control character (source %q)", next, source)
		}
		if !bindPathHasPrefix(path.Clean(source), from) {
			t.Fatalf("source %q was rewritten without matching %q", source, from)
		}

		again, matchedAgain, err := remapBindSourcePath(next, from, to)
		if err != nil || matchedAgain || again != next {
			t.Fatalf("rewrite is not final: %q -> %q -> %q (matched=%v err=%v)", source, next, again, matchedAgain, err)
		}

		// The same source inside a bind spec keeps everything after the first colon.
		if strings.Contains(source, ":") {
			return
		}
		spec := source + ":/work:ro"
		specNext, specMatched, err := remapBindSpec(spec, from, to)
		if err != nil || !specMatched || specNext != next+":/work:ro" {
			t.Fatalf("bind spec %q rewrote to %q (matched=%v err=%v), want %q", spec, specNext, specMatched, err, next+":/work:ro")
		}
	})
}

// fuzzDeviceGrantEntry is one allowed_device_requests entry the fuzzer builds
// from a driver, an optional exact device ID, an optional exact option and an
// optional exact count.
type fuzzDeviceGrantEntry struct {
	driver   string
	deviceID string
	optKey   string
	optVal   string
	hasID    bool
	hasOpt   bool
	count    *int
}

func (g fuzzDeviceGrantEntry) option() AllowedDeviceRequestEntry {
	e := AllowedDeviceRequestEntry{Driver: g.driver, Count: g.count}
	if g.hasID {
		e.DeviceIDs = []string{g.deviceID}
	}
	if g.hasOpt {
		e.Options = map[string]string{g.optKey: g.optVal}
	}
	return e
}

// grants is the independent reference: does this single entry cover req? It
// is the contract from the docs, not the implementation, and it deliberately
// requires one entry to satisfy driver, IDs, options and count together so a
// request cannot take its IDs from one grant and its options from another.
func (g fuzzDeviceGrantEntry) grants(req dockerDeviceRequest) bool {
	if !strings.EqualFold(strings.TrimSpace(req.Driver), strings.TrimSpace(g.driver)) {
		return false
	}
	if g.count != nil && req.Count != *g.count {
		return false
	}
	if g.hasID {
		if len(req.DeviceIDs) == 0 || req.Count != 0 {
			return false
		}
		for _, id := range req.DeviceIDs {
			if id != g.deviceID {
				return false
			}
		}
	}
	if g.hasOpt {
		for k, v := range req.Options {
			if k != g.optKey || v != g.optVal {
				return false
			}
		}
	}
	return true
}

// FuzzDeviceRequestGrant checks the exact-grant matcher for
// allowed_device_requests. Whenever a request is allowed, one single grant
// entry must cover its driver, every device ID, every option and its count,
// and a CDI-driver request naming anything but a qualified CDI device must be
// denied while no host device is allowlisted. A request copied from a grant
// must be allowed.
func FuzzDeviceRequestGrant(f *testing.F) {
	f.Add("nvidia", "nvidia", "0", "0", "k", "v", "k", "v", uint8(0b0011), 0)
	f.Add("nvidia", "NVIDIA", "0", "1", "k", "v", "k", "w", uint8(0b0011), 0)
	f.Add("nvidia", "nvidia", "0", "0", "k", "v", "k2", "v", uint8(0b0011), 0)
	f.Add("nvidia", "nvidia", "0", "0", "k", "v", "", "", uint8(0b0001), 0)
	f.Add("nvidia", "nvidia", "all", "0", "k", "v", "", "", uint8(0b0001), -1)
	f.Add("cdi", "cdi", "nvidia.com/gpu=0", "nvidia.com/gpu=0", "", "", "", "", uint8(0b0001), 0)
	f.Add("cdi", "cdi", "/dev/mem", "/dev/mem", "", "", "", "", uint8(0b0001), 0)
	f.Add("cdi", "CDI", "/dev/mem", "/dev/mem", "", "", "", "", uint8(0b0001), 0)
	f.Add("cdi", "cdi", "vendor/class=a", "/dev/kvm", "", "", "", "", uint8(0b0001), 0)
	f.Add(" nvidia ", "nvidia", "0", "0", "k", "v", "k", "v", uint8(0b0011), 0)
	f.Add("", "", "0", "0", "k", "v", "k", "v", uint8(0b0011), 0)
	f.Add("nvidia", "nvidia", "0", "0", "k", "v", "k", "v", uint8(0b1011), 2)

	f.Fuzz(func(t *testing.T, grantDriver, reqDriver, grantID, reqID, grantKey, grantVal, reqKey, reqVal string, flags uint8, count int) {
		if count < -3 || count > 3 {
			t.Skip()
		}
		grantA := fuzzDeviceGrantEntry{
			driver: grantDriver, deviceID: grantID, optKey: grantKey, optVal: grantVal,
			hasID: flags&1 != 0, hasOpt: flags&2 != 0,
		}
		// A second entry with the request-side values, so a request can only pass
		// by satisfying one entry whole, never by mixing the two.
		grantB := fuzzDeviceGrantEntry{
			driver: grantDriver, deviceID: reqID, optKey: reqKey, optVal: reqVal,
			hasID: flags&4 != 0, hasOpt: flags&8 != 0,
		}
		if flags&16 != 0 {
			c := count
			grantB.count = &c
		}
		grants := []fuzzDeviceGrantEntry{grantA, grantB}

		opts := ContainerCreateOptions{AllowAllDevices: flags&32 != 0}
		for _, g := range grants {
			opts.AllowedDeviceRequests = append(opts.AllowedDeviceRequests, g.option())
		}
		policy := newContainerCreatePolicy(opts)

		req := dockerDeviceRequest{Driver: reqDriver, Count: count}
		if flags&64 != 0 {
			req.DeviceIDs = []string{reqID}
		}
		if flags&128 != 0 {
			req.Options = map[string]string{reqKey: reqVal}
		}
		reason := policy.denyDeviceRequestsReason([]dockerDeviceRequest{req})

		if reason == "" {
			covered := false
			for _, g := range grants {
				if strings.TrimSpace(g.driver) != "" && g.grants(req) {
					covered = true
				}
			}
			if !covered {
				t.Fatalf("request %+v was allowed but no single grant covers it: grants=%+v", req, grants)
			}
			if !opts.AllowAllDevices && strings.EqualFold(strings.TrimSpace(req.Driver), "cdi") {
				for _, id := range req.DeviceIDs {
					if !IsQualifiedCDIDevice(id) {
						t.Fatalf("cdi request naming %q was allowed with no host device allowlisted", id)
					}
				}
			}
		}

		// A request that is a verbatim copy of a grant is allowed.
		if grantA.hasID && grantA.hasOpt && strings.TrimSpace(grantA.driver) != "" &&
			!strings.EqualFold(strings.TrimSpace(grantA.driver), "cdi") {
			self := dockerDeviceRequest{
				Driver:    grantA.driver,
				DeviceIDs: []string{grantA.deviceID},
				Options:   map[string]string{grantA.optKey: grantA.optVal},
			}
			if r := policy.denyDeviceRequestsReason([]dockerDeviceRequest{self}); r != "" {
				t.Fatalf("a request copied from a grant was denied: %+v: %s", self, r)
			}
		}
	})
}

// FuzzExecAllowedUsers checks the exec allowed_users pin. With a non-empty
// list a user is allowed exactly when it equals a trimmed entry byte for byte
// ("" is a real entry meaning User unset). An empty list places no pin. Every
// other gate is opened so the pin is the only thing under test, and the same
// verdict must come out of the exec-create body decoder.
func FuzzExecAllowedUsers(f *testing.F) {
	f.Add("app", "root", "", uint8(2), "app")
	f.Add("app", "root", "", uint8(2), "app:wheel")
	f.Add("1000", "", "", uint8(1), "01000")
	f.Add("1000", "", "", uint8(1), "1000")
	f.Add("", "app", "", uint8(1), "")
	f.Add("", "app", "", uint8(1), "app")
	f.Add(" app ", "", "", uint8(1), "app")
	f.Add(" app ", "", "", uint8(1), " app ")
	f.Add("app", "", "", uint8(0), "anything")
	f.Add("app", "", "", uint8(0), "")
	f.Add("App", "", "", uint8(1), "app")
	f.Add("app", "", "", uint8(1), "app\n")
	f.Add("0", "root", "", uint8(2), "root")

	f.Fuzz(func(t *testing.T, a, b, c string, n uint8, user string) {
		entries := []string{a, b, c}[:int(n)%4]
		policy := newExecPolicy(ExecOptions{
			AllowedUsers:     entries,
			AllowRootUser:    true,
			AllowPrivileged:  true,
			AllowBlindWrites: true,
		})

		want := len(entries) == 0
		for _, e := range entries {
			if strings.TrimSpace(e) == user {
				want = true
			}
		}

		reason := policy.denyReason(ExecInspectResult{User: user})
		if (reason == "") != want {
			t.Fatalf("allowed_users=%q user=%q: reason=%q, want allowed=%v", entries, user, reason, want)
		}

		if !utf8.ValidString(user) {
			return
		}
		body, err := json.Marshal(map[string]any{"User": user, "Cmd": []string{"true"}})
		if err != nil {
			t.Fatal(err)
		}
		req := newJSONInspectorFuzzRequest(http.MethodPost, "/containers/abc/exec", "", body)
		defer drainFuzzRequestBody(req)
		bodyReason, err := policy.inspectCreate(nil, req)
		if err != nil {
			t.Fatalf("inspectCreate error for user %q: %v", user, err)
		}
		if (bodyReason == "") != want {
			t.Fatalf("exec create body: allowed_users=%q user=%q: reason=%q, want allowed=%v", entries, user, bodyReason, want)
		}
	})
}
