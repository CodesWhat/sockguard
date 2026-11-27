package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/config"
)

// raceResult is one racer's answer.
type raceResult struct {
	owner  string
	status int
	body   string
}

// raceTwoOwners sends one request per owner at once, B a beat after A, so that
// with a daemon that stalls its inspects, B's lookup lands inside A's
// lookup-then-write window unless the proxy serializes the two.
func raceTwoOwners(t *testing.T, h *tenancyHarness, method string, pathFor func(owner string) string, bodyFor func(owner string) string) map[string]raceResult {
	t.Helper()
	var mu sync.Mutex
	results := map[string]raceResult{}
	var wg sync.WaitGroup
	for i, who := range []struct{ owner, remote string }{{"A", ownerScopesIPA}, {"B", ownerScopesIPB}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 40 * time.Millisecond)
			status, body, err := h.try(who.remote, method, pathFor(who.owner), bodyFor(who.owner))
			if err != nil {
				t.Errorf("%s %s: %v", who.owner, pathFor(who.owner), err)
			}
			mu.Lock()
			results[who.owner] = raceResult{who.owner, status, body}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

// exactlyOneWinner asserts one racer succeeded and the other was refused with
// a status in refusals, and returns the winner.
func exactlyOneWinner(t *testing.T, what string, results map[string]raceResult, refusals ...int) string {
	t.Helper()
	var winners, losers []raceResult
	for _, r := range results {
		if r.status < 300 {
			winners = append(winners, r)
		} else {
			losers = append(losers, r)
		}
	}
	if len(winners) != 1 || len(losers) != 1 {
		t.Fatalf("%s: A=%d %s | B=%d %s, want exactly one winner", what, results["A"].status, results["A"].body, results["B"].status, results["B"].body)
	}
	ok := false
	for _, s := range refusals {
		ok = ok || losers[0].status == s
	}
	if !ok {
		t.Errorf("%s: loser status = %d (%s), want one of %v", what, losers[0].status, losers[0].body, refusals)
	}
	return winners[0].owner
}

// TestServeChainTwoOwnersRacingOnePodmanSecretNameHaveOneWinner is the race
// the keyed locks exist for. Each owner's preflight reads "no such secret"
// from a daemon that stalls its inspects, and Podman's replace then makes
// whichever create lands second take the secret from the first. Without the
// lock both succeed and the first owner's secret is gone.
func TestServeChainTwoOwnersRacingOnePodmanSecretNameHaveOneWinner(t *testing.T) {
	h := newTenancyHarness(t, true, nil)
	h.daemon.inspectDelay = 120 * time.Millisecond
	results := raceTwoOwners(t, h, http.MethodPost,
		func(string) string { return "/v1.45/libpod/secrets/create?name=shared&replace=true" },
		func(owner string) string { return "data-of-" + owner })
	winner := exactlyOneWinner(t, "podman secret replace", results, http.StatusForbidden)
	if got := h.daemon.dataOf("secret", "shared"); got != "data-of-"+winner {
		t.Errorf("stored secret data = %q, want the winner's (%s)", got, winner)
	}
	if owner, _ := h.daemon.ownerOf("secret", "shared"); owner != winner {
		t.Errorf("stored secret owner = %q, want %s", owner, winner)
	}
	for _, r := range results {
		if r.owner != winner && strings.Contains(r.body, "data-of-") {
			t.Errorf("loser saw winner data: %s", r.body)
		}
	}
}

// TestServeChainTwoOwnersRacingOneNameHaveOneWinner races the other
// create-by-name routes, with and without a stalled daemon.
func TestServeChainTwoOwnersRacingOneNameHaveOneWinner(t *testing.T) {
	for _, tc := range []struct {
		name, kind, method, path string
		body                     func(owner string) string
		podman                   bool
		refusals                 []int
	}{
		{"docker volume", "volume", "POST", "/v1.45/volumes/create", func(string) string { return `{"Name":"shared"}` }, false, []int{403}},
		{"libpod volume", "volume", "POST", "/v1.45/libpod/volumes/create", func(string) string { return `{"Name":"shared"}` }, true, []int{403}},
		{"docker network", "network", "POST", "/v1.45/networks/create", func(string) string { return `{"Name":"shared"}` }, false, []int{403, 409}},
		{"libpod network ignoreIfExists", "network", "POST", "/v1.45/libpod/networks/create?ignoreIfExists=true", func(string) string { return `{"name":"shared"}` }, true, []int{403}},
		{"docker secret", "secret", "POST", "/v1.45/secrets/create", func(string) string { return `{"Name":"shared","Data":"eA=="}` }, false, []int{403, 409}},
		{"libpod secret ignore", "secret", "POST", "/v1.45/libpod/secrets/create?name=shared&ignore=true", func(o string) string { return "data-of-" + o }, true, []int{403}},
		{"container name", "container", "POST", "/v1.45/containers/create?name=shared", func(string) string { return `{"Image":"x"}` }, false, []int{403, 409}},
	} {
		for _, delay := range []time.Duration{0, 80 * time.Millisecond} {
			t.Run(tc.name+"/delay="+delay.String(), func(t *testing.T) {
				h := newTenancyHarness(t, tc.podman, nil)
				h.daemon.add("image", "x", "", nil) // unowned image both may use
				h.daemon.inspectDelay = delay
				results := raceTwoOwners(t, h, tc.method, func(string) string { return tc.path }, tc.body)
				winner := exactlyOneWinner(t, tc.name, results, tc.refusals...)
				if owner, ok := h.daemon.ownerOf(tc.kind, "shared"); !ok || owner != winner {
					t.Errorf("stored %s owner = %q (found %v), want winner %s", tc.kind, owner, ok, winner)
				}
				for _, r := range results {
					if r.owner != winner && strings.Contains(r.body, `"`+tenancyLabelKey+`":"`+winner+`"`) {
						t.Errorf("loser saw the winner's labels: %s", r.body)
					}
				}
			})
		}
	}
}

// TestServeChainTwoOwnersRacingOneImageNameHaveOneWinner races two retags onto
// one name. The daemon moves the name off whichever image held it, so without
// the lock the second retag silently takes the name from the first owner.
func TestServeChainTwoOwnersRacingOneImageNameHaveOneWinner(t *testing.T) {
	h := newTenancyHarness(t, false, nil)
	h.daemon.add("image", "a-img:1", "A", nil)
	h.daemon.add("image", "b-img:1", "B", nil)
	h.daemon.inspectDelay = 120 * time.Millisecond
	results := raceTwoOwners(t, h, http.MethodPost,
		func(owner string) string {
			return "/v1.45/images/" + strings.ToLower(owner) + "-img:1/tag?repo=shared&tag=1"
		},
		func(string) string { return "" })
	winner := exactlyOneWinner(t, "image retag", results, http.StatusForbidden)
	if owner, ok := h.daemon.ownerOf("image", "shared:1"); !ok || owner != winner {
		t.Errorf("shared:1 owner = %q (found %v), want winner %s", owner, ok, winner)
	}
}

// The first retag pauses after its destination preflight, while an alias of
// that same Docker Hub name arrives under the second owner.
func TestServeChainImageAliasesShareCreateLock(t *testing.T) {
	socketPath := shortSocketPath(t, "image-alias")
	daemon := &tenancyDaemon{}
	daemon.add("image", "a-img:1", "A", nil)
	daemon.add("image", "b-img:1", "B", nil)
	firstWrite := make(chan struct{})
	resumeFirst := make(chan struct{})
	var resumeOnce sync.Once
	resume := func() { resumeOnce.Do(func() { close(resumeFirst) }) }
	t.Cleanup(resume)
	canonical := func(ref string) string {
		switch ref {
		case "shared:1", "library/shared:1", "docker.io/shared:1", "docker.io/library/shared:1", "index.docker.io/library/shared:1":
			return "docker.io/library/shared:1"
		default:
			return ref
		}
	}
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1.45")
		if r.Method == http.MethodGet && strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json") {
			ref := strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")
			daemon.mu.Lock()
			defer daemon.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			daemon.inspect(w, "image", canonical(ref))
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(path, "/tag") {
			if strings.Contains(path, "/a-img:1/") {
				close(firstWrite)
				select {
				case <-resumeFirst:
				case <-r.Context().Done():
					return
				}
			}
			query := r.URL.Query()
			ref := canonical(query.Get("repo") + ":" + query.Get("tag"))
			repo, tag, _ := strings.Cut(ref, ":")
			query.Set("repo", repo)
			query.Set("tag", tag)
			r.URL.RawQuery = query.Encode()
		}
		daemon.ServeHTTP(w, r)
	}))
	cfg := ownerScopesConfig(socketPath)
	cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "POST", Path: "/images/*/tag"}, Action: "allow"}}
	for i := range cfg.Clients.Profiles {
		cfg.Clients.Profiles[i].Rules = cfg.Rules
	}
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatal(err)
	}
	handler := buildServeHandler(t, &cfg, newDiscardLogger(), nil, rules, newServeTestDeps())
	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodPost, "/v1.45/images/a-img:1/tag?repo=shared&tag=1", nil)
	firstReq.RemoteAddr = ownerScopesIPA
	firstDone := make(chan struct{})
	go func() { defer close(firstDone); handler.ServeHTTP(first, firstReq) }()
	select {
	case <-firstWrite:
	case <-firstDone:
		t.Fatalf("first retag stopped: %d %s", first.Code, first.Body.String())
	case <-time.After(2 * time.Second):
		t.Fatal("first retag did not reach daemon")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/v1.45/images/b-img:1/tag?repo=docker.io/library/shared&tag=1", nil).WithContext(ctx)
	secondReq.RemoteAddr = ownerScopesIPB
	handler.ServeHTTP(second, secondReq)
	resume()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first retag did not finish")
	}
	if second.Code != http.StatusServiceUnavailable {
		t.Errorf("alias retag status = %d, body %s; want 503 while the first owner holds its name", second.Code, second.Body.String())
	}
	if first.Code != http.StatusCreated {
		t.Errorf("first retag status = %d, body %s", first.Code, first.Body.String())
	}
	if owner, ok := daemon.ownerOf("image", "docker.io/library/shared:1"); !ok || owner != "A" {
		t.Errorf("stored alias owner = %q (found %v), want A", owner, ok)
	}
	if got := daemon.mutations(); len(got) != 1 {
		t.Errorf("daemon writes = %v, want first owner's retag only", got)
	}
}
