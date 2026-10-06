package ownership

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/v2/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/v2/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v2/app/internal/filter"
	"github.com/codeswhat/sockguard/v2/app/internal/logging"
	"github.com/codeswhat/sockguard/v2/app/internal/upstreamflavor"
)

// podman_secrets_test.go is the owner-isolation half of the Docker-compat
// GET /secrets refusal on a Podman upstream. The visibility half lives in
// internal/visibility/podman_secrets_test.go and the both-layers case in
// label_filter_compose_test.go.

// podmanSecretsUpstreamForTest answers GET /secrets the way Podman v5.8.1
// does: compat.ListSecrets runs abi.SecretList, which runs every secret
// through utils.IfPassesSecretsFilter, whose switch accepts only "name" and
// "id" and returns fmt.Errorf("invalid filter %q", key) on anything else;
// utils.InternalServerError turns that into a 500.
func podmanSecretsUpstreamForTest(t *testing.T, reached *bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reached != nil {
			*reached = true
		}
		decoded, err := dockerfilters.Decode(r.URL.Query().Get("filters"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for key := range decoded {
			switch strings.ToLower(key) {
			case "name", "id":
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"message": fmt.Sprintf("invalid filter %q", key),
				})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ID":"s-1","Spec":{"Name":"api-key","Labels":{}}}]`))
	})
}

// TestPodmanCompatSecretListAnswers500ForTheOwnerLabelFilter is the bug, held
// as a positive control on the fake upstream. Owner isolation injects the
// owner label into GET /secrets through needsOwnerFilter, which is right on
// dockerd and a 500 on Podman. If this stops failing, the fake upstream no
// longer models Podman.
func TestPodmanCompatSecretListAnswers500ForTheOwnerLabelFilter(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{
		Owner:          "team-a",
		UpstreamFlavor: upstreamflavor.Docker,
	}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(podmanSecretsUpstreamForTest(t, &reached))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("the Docker-flavored path must still forward GET /secrets upstream")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; the fake upstream no longer models Podman's invalid-filter 500", rec.Code, http.StatusInternalServerError)
	}
}

// TestPodmanCompatSecretListRefusedUnderOwnerIsolation is the fix: an
// owner-only deployment on a Podman upstream gets a 403 before the daemon is
// contacted, rather than the 500 above.
func TestPodmanCompatSecretListRefusedUnderOwnerIsolation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "versioned path", method: http.MethodGet, target: "/v1.53/secrets"},
		{name: "bare path", method: http.MethodGet, target: "/secrets"},
		{name: "normalized path", method: http.MethodGet, target: "/v1.53/containers/../secrets"},
		{name: "podman version grammar", method: http.MethodGet, target: "/v5.8.1/secrets"},
		{name: "head", method: http.MethodHead, target: "/v1.53/secrets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reached := false
			handler := middlewareWithDeps(testLogger(), Options{
				Owner:          "team-a",
				UpstreamFlavor: upstreamflavor.Podman,
			}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(podmanSecretsUpstreamForTest(t, &reached))

			// Warn mode must not forward it, matching
			// denyUnscopeableLibpodRead.
			meta := &logging.RequestMeta{RolloutMode: "warn"}
			req := httptest.NewRequest(tt.method, tt.target, nil)
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if reached {
				t.Fatal("the refused request reached Podman's secret list")
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if meta.ReasonCode != reasonCodeOwnerPodmanSecretList {
				t.Fatalf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerPodmanSecretList)
			}
			if tt.method == http.MethodGet && !strings.Contains(rec.Body.String(), filter.PodmanCompatSecretListDenyReason) {
				t.Fatalf("body = %s, want the shared deny reason %q", rec.Body.String(), filter.PodmanCompatSecretListDenyReason)
			}
		})
	}
}

// TestPodmanCompatSecretListInertWithoutOwnerIsolation proves the refusal
// costs nothing to a deployment that configures no owner: with Owner empty the
// middleware is a no-op, so nothing is injected and nothing is refused.
func TestPodmanCompatSecretListInertWithoutOwnerIsolation(t *testing.T) {
	t.Parallel()
	reached := false
	handler := middlewareWithDeps(testLogger(), Options{
		UpstreamFlavor: upstreamflavor.Podman,
	}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(podmanSecretsUpstreamForTest(t, &reached))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil))

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
	}
}

// TestDockerCompatSecretListKeepsOwnerLabelInjection is the no-regression
// half: on a Docker upstream the owner label still reaches the daemon.
func TestDockerCompatSecretListKeepsOwnerLabelInjection(t *testing.T) {
	t.Parallel()
	var forwarded []string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, err := dockerfilters.Decode(r.URL.Query().Get("filters"))
		if err != nil {
			t.Fatalf("decode forwarded filters: %v", err)
		}
		forwarded = decoded["label"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	})
	handler := middlewareWithDeps(testLogger(), Options{
		Owner:          "team-a",
		UpstreamFlavor: upstreamflavor.Docker,
	}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/secrets", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(forwarded) != 1 || forwarded[0] != ownerLabelForTest+"=team-a" {
		t.Fatalf("forwarded label filter = %v, want [%s=team-a]", forwarded, ownerLabelForTest)
	}
}

// TestPodmanCompatSecretRefusalIsScopedToTheListPath proves the flavor gate
// does not swallow POST /secrets/create or the per-secret reads, which name a
// resource the ownership layer already checks.
func TestPodmanCompatSecretRefusalIsScopedToTheListPath(t *testing.T) {
	t.Parallel()
	reached := false
	inspector := fakeInspector{resources: map[string]map[string]inspectResult{
		string(dockerresource.KindSecret): {"s-1": {labels: map[string]string{ownerLabelForTest: "team-a"}, found: true}},
	}}
	handler := middlewareWithDeps(testLogger(), Options{
		Owner:          "team-a",
		UpstreamFlavor: upstreamflavor.Podman,
	}, inspector.inspectResource, inspector.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ID":"s-1"}`))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.53/secrets/s-1", nil)
	req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{}))
	handler.ServeHTTP(rec, req)

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("reached = %v status = %d, want true and 200; body: %s", reached, rec.Code, rec.Body.String())
	}
}

// TestLibpodSecretCreateFlagsLookUpTheNamedSecret pins which libpod secret
// creates look the named secret up and what each lookup answer does.
// `replace` and `ignore` count as set unless gorilla/schema's bool converter
// would read them as false, so a value Podman refuses with a 400 ("yes",
// " true") still costs a lookup rather than a guess. The chain test
// TestServeChainLibpodSecretCreateReplaceIsOwnerChecked drives the same check
// against a daemon that stores secrets the way Podman does.
func TestLibpodSecretCreateFlagsLookUpTheNamedSecret(t *testing.T) {
	t.Parallel()
	secrets := map[string]inspectResult{
		"theirs":   {labels: map[string]string{DefaultLabelKey: "team-b"}, found: true},
		"mine":     {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
		"unowned":  {labels: map[string]string{}, found: true},
		" padded":  {labels: map[string]string{DefaultLabelKey: "team-b"}, found: true},
		"unlookup": {err: fmt.Errorf("upstream returned 500")},
	}
	tests := []struct {
		query      string
		wantLookup string
		wantStatus int
	}{
		{query: "name=theirs", wantStatus: http.StatusAccepted},
		{query: "name=theirs&replace=false&ignore=false", wantStatus: http.StatusAccepted},
		{query: "name=theirs&replace=", wantStatus: http.StatusAccepted},
		{query: "name=theirs&replace=0", wantStatus: http.StatusAccepted},
		{query: "name=theirs&replace=f", wantStatus: http.StatusAccepted},
		{query: "name=theirs&replace=F", wantStatus: http.StatusAccepted},
		{query: "name=theirs&replace=FALSE", wantStatus: http.StatusAccepted},
		{query: "name=theirs&replace=False", wantStatus: http.StatusAccepted},
		{query: "name=theirs&replace=true", wantLookup: "theirs", wantStatus: http.StatusForbidden},
		{query: "name=theirs&replace=TRUE", wantLookup: "theirs", wantStatus: http.StatusForbidden},
		{query: "name=theirs&replace=t", wantLookup: "theirs", wantStatus: http.StatusForbidden},
		{query: "name=theirs&replace=on", wantLookup: "theirs", wantStatus: http.StatusForbidden},
		{query: "name=theirs&replace=yes", wantLookup: "theirs", wantStatus: http.StatusForbidden},
		{query: "name=theirs&replace=+true", wantLookup: "theirs", wantStatus: http.StatusForbidden},
		{query: "name=theirs&ignore=1", wantLookup: "theirs", wantStatus: http.StatusForbidden},
		{query: "name=theirs&replace=true&ignore=true", wantLookup: "theirs", wantStatus: http.StatusForbidden},
		{query: "name=unowned&replace=true", wantLookup: "unowned", wantStatus: http.StatusForbidden},
		{query: "name=%20padded&replace=true", wantLookup: " padded", wantStatus: http.StatusForbidden},
		{query: "name=mine&replace=true", wantLookup: "mine", wantStatus: http.StatusAccepted},
		{query: "name=mine&ignore=true", wantLookup: "mine", wantStatus: http.StatusAccepted},
		{query: "name=fresh&replace=true", wantLookup: "fresh", wantStatus: http.StatusAccepted},
		{query: "name=unlookup&replace=true", wantLookup: "unlookup", wantStatus: http.StatusBadGateway},
		{query: "replace=true", wantStatus: http.StatusAccepted},
		{query: "name=&replace=true", wantStatus: http.StatusAccepted},
		{query: "name=..&replace=true", wantStatus: http.StatusForbidden},
		{query: "name=.&ignore=true", wantStatus: http.StatusForbidden},
		{query: "name=theirs&replace=true&Name=mine", wantStatus: http.StatusForbidden},
		{query: "name=theirs&replace=false&Replace=false", wantStatus: http.StatusForbidden},
		{query: "name=theirs&ignore=false&ignore=false", wantStatus: http.StatusForbidden},
		{query: "name=theirs&Name=mine", wantStatus: http.StatusAccepted},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			t.Parallel()
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{string(dockerresource.KindSecret): secrets}}
			opts := Options{Owner: "team-a", LabelKey: DefaultLabelKey}
			var forwarded map[string]string
			handler := middlewareWithDeps(testLogger(), opts, inspector.inspectResource, inspector.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.Unmarshal([]byte(r.URL.Query().Get("labels")), &forwarded); err != nil {
					t.Errorf("decode forwarded labels: %v", err)
				}
				w.WriteHeader(http.StatusAccepted)
			}))

			req := httptest.NewRequest(http.MethodPost, "/libpod/secrets/create?"+tt.query, strings.NewReader("payload"))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			var want []resourceInspectCall
			if tt.wantLookup != "" {
				want = []resourceInspectCall{{kind: dockerresource.KindSecret, id: tt.wantLookup}}
			}
			if !slices.Equal(inspector.calls, want) {
				t.Errorf("inspect calls = %+v, want %+v", inspector.calls, want)
			}
			if rec.Code == http.StatusAccepted && forwarded[DefaultLabelKey] != "team-a" {
				t.Errorf("forwarded labels = %v, want the owner label stamped", forwarded)
			}
		})
	}
}

// TestLibpodContainerCreateLooksUpTheSecretsItNames pins which secrets a
// libpod container create is checked against, in what order, and what each
// lookup answer does. A body naming a secret the lookup can't vouch for, or
// setting one in the environment, is refused before anything is looked up.
// The chain test
// TestServeChainLibpodContainerCreateSecretsAreOwnerChecked drives the same
// check against a daemon that resolves secrets the way Podman does.
func TestLibpodContainerCreateLooksUpTheSecretsItNames(t *testing.T) {
	t.Parallel()
	const (
		fullID     = "0123456789abcdef012345678"
		longerThan = fullID + "9"
	)
	secrets := map[string]inspectResult{
		"theirs":     {labels: map[string]string{DefaultLabelKey: "team-b"}, found: true},
		"mine":       {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
		"also-mine":  {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
		"third-mine": {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
		"CAFE":       {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
		"cafe-1":     {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
		longerThan:   {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
		"unowned":    {labels: map[string]string{}, found: true},
		" padded":    {labels: map[string]string{DefaultLabelKey: "team-b"}, found: true},
		"padded":     {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
		"unlookup":   {err: fmt.Errorf("upstream returned 500")},
	}
	tests := []struct {
		body        string
		wantLookups []string
		wantStatus  int
		wantReason  string
	}{
		// Nothing named.
		{body: `{}`, wantStatus: http.StatusAccepted},
		{body: `{"secrets":[],"secret_env":{}}`, wantStatus: http.StatusAccepted},
		{body: `{"secrets":null,"secret_env":null}`, wantStatus: http.StatusAccepted},

		// Each source is looked up once, in the order the body lists them.
		{body: `{"secrets":[{"Source":"mine"}]}`, wantLookups: []string{"mine"}, wantStatus: http.StatusAccepted},
		{body: `{"secrets":[{"source":"mine"},{"source":"mine"}]}`, wantLookups: []string{"mine"}, wantStatus: http.StatusAccepted},
		{body: `{"secrets":[{"Source":"third-mine"},{"Source":"also-mine"},{"Source":"mine"},{"Source":"also-mine"}]}`, wantLookups: []string{"third-mine", "also-mine", "mine"}, wantStatus: http.StatusAccepted},

		// Another owner's, unlabeled, absent and unreadable secrets.
		{body: `{"secrets":[{"Source":"theirs"}]}`, wantLookups: []string{"theirs"}, wantStatus: http.StatusForbidden, wantReason: `libpod owner policy denied access to secret "theirs" referenced by container create secrets`},
		{body: `{"secrets":[{"Source":"mine"},{"Source":"theirs"}]}`, wantLookups: []string{"mine", "theirs"}, wantStatus: http.StatusForbidden, wantReason: `libpod owner policy denied access to secret "theirs" referenced by container create secrets`},
		{body: `{"secrets":[{"Source":"unowned"}]}`, wantLookups: []string{"unowned"}, wantStatus: http.StatusForbidden, wantReason: `libpod owner policy denied access to secret "unowned" referenced by container create secrets`},
		{body: `{"secrets":[{"Source":"gone"}]}`, wantLookups: []string{"gone"}, wantStatus: http.StatusNotFound, wantReason: `libpod owner policy could not resolve secret "gone" referenced by container create secrets`},
		{body: `{"secrets":[{"Source":"unlookup"}]}`, wantLookups: []string{"unlookup"}, wantStatus: http.StatusBadGateway},

		// Podman doesn't trim a source, so neither does the lookup.
		{body: `{"secrets":[{"Source":" padded"}]}`, wantLookups: []string{" padded"}, wantStatus: http.StatusForbidden, wantReason: `libpod owner policy denied access to secret " padded" referenced by container create secrets`},

		// encoding/json matches keys in any letter case, and folds the long
		// s (U+017F) to "s".
		{body: `{"SECRETS":[{"SOURCE":"theirs"}]}`, wantLookups: []string{"theirs"}, wantStatus: http.StatusForbidden, wantReason: `libpod owner policy denied access to secret "theirs" referenced by container create secrets`},
		{body: `{"ſecrets":[{"ſource":"theirs"}]}`, wantLookups: []string{"theirs"}, wantStatus: http.StatusForbidden, wantReason: `libpod owner policy denied access to secret "theirs" referenced by container create secrets`},

		// Sources Podman resolves that can't be looked up, and shapes its
		// decode refuses.
		{body: `{"secrets":[{}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":[null]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":[{"Source":""}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":[{"Source":null}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":[{"Source":"."}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":[{"Source":".."}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":[{"Source":"mine"},{"Target":"t"}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":"mine"}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":{"Source":"mine"}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":["mine"]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},
		{body: `{"secrets":[{"Source":7}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretReference},

		// A source that could be an ID or an ID prefix, whoever's it is.
		{body: `{"secrets":[{"Source":"a"}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretID},
		{body: `{"secrets":[{"Source":"cafe"}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretID},
		{body: `{"secrets":[{"Source":"` + fullID + `"}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretID},
		{body: `{"secrets":[{"Source":"42"}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretID},
		{body: `{"secrets":[{"Source":"mine"},{"Source":"db"}]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretID},

		// And ones that can only be a name.
		{body: `{"secrets":[{"Source":"CAFE"}]}`, wantLookups: []string{"CAFE"}, wantStatus: http.StatusAccepted},
		{body: `{"secrets":[{"Source":"cafe-1"}]}`, wantLookups: []string{"cafe-1"}, wantStatus: http.StatusAccepted},
		{body: `{"secrets":[{"Source":"` + longerThan + `"}]}`, wantLookups: []string{longerThan}, wantStatus: http.StatusAccepted},

		// An environment secret is read by name at every start, so one is
		// refused whoever's secret it names, in any key spelling.
		{body: `{"secret_env":{"K":"mine"}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"secret_env":{"K":"theirs"}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"secrets":[{"Source":"mine"}],"secret_env":{"K":"mine"}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"Secret_Env":{"K":"mine"}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"ſecret_env":{"K":"mine"}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"secret_env":{"K":""}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"secret_env":{"K":null}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"secret_env":{"":"mine"}}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"secret_env":"mine"}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
		{body: `{"secret_env":["mine"]}`, wantStatus: http.StatusForbidden, wantReason: "libpod " + libpodContainerCreateDenySecretEnv},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			t.Parallel()
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{string(dockerresource.KindSecret): secrets}}
			opts := Options{Owner: "team-a", LabelKey: DefaultLabelKey}
			var forwarded struct {
				Labels map[string]string `json:"labels"`
			}
			handler := middlewareWithDeps(testLogger(), opts, inspector.inspectResource, inspector.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&forwarded); err != nil {
					t.Errorf("decode forwarded body: %v", err)
				}
				w.WriteHeader(http.StatusAccepted)
			}))

			req := httptest.NewRequest(http.MethodPost, "/v5.0.0/libpod/containers/create", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			var lookups []string
			for _, call := range inspector.calls {
				if call.kind != dockerresource.KindSecret {
					t.Errorf("inspected %s %q, want only secrets", call.kind, call.id)
				}
				lookups = append(lookups, call.id)
			}
			if !slices.Equal(lookups, tt.wantLookups) {
				t.Errorf("secret lookups = %q, want %q", lookups, tt.wantLookups)
			}
			if tt.wantReason != "" {
				var denial struct {
					Message string `json:"message"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil || denial.Message != tt.wantReason {
					t.Errorf("body = %s, want message %q", rec.Body.String(), tt.wantReason)
				}
			}
			if rec.Code == http.StatusAccepted && forwarded.Labels[DefaultLabelKey] != "team-a" {
				t.Errorf("forwarded labels = %v, want the owner label stamped", forwarded.Labels)
			}
		})
	}
}

// TestLibpodContainerCreateChecksTheSecretsItForwards pins the two ways a body
// can name `secrets` twice. Spelled in two letter cases, Podman's decode would
// take whichever comes later, so the body is refused. Spelled the same way
// twice, the later one is the one that's checked and the only one forwarded.
func TestLibpodContainerCreateChecksTheSecretsItForwards(t *testing.T) {
	t.Parallel()
	secrets := map[string]inspectResult{
		"theirs": {labels: map[string]string{DefaultLabelKey: "team-b"}, found: true},
		"mine":   {labels: map[string]string{DefaultLabelKey: "team-a"}, found: true},
	}
	tests := []struct {
		body          string
		wantStatus    int
		wantLookups   []string
		wantForwarded []string
	}{
		{body: `{"secrets":[{"Source":"mine"}],"Secrets":[{"Source":"theirs"}]}`, wantStatus: http.StatusBadRequest},
		{body: `{"secrets":[{"Source":"mine","source":"theirs"}]}`, wantStatus: http.StatusBadRequest},
		{body: `{"secret_env":{},"SECRET_ENV":{"K":"theirs"}}`, wantStatus: http.StatusBadRequest},
		{body: `{"secrets":[{"Source":"mine"}],"secrets":[{"Source":"theirs"}]}`, wantStatus: http.StatusForbidden, wantLookups: []string{"theirs"}},
		{body: `{"secrets":[{"Source":"theirs"}],"secrets":[{"Source":"mine"}]}`, wantStatus: http.StatusAccepted, wantLookups: []string{"mine"}, wantForwarded: []string{"mine"}},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			t.Parallel()
			inspector := &recordingInspector{resources: map[string]map[string]inspectResult{string(dockerresource.KindSecret): secrets}}
			var forwarded []string
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"}, inspector.inspectResource, inspector.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Secrets []struct{ Source string } `json:"secrets"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode forwarded body: %v", err)
				}
				for _, secret := range body.Secrets {
					forwarded = append(forwarded, secret.Source)
				}
				w.WriteHeader(http.StatusAccepted)
			}))

			req := httptest.NewRequest(http.MethodPost, "/v5.0.0/libpod/containers/create", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			var lookups []string
			for _, call := range inspector.calls {
				lookups = append(lookups, call.id)
			}
			if !slices.Equal(lookups, tt.wantLookups) {
				t.Errorf("secret lookups = %q, want %q", lookups, tt.wantLookups)
			}
			if !slices.Equal(forwarded, tt.wantForwarded) {
				t.Errorf("forwarded secrets = %q, want %q", forwarded, tt.wantForwarded)
			}
		})
	}
}

// callerOwnsEverythingInspector answers every lookup with a resource carrying
// the caller's owner label, and records what it was asked.
type callerOwnsEverythingInspector struct {
	owner string
	calls []resourceInspectCall
}

func (i *callerOwnsEverythingInspector) inspectResource(_ context.Context, kind dockerresource.Kind, id string) (map[string]string, bool, error) {
	i.calls = append(i.calls, resourceInspectCall{kind: kind, id: id})
	return map[string]string{DefaultLabelKey: i.owner}, true, nil
}

func (i *callerOwnsEverythingInspector) inspectExec(context.Context, string) (string, bool, error) {
	return "", false, nil
}

// postLibpodContainerCreateOwningEverything sends body as team-a's libpod
// container create to a daemon where every resource is team-a's, and returns
// the response and every lookup owner isolation made, in order.
func postLibpodContainerCreateOwningEverything(t *testing.T, body string) (*httptest.ResponseRecorder, []resourceInspectCall) {
	t.Helper()
	inspector := &callerOwnsEverythingInspector{owner: "team-a"}
	handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a", LabelKey: DefaultLabelKey}, inspector.inspectResource, inspector.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v5.0.0/libpod/containers/create", strings.NewReader(body)))
	return rec, inspector.calls
}

// libpodSecretMounts renders count `secrets` entries, the i-th one naming
// name(i).
func libpodSecretMounts(count int, name func(i int) string) string {
	var list strings.Builder
	for i := range count {
		if i > 0 {
			list.WriteByte(',')
		}
		fmt.Fprintf(&list, `{"Source":%q}`, name(i))
	}
	return list.String()
}

// TestLibpodContainerCreateSecretsCountTowardTheReferenceCap pins that a
// secret is one of the resources a create is checked for. Each costs an
// inspect, so secrets share libpodCreateMaxReferences with the containers,
// networks, volumes and images the create names, and a create past it is
// refused before anything is looked up.
func TestLibpodContainerCreateSecretsCountTowardTheReferenceCap(t *testing.T) {
	t.Parallel()
	secret := func(i int) string { return fmt.Sprintf("secret-%d", i) }
	containers := func(count int) string {
		names := make([]string, 0, count)
		for i := range count {
			names = append(names, fmt.Sprintf(`"ctr-%d"`, i))
		}
		return strings.Join(names, ",")
	}
	tooMany := "libpod " + fmt.Sprintf(libpodCreateDenyTooMany, "container create")
	tests := []struct {
		name        string
		body        string
		wantStatus  int
		wantLookups int
	}{
		{
			name:        "as many secrets as the cap",
			body:        `{"secrets":[` + libpodSecretMounts(libpodCreateMaxReferences, secret) + `]}`,
			wantStatus:  http.StatusAccepted,
			wantLookups: libpodCreateMaxReferences,
		},
		{
			name:       "one secret past the cap",
			body:       `{"secrets":[` + libpodSecretMounts(libpodCreateMaxReferences+1, secret) + `]}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:        "a secret named twice counts once",
			body:        `{"secrets":[` + libpodSecretMounts(libpodCreateMaxReferences, secret) + `,` + libpodSecretMounts(libpodCreateMaxReferences, secret) + `]}`,
			wantStatus:  http.StatusAccepted,
			wantLookups: libpodCreateMaxReferences,
		},
		{
			name:        "secrets and containers that add up to the cap",
			body:        `{"volumes_from":[` + containers(200) + `],"secrets":[` + libpodSecretMounts(libpodCreateMaxReferences-200, secret) + `]}`,
			wantStatus:  http.StatusAccepted,
			wantLookups: libpodCreateMaxReferences,
		},
		{
			name:       "secrets and containers that add up to one past the cap",
			body:       `{"volumes_from":[` + containers(200) + `],"secrets":[` + libpodSecretMounts(libpodCreateMaxReferences-199, secret) + `]}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "one secret beside as many containers as the cap",
			body:       `{"volumes_from":[` + containers(libpodCreateMaxReferences) + `],"secrets":[{"Source":"secret-0"}]}`,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec, lookups := postLibpodContainerCreateOwningEverything(t, tt.body)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if len(lookups) != tt.wantLookups {
				t.Fatalf("owner isolation made %d lookups, want %d", len(lookups), tt.wantLookups)
			}
			if tt.wantStatus != http.StatusForbidden {
				return
			}
			var denial struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil || denial.Message != tooMany {
				t.Fatalf("body = %s, want message %q", rec.Body.String(), tooMany)
			}
		})
	}
}

// TestLibpodContainerCreateReadsALongSecretListOnce sends a `secrets` list
// close to the largest a body can hold. The reader goes through it once: every
// distinct secret is looked up once, in the order the body first names it,
// however often it's repeated, and a list of distinct secrets is refused at
// the cap with nothing looked up.
func TestLibpodContainerCreateReadsALongSecretListOnce(t *testing.T) {
	t.Parallel()
	const entries = 40_000

	t.Run("a few secrets repeated", func(t *testing.T) {
		t.Parallel()
		body := `{"secrets":[` + libpodSecretMounts(entries, func(i int) string {
			return fmt.Sprintf("s-%d", i%libpodCreateMaxReferences)
		}) + `]}`
		rec, lookups := postLibpodContainerCreateOwningEverything(t, body)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
		}
		want := make([]resourceInspectCall, 0, libpodCreateMaxReferences)
		for i := range libpodCreateMaxReferences {
			want = append(want, resourceInspectCall{kind: dockerresource.KindSecret, id: fmt.Sprintf("s-%d", i)})
		}
		if !slices.Equal(lookups, want) {
			t.Fatalf("owner isolation made %d lookups, want each of the %d secrets once, in order", len(lookups), len(want))
		}
	})

	t.Run("every secret distinct", func(t *testing.T) {
		t.Parallel()
		body := `{"secrets":[` + libpodSecretMounts(entries, func(i int) string { return fmt.Sprintf("s-%d", i) }) + `]}`
		rec, lookups := postLibpodContainerCreateOwningEverything(t, body)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		if len(lookups) != 0 {
			t.Fatalf("owner isolation made %d lookups, want none", len(lookups))
		}
	})
}

// TestLibpodContainerCreateSecretRefusalKeepsTheOwnerStamp covers the rollout
// contract for a create refused on its secrets: a warn profile forwards it,
// and the container it creates still carries the owner label.
func TestLibpodContainerCreateSecretRefusalKeepsTheOwnerStamp(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"secrets":[{"Source":""}]}`,
		`{"secrets":[{"Source":"cafe"}]}`,
		`{"secrets":[{"Source":"theirs"}]}`,
		`{"secret_env":{"K":"theirs"}}`,
	} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			inspector := fakeInspector{resources: map[string]map[string]inspectResult{string(dockerresource.KindSecret): {
				"theirs": {labels: map[string]string{DefaultLabelKey: "team-b"}, found: true},
			}}}
			var forwarded struct {
				Labels map[string]string `json:"labels"`
			}
			handler := middlewareWithDeps(testLogger(), Options{Owner: "team-a"}, inspector.inspectResource, inspector.inspectExec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&forwarded); err != nil {
					t.Errorf("decode forwarded body: %v", err)
				}
				w.WriteHeader(http.StatusAccepted)
			}))

			meta := &logging.RequestMeta{RolloutMode: "warn"}
			req := httptest.NewRequest(http.MethodPost, "/v5.0.0/libpod/containers/create", strings.NewReader(body))
			req = req.WithContext(logging.WithMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
			}
			if forwarded.Labels[DefaultLabelKey] != "team-a" {
				t.Errorf("forwarded labels = %v, want the owner label stamped", forwarded.Labels)
			}
			if meta.ReasonCode != reasonCodeOwnerPolicyDeniedAccess {
				t.Errorf("meta.ReasonCode = %q, want %q", meta.ReasonCode, reasonCodeOwnerPolicyDeniedAccess)
			}
		})
	}
}

// TestCouldBePodmanSecretID pins the references Podman's Lookup could match
// against a secret ID or a prefix of one: lowercase hex, no longer than an ID.
func TestCouldBePodmanSecretID(t *testing.T) {
	t.Parallel()
	const fullID = "0123456789abcdef012345678"
	tests := map[string]bool{
		"":            false,
		"a":           true,
		"0":           true,
		"db":          true,
		"cafe":        true,
		"ed25519":     true,
		fullID:        true,
		fullID + "9":  false,
		"CAFE":        false,
		"cafE":        false,
		"cafe-1":      false,
		"cafe ":       false,
		" cafe":       false,
		"g":           false,
		"db_password": false,
		"café":        false,
		"0x1f":        false,
	}
	for reference, want := range tests {
		if got := couldBePodmanSecretID(reference); got != want {
			t.Errorf("couldBePodmanSecretID(%q) = %v, want %v", reference, got, want)
		}
	}
}
