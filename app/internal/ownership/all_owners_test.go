package ownership

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

func TestAllOwnersStampsCreatesAndChecksNothing(t *testing.T) {
	t.Parallel()

	failInspect := func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
		t.Error("scope all must not inspect a resource for an owner check")
		return nil, false, nil
	}
	failExec := func(context.Context, string) (string, bool, error) {
		t.Error("scope all must not inspect an exec for an owner check")
		return "", false, nil
	}

	tests := []struct {
		name, method, path, body string
		wantStatus               int
		check                    func(t *testing.T, got *http.Request, body string)
	}{
		{"container create is stamped", http.MethodPost, "/containers/create", `{"Image":"alpine"}`, http.StatusNoContent,
			func(t *testing.T, _ *http.Request, body string) {
				if !strings.Contains(body, `"com.sockguard.owner":"adm"`) {
					t.Errorf("create body = %s, want the owner label stamped", body)
				}
			}},
		{"list is not narrowed", http.MethodGet, "/containers/json", "", http.StatusNoContent,
			func(t *testing.T, got *http.Request, _ string) {
				if f := got.URL.Query().Get("filters"); f != "" {
					t.Errorf("filters = %q, want none injected", f)
				}
			}},
		{"foreign container delete is not checked", http.MethodDelete, "/containers/victim", "", http.StatusNoContent, nil},
		{"unscopeable libpod read is not refused", http.MethodGet, "/libpod/generate/kube", "", http.StatusNoContent, nil},
		{"docker build stays refused", http.MethodPost, "/build", "", http.StatusForbidden, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotReq *http.Request
			var gotBody string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotReq = r
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.WriteHeader(http.StatusNoContent)
			})
			handler := middlewareWithDeps(testLogger(), Options{Owner: "adm", LabelKey: "com.sockguard.owner", AllOwners: true},
				failInspect, failExec)(next)
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus < 400 && gotReq == nil {
				t.Fatal("allowed request never reached upstream")
			}
			if tt.wantStatus >= 400 && gotReq != nil {
				t.Fatal("refused request reached upstream")
			}
			if tt.check != nil {
				tt.check(t, gotReq, gotBody)
			}
		})
	}
}

type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Error("authorizer must not contact the daemon under scope all")
	return nil, io.ErrUnexpectedEOF
}

func TestAllOwnersBuildkitImageAuthorizerAllowsAnyDestination(t *testing.T) {
	t.Parallel()
	authorize := NewBuildkitImageAuthorizer(failTransport{t}, Options{Owner: "adm", AllOwners: true})
	if err := authorize(context.Background(), "registry.example/other-owner/app:1"); err != nil {
		t.Fatalf("authorize = %v, want nil under scope all", err)
	}
}

func TestAllOwnersImageWritesRequireReadableDestinations(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"enforce", "warn", "audit"} {
		for _, tc := range []struct {
			name, path string
			wantStatus int
		}{
			{"repository-wide pull", "/images/create?fromImage=team/shared", http.StatusForbidden},
			{"native all tags", "/libpod/images/pull?reference=team/shared:1&allTags=true", http.StatusForbidden},
			{"ambiguous import", "/images/create?fromSrc=-&repo=one&repo=two", http.StatusForbidden},
			{"ambiguous retag", "/images/source/tag?repo=one&repo=two&tag=1", http.StatusForbidden},
			{"tagged pull", "/images/create?fromImage=team/shared&tag=1", http.StatusCreated},
			{"valid retag", "/images/source/tag?repo=team/shared&tag=1", http.StatusCreated},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				locks := NewKeyedLocks(0, 0)
				forwarded := false
				next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					forwarded = true
					if tc.wantStatus == http.StatusCreated && locks.size() == 0 {
						t.Error("admin image destination is not locked")
					}
					w.WriteHeader(http.StatusCreated)
				})
				inspect := func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
					t.Error("admin image write must not compare owners")
					return nil, false, nil
				}
				handler := middlewareWithDeps(testLogger(), Options{Owner: "adm", AllOwners: true, Locks: locks}, inspect, nil)(next)
				req := httptest.NewRequest(http.MethodPost, tc.path, nil)
				req = req.WithContext(logging.WithMeta(req.Context(), &logging.RequestMeta{RolloutMode: mode}))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.wantStatus {
					t.Errorf("status = %d %s, want %d", rec.Code, rec.Body.String(), tc.wantStatus)
				}
				if forwarded != (tc.wantStatus == http.StatusCreated) {
					t.Errorf("forwarded = %v", forwarded)
				}
				if locks.size() != 0 {
					t.Error("destination lock was not released")
				}
			})
		}
	}
}

func TestAllOwnersTaggedPullSharesTenantDestinationLock(t *testing.T) {
	t.Parallel()
	locks := NewKeyedLocks(0, 0)
	entered, unblock, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(unblock) }) }
	defer func() { resume(); <-done }()
	admin := middlewareWithDeps(testLogger(), Options{Owner: "adm", AllOwners: true, Locks: locks}, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-unblock
		w.WriteHeader(http.StatusCreated)
	}))
	first := httptest.NewRecorder()
	go func() {
		defer close(done)
		admin.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/images/create?fromImage=team/shared&tag=1", nil))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("admin pull did not reach upstream")
	}
	forwarded := false
	inspectCalls := 0
	inspect := func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
		inspectCalls++
		return map[string]string{DefaultLabelKey: "tenant"}, true, nil
	}
	tenant := middlewareWithDeps(testLogger(), Options{Owner: "tenant", Locks: locks}, inspect, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusCreated)
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	second := httptest.NewRecorder()
	tenant.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/images/source/tag?repo=docker.io/team/shared&tag=1", nil).WithContext(ctx))
	if second.Code != http.StatusServiceUnavailable || forwarded || inspectCalls != 0 {
		t.Errorf("tenant retag = %d, forwarded=%v inspects=%d; want locked refusal before preflight", second.Code, forwarded, inspectCalls)
	}
	resume()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("admin pull did not finish")
	}
	if first.Code != http.StatusCreated || locks.size() != 0 {
		t.Errorf("admin status=%d, remaining keys=%d", first.Code, locks.size())
	}
}

func TestAllOwnersServiceTemplatesRemainStampedAndLocked(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/services/create", "/services/foreign/update?version=1"} {
		t.Run(path, func(t *testing.T) {
			locks := NewKeyedLocks(0, 0)
			forwarded := false
			inspect := func(context.Context, dockerresource.Kind, string) (map[string]string, bool, error) {
				t.Error("admin service must not authorize referenced resource owners")
				return nil, false, nil
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				var body struct {
					Labels       map[string]string
					TaskTemplate struct {
						ContainerSpec struct{ Labels map[string]string }
					}
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.Labels[DefaultLabelKey] != "adm" || body.TaskTemplate.ContainerSpec.Labels[DefaultLabelKey] != "adm" {
					t.Errorf("service/task owner stamps = %+v", body)
				}
				if locks.size() == 0 {
					t.Error("service name is not locked")
				}
				w.WriteHeader(http.StatusCreated)
			})
			handler := middlewareWithDeps(testLogger(), Options{Owner: "adm", AllOwners: true, Locks: locks}, inspect, nil)(next)
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"Name":"svc","TaskTemplate":{"ContainerSpec":{"Image":"example/app:1","Mounts":[{"Type":"volume","Source":"data-{{.Task.Slot}}","Target":"/data"}]}}}`))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusCreated || !forwarded {
				t.Errorf("admin service = %d %s, forwarded=%v", rec.Code, rec.Body.String(), forwarded)
			}
			if locks.size() != 0 {
				t.Error("service name lock was not released")
			}
		})
	}
}
