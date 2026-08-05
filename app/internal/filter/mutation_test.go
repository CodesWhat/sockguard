package filter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/internal/imagetrust"
	"github.com/codeswhat/sockguard/internal/logging"
)

func TestMutationChainInjectsRequiredLabelBeforeContainerPolicy(t *testing.T) {
	var forwarded []byte
	handler := mutationMiddleware(t, Options{
		PolicyConfig: PolicyConfig{
			ContainerCreate: ContainerCreateOptions{RequiredLabels: []string{"com.example.mandatory"}},
		},
		Mutation: MutationOptions{Rules: []MutationRuleOptions{{
			ID:       "mandatory-label",
			Mode:     "enforce",
			Surfaces: []string{mutationSurfaceContainerCreate},
			InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{
				"com.example.mandatory": "canonical",
			}},
		}}},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1.53/containers/create", strings.NewReader(`{"Image":"alpine:3.21"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(forwarded, &doc); err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	labels := doc["Labels"].(map[string]any)
	if got := labels["com.example.mandatory"]; got != "canonical" {
		t.Fatalf("forwarded mandatory label = %#v, want canonical", got)
	}
}

func TestMutationChainOverwritesClientLabelWithSingleCanonicalField(t *testing.T) {
	var forwarded []byte
	handler := mutationMiddleware(t, Options{
		PolicyConfig: PolicyConfig{
			ContainerCreate: ContainerCreateOptions{RequiredLabels: []string{"com.example.mandatory"}},
		},
		Mutation: MutationOptions{Rules: []MutationRuleOptions{{
			ID:           "canonical-label",
			Mode:         "enforce",
			Surfaces:     []string{mutationSurfaceContainerCreate},
			InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{"com.example.mandatory": "canonical"}},
		}}},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"alpine:3.21","labels":{"com.example.mandatory":"client-value","keep":"yes"}}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Count(forwarded, []byte(`"Labels"`)) != 1 || bytes.Contains(forwarded, []byte(`"labels"`)) {
		t.Fatalf("forwarded body has ambiguous/non-canonical Labels fields: %s", forwarded)
	}
	var doc map[string]any
	if err := json.Unmarshal(forwarded, &doc); err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	labels := doc["Labels"].(map[string]any)
	if labels["com.example.mandatory"] != "canonical" || labels["keep"] != "yes" {
		t.Fatalf("forwarded Labels = %#v, want mandatory overwrite plus existing label", labels)
	}
}

func TestMutationChainRegistryPolicyEvaluatesTargetReference(t *testing.T) {
	tests := []struct {
		name            string
		from            string
		to              string
		allowedRegistry string
		wantStatus      int
		wantForwarded   bool
	}{
		{
			name:            "allowed source to denied target",
			from:            "source.example/team/app:v1",
			to:              "denied.example/team/app:v1",
			allowedRegistry: "source.example",
			wantStatus:      http.StatusForbidden,
		},
		{
			name:            "denied source to allowed target",
			from:            "denied.example/team/app:v1",
			to:              "allowed.example/team/app:v1",
			allowedRegistry: "allowed.example",
			wantStatus:      http.StatusNoContent,
			wantForwarded:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forwarded := false
			handler := mutationMiddleware(t, Options{
				PolicyConfig: PolicyConfig{
					DenyResponseVerbosity: DenyResponseVerbosityVerbose,
					Service:               ServiceOptions{AllowedRegistries: []string{tt.allowedRegistry}},
				},
				Mutation: MutationOptions{Rules: []MutationRuleOptions{{
					ID:       "registry-remap",
					Mode:     "enforce",
					Surfaces: []string{mutationSurfaceServiceCreate},
					RemapImage: &ImageRemapMutationOptions{
						Match: "exact",
						From:  tt.from,
						To:    tt.to,
					},
				}}},
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				body, _ := io.ReadAll(r.Body)
				if !bytes.Contains(body, []byte(tt.to)) {
					t.Errorf("upstream body = %s, want remapped target %q", body, tt.to)
				}
				w.WriteHeader(http.StatusNoContent)
			}))

			body := `{"TaskTemplate":{"ContainerSpec":{"Image":"` + tt.from + `"}}}`
			req := httptest.NewRequest(http.MethodPost, "/services/create", strings.NewReader(body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if forwarded != tt.wantForwarded {
				t.Fatalf("upstream called = %v, want %v", forwarded, tt.wantForwarded)
			}
			if !tt.wantForwarded {
				var denial DenialResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &denial); err != nil {
					t.Fatalf("decode denial response: %v", err)
				}
				if !strings.Contains(denial.Reason, `registry "denied.example" is not allowlisted`) {
					t.Fatalf("denial reason = %q, want target registry denial", denial.Reason)
				}
			}
		})
	}
}

func TestMutationChainImageTrustEvaluatesRemappedTarget(t *testing.T) {
	verifier := &mockImageVerifier{err: errors.New("target is unsigned")}
	trustPolicy := containerCreatePolicy{
		allowPrivileged:        true,
		allowHostNetwork:       true,
		allowHostPID:           true,
		allowHostIPC:           true,
		allowHostUserNS:        true,
		allowHostCgroupNS:      true,
		allowAllDevices:        true,
		allowAllCapabilities:   true,
		allowDeviceRequests:    true,
		allowDeviceCgroupRules: true,
		allowSysctls:           true,
		imageTrustVerifier:     verifier,
		imageFetcher:           oneCandidateFetcher(),
		imageTrustCfg:          imagetrust.Config{Mode: imagetrust.ModeEnforce},
	}
	engine := newMutationEngine(MutationOptions{Rules: []MutationRuleOptions{{
		ID:       "signed-to-unsigned",
		Mode:     "enforce",
		Surfaces: []string{mutationSurfaceContainerCreate},
		RemapImage: &ImageRemapMutationOptions{
			Match: "exact",
			From:  "signed.example/app:v1",
			To:    "unsigned.example/app:v1",
		},
	}}})
	policies := []requestInspectPolicy{
		{method: http.MethodPost, matches: matchesContainerCreateInspection, severity: inspectSeverityCritical, inspect: newContainerCreateMutationPolicy(engine).inspect},
		{method: http.MethodPost, matches: matchesContainerCreateInspection, severity: inspectSeverityCritical, inspect: trustPolicy.inspect},
	}
	runtime := runtimePolicy{inspectPoliciesByMethod: groupInspectPoliciesByMethod(policies)}
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(`{"Image":"signed.example/app:v1"}`))

	reason, code, status := runtime.inspectAllowedRequest(testLogger(), req, NormalizePath(req.URL.Path))

	if status != http.StatusForbidden || code != reasonCodeRequestBodyPolicyDenied {
		t.Fatalf("inspectAllowedRequest() = status %d code %q, want 403/%q; reason=%q", status, code, reasonCodeRequestBodyPolicyDenied, reason)
	}
	if verifier.lastCalled != "unsigned.example/app:v1" {
		t.Fatalf("image verifier called with %q, want remapped target", verifier.lastCalled)
	}
	if !strings.Contains(reason, "image trust verification failed") {
		t.Fatalf("reason = %q, want image-trust denial", reason)
	}
}

func TestMutationChainServiceCreateMutatesBothLabelMapsAndImage(t *testing.T) {
	var forwarded []byte
	handler := mutationMiddleware(t, Options{
		PolicyConfig: PolicyConfig{Service: ServiceOptions{AllowedRegistries: []string{"mirror.example"}}},
		Mutation: MutationOptions{Rules: []MutationRuleOptions{
			{
				ID:           "service-labels",
				Mode:         "enforce",
				Surfaces:     []string{mutationSurfaceServiceCreate},
				InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{"com.example.team": "platform"}},
			},
			{
				ID:       "service-image",
				Mode:     "enforce",
				Surfaces: []string{mutationSurfaceServiceCreate},
				RemapImage: &ImageRemapMutationOptions{
					Match: "prefix",
					From:  "source.example/",
					To:    "mirror.example/",
				},
			},
		}},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	body := `{"Labels":{"existing":"root"},"TaskTemplate":{"ContainerSpec":{"Image":"source.example/team/app:v1","Labels":{"existing":"task"}}}}`
	req := httptest.NewRequest(http.MethodPost, "/v1.53/services/create", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(forwarded, &doc); err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	rootLabels := doc["Labels"].(map[string]any)
	task := doc["TaskTemplate"].(map[string]any)["ContainerSpec"].(map[string]any)
	taskLabels := task["Labels"].(map[string]any)
	if rootLabels["com.example.team"] != "platform" || taskLabels["com.example.team"] != "platform" {
		t.Fatalf("root Labels=%#v task Labels=%#v, want injected label in both maps", rootLabels, taskLabels)
	}
	if task["Image"] != "mirror.example/team/app:v1" {
		t.Fatalf("task image = %#v, want remapped image", task["Image"])
	}
}

func TestMutationChainServiceUpdateMutatesImageAndPreservesVersionQuery(t *testing.T) {
	var forwarded []byte
	var forwardedQuery string
	handler := mutationMiddleware(t, Options{
		PolicyConfig: PolicyConfig{Service: ServiceOptions{AllowedRegistries: []string{"mirror.example"}}},
		Mutation: MutationOptions{Rules: []MutationRuleOptions{{
			ID:       "update-image",
			Mode:     "enforce",
			Surfaces: []string{mutationSurfaceServiceUpdate},
			RemapImage: &ImageRemapMutationOptions{
				Match: "exact",
				From:  "source.example/app:v1",
				To:    "mirror.example/app:v2",
			},
		}}},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedQuery = r.URL.RawQuery
		forwarded, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	body := `{"TaskTemplate":{"ContainerSpec":{"Image":"source.example/app:v1"}},"Version":{"Index":9007199254740993}}`
	req := httptest.NewRequest(http.MethodPost, "/v1.53/services/svc-1/update?version=7", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if forwardedQuery != "version=7" {
		t.Fatalf("forwarded query = %q, want version=7", forwardedQuery)
	}
	if !bytes.Contains(forwarded, []byte(`"Image":"mirror.example/app:v2"`)) {
		t.Fatalf("forwarded body = %s, want remapped service-update image", forwarded)
	}
	if bytes.Contains(forwarded, []byte(`"Labels"`)) {
		t.Fatalf("forwarded service-update body unexpectedly contains Labels: %s", forwarded)
	}
	if !bytes.Contains(forwarded, []byte(`9007199254740993`)) {
		t.Fatalf("forwarded body corrupted large Version.Index: %s", forwarded)
	}
}

func TestWarnAndAuditMutationsAreTransportNonInterfering(t *testing.T) {
	for _, mode := range []string{"warn", "audit"} {
		t.Run(mode, func(t *testing.T) {
			original := []byte(" {\n  \"Image\" : \"alpine:3.21\", \"Labels\" : {\"keep\":\"yes\"}\n } ")
			control := captureMutationTransport(t, original, MutationOptions{})
			dryRun := captureMutationTransport(t, original, MutationOptions{Rules: []MutationRuleOptions{{
				ID:           mode + "-labels",
				Mode:         mode,
				Surfaces:     []string{mutationSurfaceContainerCreate},
				InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{"new": "value"}},
			}}})
			if !mutationTransportEqual(control, dryRun) {
				t.Fatalf("%s mutation changed transport\ncontrol: %#v\ndry-run: %#v", mode, control, dryRun)
			}
		})
	}
}

type mutationTransportSnapshot struct {
	body             string
	contentLength    int64
	getBody          string
	transferEncoding []string
	contentHeader    string
	transferHeader   string
}

func captureMutationTransport(t *testing.T, body []byte, mutation MutationOptions) mutationTransportSnapshot {
	t.Helper()
	var got mutationTransportSnapshot
	handler := mutationMiddleware(t, Options{Mutation: mutation}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		got.body = string(forwarded)
		got.contentLength = r.ContentLength
		got.transferEncoding = append([]string(nil), r.TransferEncoding...)
		got.contentHeader = r.Header.Get("Content-Length")
		got.transferHeader = r.Header.Get("Transfer-Encoding")
		if r.GetBody != nil {
			replay, err := r.GetBody()
			if err != nil {
				t.Errorf("GetBody: %v", err)
			} else {
				replayed, _ := io.ReadAll(replay)
				_ = replay.Close()
				got.getBody = string(replayed)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(body))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Content-Length", "stale-length")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	return got
}

func mutationTransportEqual(a, b mutationTransportSnapshot) bool {
	return a.body == b.body &&
		a.contentLength == b.contentLength &&
		a.getBody == b.getBody &&
		a.contentHeader == b.contentHeader &&
		a.transferHeader == b.transferHeader &&
		slicesEqual(a.transferEncoding, b.transferEncoding)
}

func TestMutationAuditRecordsAllOutcomesWithoutSensitiveValues(t *testing.T) {
	const (
		sourceImage = "source-secret.example/team/app:v1"
		targetImage = "mirror-secret.example/team/app:v1"
		invalidRef  = "not valid image-secret.invalid"
		labelSecret = "label-secret-value"
	)
	var auditBuf bytes.Buffer
	auditLogger := logging.NewAuditLogger(&auditBuf)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	opts := Options{Mutation: MutationOptions{Rules: []MutationRuleOptions{
		{ID: "enforce-applied", Mode: "enforce", Surfaces: []string{mutationSurfaceContainerCreate}, InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{"mandatory": "canonical"}}},
		{ID: "enforce-noop", Mode: "enforce", Surfaces: []string{mutationSurfaceContainerCreate}, InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{"stable": "same"}}},
		{ID: "warn-would-apply", Mode: "warn", Surfaces: []string{mutationSurfaceContainerCreate}, RemapImage: &ImageRemapMutationOptions{Match: "exact", From: sourceImage, To: targetImage}},
		{ID: "audit-would-noop", Mode: "audit", Surfaces: []string{mutationSurfaceContainerCreate}, RemapImage: &ImageRemapMutationOptions{Match: "exact", From: "other.example/app:v1", To: "other.example/app:v2"}},
		{ID: "warn-failed", Mode: "warn", Surfaces: []string{mutationSurfaceContainerCreate}, RemapImage: &ImageRemapMutationOptions{Match: "exact", From: targetImage, To: invalidRef}},
	}}}
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/**", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}
	filtered := MiddlewareWithOptions([]*CompiledRule{rule}, logger, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler := logging.AccessLogMiddleware(logger)(logging.AuditLogMiddleware(auditLogger, logging.AuditOptions{})(filtered))
	body := `{"Image":"` + sourceImage + `","Labels":{"stable":"same","secret":"` + labelSecret + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if err := auditLogger.Close(); err != nil {
		t.Fatalf("audit logger Close: %v", err)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &event); err != nil {
		t.Fatalf("decode audit event: %v\n%s", err, auditBuf.String())
	}
	mutation, ok := event["mutation"].(map[string]any)
	if !ok {
		t.Fatalf("audit mutation = %#v, want object", event["mutation"])
	}
	if mutation["actual_changed"] != true {
		t.Fatalf("mutation.actual_changed = %#v, want true", mutation["actual_changed"])
	}
	rules, ok := mutation["rules"].([]any)
	if !ok || len(rules) != 5 {
		t.Fatalf("mutation.rules = %#v, want five outcomes", mutation["rules"])
	}
	wantOutcomes := []string{mutationOutcomeApplied, mutationOutcomeNoop, mutationOutcomeWouldApply, mutationOutcomeWouldNoop, mutationOutcomeFailed}
	for i, want := range wantOutcomes {
		rule := rules[i].(map[string]any)
		if rule["outcome"] != want {
			t.Errorf("rules[%d].outcome = %#v, want %q", i, rule["outcome"], want)
		}
	}

	combined := auditBuf.String() + logBuf.String()
	for _, secret := range []string{sourceImage, targetImage, invalidRef, labelSecret} {
		if strings.Contains(combined, secret) {
			t.Errorf("log/audit output leaked sensitive value %q:\n%s", secret, combined)
		}
	}
	for _, id := range []string{"enforce-applied", "enforce-noop", "warn-would-apply", "audit-would-noop", "warn-failed"} {
		if !strings.Contains(combined, id) {
			t.Errorf("log/audit output missing rule id %q: %s", id, combined)
		}
	}
	if !strings.Contains(logBuf.String(), `"level":"WARN"`) {
		t.Fatalf("access log = %s, want WARN for evaluated warn rule", logBuf.String())
	}
}

func TestMutationFailuresDenyWithoutCallingUpstream(t *testing.T) {
	tests := []struct {
		name           string
		body           []byte
		mutation       MutationOptions
		wantStatus     int
		wantCode       string
		forbiddenLeaks []string
	}{
		{
			name:       "malformed JSON",
			body:       []byte(`{"Image":`),
			mutation:   injectMutationOptions("malformed"),
			wantStatus: http.StatusBadRequest,
			wantCode:   reasonCodeMutationRequestInvalid,
		},
		{
			name:       "duplicate key JSON",
			body:       []byte(`{"super-secret-label":"one","super-secret-label":"two"}`),
			mutation:   injectMutationOptions("duplicate"),
			wantStatus: http.StatusBadRequest,
			wantCode:   reasonCodeMutationRequestInvalid,
			forbiddenLeaks: []string{
				"super-secret-label",
			},
		},
		{
			name:       "oversized JSON",
			body:       bytes.Repeat([]byte(" "), maxMutationBodyBytes+1),
			mutation:   injectMutationOptions("oversized"),
			wantStatus: http.StatusRequestEntityTooLarge,
			wantCode:   reasonCodeMutationRequestTooLarge,
		},
		{
			name: "invalid remap result",
			body: []byte(`{"Image":"source-secret.example/app:v1"}`),
			mutation: MutationOptions{Rules: []MutationRuleOptions{{
				ID:       "invalid-result",
				Mode:     "enforce",
				Surfaces: []string{mutationSurfaceContainerCreate},
				RemapImage: &ImageRemapMutationOptions{
					Match: "prefix",
					From:  "source-secret.example/",
					To:    "not valid image-secret/",
				},
			}}},
			wantStatus: http.StatusBadRequest,
			wantCode:   reasonCodeMutationApplyFailed,
			forbiddenLeaks: []string{
				"source-secret.example/app:v1",
				"not valid image-secret/app:v1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstreamCalls := 0
			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			filtered := mutationMiddlewareWithLogger(t, logger, Options{Mutation: tt.mutation}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
				w.WriteHeader(http.StatusNoContent)
			}))
			handler := logging.AccessLogMiddleware(logger)(filtered)
			req := httptest.NewRequest(http.MethodPost, "/containers/create", bytes.NewReader(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if upstreamCalls != 0 {
				t.Fatalf("upstream calls = %d, want zero on fail-closed mutation", upstreamCalls)
			}
			if !strings.Contains(logBuf.String(), `"reason_code":"`+tt.wantCode+`"`) {
				t.Fatalf("access log = %s, want reason_code %q", logBuf.String(), tt.wantCode)
			}
			for _, secret := range tt.forbiddenLeaks {
				if strings.Contains(logBuf.String(), secret) {
					t.Errorf("log output leaked body-derived value %q:\n%s", secret, logBuf.String())
				}
			}
		})
	}
}

func TestMutationReadFailureDoesNotReachUpstream(t *testing.T) {
	upstreamCalls := 0
	body := &mutationReadErrorBody{}
	handler := mutationMiddleware(t, Options{Mutation: injectMutationOptions("read-failure")}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	req.Body = body
	req.ContentLength = 1
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want zero after body read failure", upstreamCalls)
	}
	if !body.closed {
		t.Fatal("request body was not closed after read failure")
	}
}

type mutationReadErrorBody struct {
	closed bool
}

func (*mutationReadErrorBody) Read([]byte) (int, error) {
	return 0, errors.New("injected mutation body read failure")
}

func (b *mutationReadErrorBody) Close() error {
	b.closed = true
	return nil
}

func injectMutationOptions(id string) MutationOptions {
	return MutationOptions{Rules: []MutationRuleOptions{{
		ID:           id,
		Mode:         "enforce",
		Surfaces:     []string{mutationSurfaceContainerCreate},
		InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{"required": "value"}},
	}}}
}

func mutationMiddleware(t *testing.T, opts Options, next http.Handler) http.Handler {
	t.Helper()
	return mutationMiddlewareWithLogger(t, testLogger(), opts, next)
}

func mutationMiddlewareWithLogger(t *testing.T, logger *slog.Logger, opts Options, next http.Handler) http.Handler {
	t.Helper()
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/**", Action: ActionAllow, Index: 0})
	if err != nil {
		t.Fatalf("CompileRule: %v", err)
	}
	return MiddlewareWithOptions([]*CompiledRule{rule}, logger, opts)(next)
}
