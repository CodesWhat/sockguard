package buildkitproxy

import (
	"sync"
	"time"
)

const (
	// BuildKit currently generates 25-byte lowercase base-36 identifiers for
	// sessions, refs, and upload ids. These bounds leave ample compatibility
	// room for opaque future formats while preventing one gRPC message from
	// pinning frame-sized strings in the long-lived registry indexes.
	maxBuildkitSessionIDBytes = 256
	maxBuildkitRefBytes       = 256
	maxBuildkitUploadIDBytes  = 256

	// One Control tunnel normally names one BuildKit session. This generous
	// ceiling prevents repeated Solves that reuse one ref from bypassing
	// MaxRefsPerSession and growing solveSessions without bound.
	maxBuildkitSessionIDsPerSession = 256

	// Upload callbacks normally start while Solve is active. Keeping their
	// admission valid for a full hour preserves delayed Pull calls after the
	// /grpc control tunnel closes while ensuring abandoned ids eventually stop
	// consuming a principal's quota.
	uploadKeyTTL = time.Hour
)

// canonicalBuildkitSessionID validates the opaque identifier shared by the
// POST /session header and Control/Solve.Session. BuildKit's current base-36
// ids are a strict subset of this conservative ASCII alphabet; UUID-shaped
// and similarly opaque future ids remain compatible without admitting path
// separators, whitespace, control bytes, or non-ASCII confusables.
func canonicalBuildkitSessionID(id string) (string, bool) {
	if id == "" || len(id) > maxBuildkitSessionIDBytes {
		return "", false
	}
	for i := range len(id) {
		c := id[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' {
			continue
		}
		return "", false
	}
	return id, true
}

// SessionKey identifies who a mediated BuildKit tunnel belongs to. Per the
// #185 Phase 2 sign-off ("session/ref registry keyed by client identity +
// profile — never UUID alone"), the registry never trusts a client-supplied
// BuildKit session identifier by itself. ClientIdentity and Profile are
// resolved by cmd/serve.go's wiring layer from a verified certificate
// fingerprint, captured Unix peer credentials, or a normalized remote host
// fallback. Cross-endpoint capabilities add the BuildKit session identifier
// as a third, untrusted-but-correlating component in buildkitSessionKey.
type SessionKey struct {
	ClientIdentity string
	Profile        string
}

// RefState is Phase 3+'s per-solve-ref ownership record: which session
// produced a given BuildKit ref, so a later Control/Status or
// FileSend/DiffCopy call naming that ref can be checked against the session
// that actually opened it instead of trusting a caller-supplied ref string
// on its own (the #185 synthesis's "buildkit_ref_not_owned" audit reason,
// Control/Status's "ref must belong to an admitted Solve from the same
// client/profile" requirement).
type RefState struct {
	Ref      string
	OpenedAt time.Time
}

// Session is one mediated tunnel: a single hijacked /session or /grpc
// connection tracked for its lifetime in a SessionRegistry. Profile is
// frozen at Open time and never reassigned — a config hot-reload that
// changes what a profile name means must not retroactively change the
// policy an already-open tunnel is held to (the #185 synthesis: "the
// profile is frozen at tunnel open"). ID is a sockguard-assigned, per-process
// monotonic counter, never derived from client input, used to correlate this
// session's audit log lines without exposing (or trusting) the client's own
// session ID. ClientUUID is the BuildKit-generated correlation component
// presented on POST /session; registry authorization always combines it with
// Key and never treats it as a principal.
type Session struct {
	ID         uint64
	Key        SessionKey
	Endpoint   Endpoint
	Profile    string
	ClientUUID string
	OpenedAt   time.Time

	mu               sync.Mutex
	Refs             map[string]*RefState
	buildkitSessions map[string]struct{}
}

// tryPutRef atomically checks the per-session cap (maxRefs <= 0 disables it)
// and records ref locally if there's room, reporting whether ref is now
// admitted (ok) and whether this call is what newly admitted it (isNew).
// isNew distinguishes a genuinely new ref from a repeated admission of one
// the session already holds: SessionRegistry.PutRef must only increment the
// registry-wide refcount once per distinct ref per session, matching exactly
// how Close later decrements it once per entry in s.Refs.
func (s *Session) tryPutRef(ref string, maxRefs int) (ok, isNew bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Refs[ref]; exists {
		return true, false
	}
	if maxRefs > 0 && len(s.Refs) >= maxRefs {
		return false, false
	}
	s.Refs[ref] = &RefState{Ref: ref, OpenedAt: time.Now()}
	return true, true
}

// refsSnapshot returns a copy of the ref strings this session currently
// holds, for SessionRegistry.Close to release without holding both s.mu and
// the registry's own mutex at once.
func (s *Session) refsSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.Refs))
	for ref := range s.Refs {
		out = append(out, ref)
	}
	return out
}

func (s *Session) buildkitSessionsSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.buildkitSessions))
	for id := range s.buildkitSessions {
		out = append(out, id)
	}
	return out
}

type buildkitSessionKey struct {
	Principal SessionKey
	ID        string
}

type uploadKeyState struct {
	ExpiresAt time.Time
}

// SessionRegistry tracks every currently-open mediated BuildKit tunnel.
// Safe for concurrent use.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[uint64]*Session
	nextID   uint64

	// refOwners is Phase 3's ref-ownership index: which SessionKey (client
	// identity + profile — see SessionKey's doc comment) admitted a given
	// BuildKit ref via an admitted Solve, so a later Control/Status call naming that ref
	// can be checked with OwnsRef against the identity+profile that ran the
	// Solve, NOT against the single connection/Session.ID that happened to
	// carry it. buildx typically opens Solve and Status as two concurrent
	// streams on the very same hijacked connection, so in the common case
	// this coincides with a single Session — but per the #185 Phase 3
	// synthesis ("belongs to an admitted Solve from the same client
	// identity + profile"), ownership is deliberately scoped to the wider
	// key, not the narrower connection, so it survives a client reconnecting
	// mid-build without granting any ownership across DIFFERENT identities
	// or profiles. The map value is a refcount, not a set-membership bool,
	// because more than one live Session sharing the same SessionKey may
	// each PutRef the same ref string (harmless — same trust boundary); Close
	// only removes the contribution the session it's closing actually made.
	refOwners map[SessionKey]map[string]int

	// solveSessions binds session-side capabilities to the BuildKit session
	// identifier named by Control/Solve and presented by POST /session. The
	// caller-supplied identifier is safe only as the final component of this
	// key; Principal remains the trusted client identity plus policy profile.
	solveSessions map[buildkitSessionKey]int

	// uploadKeys is Phase 5 (issue #185)'s one-use Upload/Pull credential index:
	// which principal/profile/BuildKit-session scope admitted a given upload
	// URL id (see upload.go's
	// solveUploadKeys, called from bridge.go's forwardControlMediated
	// once a Solve naming an "http://buildkit-session/<id>" context/
	// context:<name> FrontendAttrs value is admitted). Scoped to
	// buildkitSessionKey rather than a single tunnel because the admitting
	// call (Control/Solve, over POST /grpc) and
	// the consuming call (Upload/Pull, over POST /session) are always two
	// DIFFERENT hijacked connections — buildx dials /session and /grpc
	// separately — so they can never share one Session.ID. Unlike
	// refOwners' refcount-per-ref shape, a value here is consumed exactly
	// once (map entry deleted on the first successful ConsumeUploadKey) and
	// is NOT released early by SessionRegistry.Close: an admitted-but-not-
	// yet-consumed token has no session of its own to tie a release to
	// (the admitting /grpc session may legitimately close before the
	// /session tunnel's Pull call ever arrives), so it stays valid until
	// consumed or the process restarts. AdmitSolve bounds the SET SIZE per
	// SessionKey via Limits.MaxUploadKeysPerSession to keep this from growing
	// unboundedly for one client identity across many builds.
	uploadKeys map[buildkitSessionKey]map[string]uploadKeyState

	now func() time.Time
}

type solveAdmissionResult uint8

const (
	solveAdmissionSucceeded solveAdmissionResult = iota
	solveAdmissionRefLimitExceeded
	solveAdmissionUploadLimitExceeded
	solveAdmissionSessionIDMissing
	solveAdmissionSessionIDInvalid
	solveAdmissionSessionLimitExceeded
	solveAdmissionRefInvalid
	solveAdmissionUploadIDInvalid
	solveAdmissionSessionClosed
)

// NewSessionRegistry returns an empty registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{sessions: make(map[uint64]*Session), now: time.Now}
}

// setNow replaces the registry clock. Production uses time.Now; tests inject
// a deterministic clock so upload expiry can be exercised without sleeping.
func (r *SessionRegistry) setNow(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now == nil {
		r.now = time.Now
		return
	}
	r.now = now
}

func (r *SessionRegistry) currentTimeLocked() time.Time {
	if r.now == nil {
		return time.Now()
	}
	return r.now()
}

// Open registers a new session for key and returns it. clientUUID is the
// client-supplied X-Docker-Expose-Session-Uuid header value (or empty on the
// /grpc control tunnel). It is used only in combination with key; see
// SessionKey's doc comment.
func (r *SessionRegistry) Open(key SessionKey, endpoint Endpoint, clientUUID string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nextID++
	s := &Session{
		ID:               r.nextID,
		Key:              key,
		Endpoint:         endpoint,
		Profile:          key.Profile,
		ClientUUID:       clientUUID,
		OpenedAt:         time.Now(),
		Refs:             make(map[string]*RefState),
		buildkitSessions: make(map[string]struct{}),
	}
	r.sessions[s.ID] = s
	return s
}

// Close removes the session with the given ID, releasing every ref it
// admitted via a Solve from the registry-wide ownership index (see
// refOwners's doc comment) — a ref another still-open session sharing the
// same SessionKey also admitted stays owned; only this session's own
// contribution is released. A no-op if id doesn't exist (already closed, or
// never opened).
//
// The whole operation — unregistering from r.sessions, snapshotting the
// session's refs, and decrementing their registry-wide counts — happens
// under ONE r.mu critical section, mirroring admitSolve (see its doc comment
// for the two races this serialization closes and for the r.mu → s.mu lock
// ordering refsSnapshot's nested s.mu acquisition follows).
func (r *SessionRegistry) Close(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return
	}
	delete(r.sessions, id)

	refs := s.refsSnapshot()
	owners := r.refOwners[s.Key]
	for _, ref := range refs {
		if owners[ref] <= 1 {
			delete(owners, ref)
		} else {
			owners[ref]--
		}
	}
	if len(owners) == 0 {
		delete(r.refOwners, s.Key)
	}

	for _, buildkitSessionID := range s.buildkitSessionsSnapshot() {
		scope := buildkitSessionKey{Principal: s.Key, ID: buildkitSessionID}
		if r.solveSessions[scope] <= 1 {
			delete(r.solveSessions, scope)
		} else {
			r.solveSessions[scope]--
		}
	}
}

// Get looks up a session by its sockguard-assigned ID.
func (r *SessionRegistry) Get(id uint64) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	return s, ok
}

// Len reports the number of currently-open sessions.
func (r *SessionRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// PutRef registers ref as owned by session s, both locally for Close cleanup
// and under s.Key in the registry-wide ownership index. Returns false without
// recording anything if the session is closed or already holds maxRefs
// distinct refs; maxRefs <= 0 disables the bound. Production Solve admission
// uses admitSolve so ref and upload-id publication stay atomic.
func (r *SessionRegistry) PutRef(s *Session, ref string, maxRefs int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if open, stillOpen := r.sessions[s.ID]; !stillOpen || open != s {
		return false
	}

	admitted, isNew := s.tryPutRef(ref, maxRefs)
	if !admitted {
		return false
	}
	if !isNew {
		return true
	}

	if r.refOwners == nil {
		r.refOwners = make(map[SessionKey]map[string]int)
	}
	owners := r.refOwners[s.Key]
	if owners == nil {
		owners = make(map[string]int)
		r.refOwners[s.Key] = owners
	}
	owners[ref]++
	return true
}

// admitSolve atomically publishes a Solve's ref ownership and upload ids.
// Every limit and session-liveness check runs before either index is mutated,
// so a rejected Solve cannot leave behind ownership or a usable partial id.
func (r *SessionRegistry) admitSolve(s *Session, buildkitSessionID, ref string, uploadIDs []string, maxRefs, maxUploadKeys int) solveAdmissionResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	if open, stillOpen := r.sessions[s.ID]; !stillOpen || open != s {
		return solveAdmissionSessionClosed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if buildkitSessionID == "" {
		return solveAdmissionSessionIDMissing
	}
	if _, ok := canonicalBuildkitSessionID(buildkitSessionID); !ok {
		return solveAdmissionSessionIDInvalid
	}
	if ref == "" || len(ref) > maxBuildkitRefBytes {
		return solveAdmissionRefInvalid
	}
	for _, id := range uploadIDs {
		if id == "" || len(id) > maxBuildkitUploadIDBytes {
			return solveAdmissionUploadIDInvalid
		}
	}

	_, refExists := s.Refs[ref]
	if !refExists && maxRefs > 0 && len(s.Refs) >= maxRefs {
		return solveAdmissionRefLimitExceeded
	}
	_, buildkitSessionExists := s.buildkitSessions[buildkitSessionID]
	if !buildkitSessionExists && len(s.buildkitSessions) >= maxBuildkitSessionIDsPerSession {
		return solveAdmissionSessionLimitExceeded
	}

	now := r.currentTimeLocked()
	totalUploadIDs := r.purgeExpiredUploadKeysForPrincipalLocked(s.Key, now)
	scope := buildkitSessionKey{Principal: s.Key, ID: buildkitSessionID}
	existingUploadIDs := r.uploadKeys[scope]
	newUploadIDs := make([]string, 0, len(uploadIDs))
	seen := make(map[string]struct{}, len(uploadIDs))
	for _, id := range uploadIDs {
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		if _, exists := existingUploadIDs[id]; !exists {
			newUploadIDs = append(newUploadIDs, id)
		}
	}
	if maxUploadKeys > 0 && totalUploadIDs+len(newUploadIDs) > maxUploadKeys {
		return solveAdmissionUploadLimitExceeded
	}

	if !refExists {
		s.Refs[ref] = &RefState{Ref: ref, OpenedAt: time.Now()}
		if r.refOwners == nil {
			r.refOwners = make(map[SessionKey]map[string]int)
		}
		owners := r.refOwners[s.Key]
		if owners == nil {
			owners = make(map[string]int)
			r.refOwners[s.Key] = owners
		}
		owners[ref]++
	}
	if !buildkitSessionExists {
		s.buildkitSessions[buildkitSessionID] = struct{}{}
		if r.solveSessions == nil {
			r.solveSessions = make(map[buildkitSessionKey]int)
		}
		r.solveSessions[scope]++
	}
	if len(newUploadIDs) > 0 {
		if r.uploadKeys == nil {
			r.uploadKeys = make(map[buildkitSessionKey]map[string]uploadKeyState)
		}
		ids := r.uploadKeys[scope]
		if ids == nil {
			ids = make(map[string]uploadKeyState)
			r.uploadKeys[scope] = ids
		}
		for _, id := range newUploadIDs {
			ids[id] = uploadKeyState{ExpiresAt: now.Add(uploadKeyTTL)}
		}
	}
	return solveAdmissionSucceeded
}

// purgeExpiredUploadKeysForPrincipalLocked removes expired upload ids for one
// principal/profile and returns the number of live ids still consuming that
// principal's quota. Caller must hold r.mu.
func (r *SessionRegistry) purgeExpiredUploadKeysForPrincipalLocked(principal SessionKey, now time.Time) int {
	total := 0
	for scope, ids := range r.uploadKeys {
		if scope.Principal != principal {
			continue
		}
		for id, state := range ids {
			if !now.Before(state.ExpiresAt) {
				delete(ids, id)
				continue
			}
			total++
		}
		if len(ids) == 0 {
			delete(r.uploadKeys, scope)
		}
	}
	return total
}

// purgeExpiredUploadKeysForScopeLocked removes expired upload ids for one
// principal/profile/session scope. Caller must hold r.mu.
func (r *SessionRegistry) purgeExpiredUploadKeysForScopeLocked(scope buildkitSessionKey, now time.Time) {
	ids := r.uploadKeys[scope]
	for id, state := range ids {
		if !now.Before(state.ExpiresAt) {
			delete(ids, id)
		}
	}
	if len(ids) == 0 {
		delete(r.uploadKeys, scope)
	}
}

// OwnsRef reports whether ref was admitted by ANY session sharing
// key — see refOwners's doc comment for why ownership is checked at the
// client-identity+profile granularity, not per individual connection.
func (r *SessionRegistry) OwnsRef(key SessionKey, ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refOwners[key][ref] > 0
}

// HasAdmittedSolve reports whether key and buildkitSessionID have admitted at
// least one Control/Solve on an open control tunnel. Phase 5's
// FileSend/DiffCopy mediation
// (filesend.go) uses this to enforce the #185 synthesis's "allow only when
// bound to an admitted Solve from the same correlated session" rule: moby.filesync.
// v1.FileSend.DiffCopy's BytesMessage carries no ref (or any other
// identifying field) of its own to check with OwnsRef directly, so the only
// meaningful check available is "has this principal/profile/session scope
// solved anything at all yet."
func (r *SessionRegistry) HasAdmittedSolve(key SessionKey, buildkitSessionID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.solveSessions[buildkitSessionKey{Principal: key, ID: buildkitSessionID}] > 0
}

// ConsumeUploadKey reports whether id is a currently-valid, not-yet-consumed
// Upload/Pull token for key, and if so atomically removes it — the "one-use"
// half of the #185 synthesis's "one-use token bound to an admitted stdin/
// remote-context upload" requirement. A second call with the same id (or a
// call naming an id that was never admitted at all) returns false: both
// cases mean "this is not currently a valid token for a fresh Pull,"
// deliberately collapsed to one outcome — see upload.go's
// buildkit_upload_token_invalid audit reason.
func (r *SessionRegistry) ConsumeUploadKey(key SessionKey, buildkitSessionID, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	scope := buildkitSessionKey{Principal: key, ID: buildkitSessionID}
	r.purgeExpiredUploadKeysForScopeLocked(scope, r.currentTimeLocked())
	keys, ok := r.uploadKeys[scope]
	if !ok {
		return false
	}
	if _, exists := keys[id]; !exists {
		return false
	}
	delete(keys, id)
	if len(keys) == 0 {
		delete(r.uploadKeys, scope)
	}
	return true
}
