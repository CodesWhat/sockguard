package buildkitproxy

import (
	"sync"
	"time"
)

// SessionKey identifies who a mediated BuildKit tunnel belongs to. Per the
// #185 Phase 2 sign-off ("session/ref registry keyed by client identity +
// profile — never UUID alone"), the registry never trusts the
// client-supplied X-Docker-Expose-Session-Uuid value as its key: that header
// is attacker-controlled and two unrelated clients could present the same
// (or colliding) value. ClientIdentity and Profile are resolved by the
// caller — cmd/serve.go's wiring layer, which owns internal/clientacl and
// must not be imported back into this package (see mediator.go's Dialer doc
// comment for the same layering reason) — from whatever identity signal
// sockguard already trusts elsewhere for that connection (TLS client
// certificate CN, unix peer credentials, or at minimum the remote address),
// paired with the policy profile selected for the request.
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
// client/profile" requirement). Phase 2 defines the shape and gives Session
// a place to hold it, but nothing populates it yet — no phase-2 code path
// ever calls Session.PutRef.
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
// session UUID.
type Session struct {
	ID         uint64
	Key        SessionKey
	Endpoint   Endpoint
	Profile    string
	ClientUUID string
	OpenedAt   time.Time

	mu   sync.Mutex
	Refs map[string]*RefState
}

// PutRef records ref as owned by this session. Phase 3+ calls this when a
// Control/Solve this session issued completes; Phase 2 never calls it in any
// production code path, but the method exists now so the registry's shape
// doesn't change out from under the phase that actually needs it.
func (s *Session) PutRef(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Refs[ref] = &RefState{Ref: ref, OpenedAt: time.Now()}
}

// OwnsRef reports whether ref was previously recorded via PutRef on this
// session.
func (s *Session) OwnsRef(ref string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Refs[ref]
	return ok
}

// SessionRegistry tracks every currently-open mediated BuildKit tunnel.
// Safe for concurrent use.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[uint64]*Session
	nextID   uint64
}

// NewSessionRegistry returns an empty registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{sessions: make(map[uint64]*Session)}
}

// Open registers a new session for key and returns it. clientUUID is the
// client-supplied X-Docker-Expose-Session-Uuid header value (or empty
// string) — recorded as advisory metadata for logs/correlation only; see
// SessionKey's doc comment for why it is never the registry's trust
// boundary.
func (r *SessionRegistry) Open(key SessionKey, endpoint Endpoint, clientUUID string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nextID++
	s := &Session{
		ID:         r.nextID,
		Key:        key,
		Endpoint:   endpoint,
		Profile:    key.Profile,
		ClientUUID: clientUUID,
		OpenedAt:   time.Now(),
		Refs:       make(map[string]*RefState),
	}
	r.sessions[s.ID] = s
	return s
}

// Close removes the session with the given ID. A no-op if it doesn't exist
// (already closed, or never opened).
func (r *SessionRegistry) Close(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
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
