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

// tryPutRef atomically checks the per-session cap (maxRefs <= 0 disables it)
// and records ref locally if there's room, reporting whether ref is now
// admitted (ok) and whether this call is what newly admitted it (isNew).
// isNew distinguishes a genuinely new ref from a re-PutRef of one the
// session already holds: SessionRegistry.PutRef must only increment the
// registry-wide refcount once per distinct ref per session, matching
// exactly how Close later decrements it once per entry in s.Refs — an
// unconditional increment on every call would let a client that calls Solve
// twice with the same Ref leak the registry-wide count by one forever, since
// Close only ever removes one contribution per distinct ref regardless of
// how many times PutRef added it locally. SessionRegistry.PutRef calls this
// under s.mu exactly once so the check-then-insert can never race against a
// concurrent PutRef call on the same session from another HTTP/2 stream
// (client-driven concurrency the streamAbuseGuard doc comment already notes
// as a live abuse surface).
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

// SessionRegistry tracks every currently-open mediated BuildKit tunnel.
// Safe for concurrent use.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[uint64]*Session
	nextID   uint64

	// refOwners is Phase 3's ref-ownership index: which SessionKey (client
	// identity + profile — see SessionKey's doc comment) admitted a given
	// BuildKit ref via PutRef, so a later Control/Status call naming that ref
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

// Close removes the session with the given ID, releasing every ref it
// admitted via PutRef from the registry-wide ownership index (see
// refOwners's doc comment) — a ref another still-open session sharing the
// same SessionKey also admitted stays owned; only this session's own
// contribution is released. A no-op if id doesn't exist (already closed, or
// never opened).
//
// The whole operation — unregistering from r.sessions, snapshotting the
// session's refs, and decrementing their registry-wide counts — happens
// under ONE r.mu critical section, mirroring PutRef (see its doc comment
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
	if len(refs) == 0 {
		return
	}

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

// PutRef registers ref as owned by session s, both locally (s.Refs, via
// Session.tryPutRef — used above by Close to know what to release) and under
// s.Key in the registry-wide ownership index OwnsRef consults. Returns false
// without recording anything if s already holds maxRefs distinct refs (see
// Limits.MaxRefsPerSession); maxRefs <= 0 disables the bound.
//
// The whole operation — confirming s is still registered in r.sessions,
// admitting the ref locally via tryPutRef, and publishing it to the
// registry-wide index — happens under ONE r.mu critical section, mirroring
// Close. Serializing the two on r.mu closes two races a finer-grained
// scheme was shown to leave open:
//
//  1. A PutRef whose tryPutRef insert lands after Close has already taken
//     its (then-empty) refsSnapshot would still publish to refOwners
//     moments later — an entry for a session Close has already run for and
//     will never run for again, so nothing would ever release it, and
//     OwnsRef would report true for that SessionKey/ref for the rest of
//     the process's lifetime.
//  2. The mirror image: a tryPutRef insert landing between Close's
//     r.sessions delete and its refsSnapshot puts the ref INTO the
//     snapshot without it ever reaching refOwners — Close's decrement loop
//     would then release a count this session never contributed, stealing
//     ownership from a still-open sibling session sharing the same
//     SessionKey (its Status calls would start failing
//     buildkit_ref_not_owned).
//
// Lock ordering: tryPutRef (and Close's refsSnapshot) acquire s.mu strictly
// NESTED inside the r.mu critical section, and no code path ever takes them
// in the opposite order, so the nesting cannot deadlock.
func (r *SessionRegistry) PutRef(s *Session, ref string, maxRefs int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, stillOpen := r.sessions[s.ID]; !stillOpen {
		return false
	}

	admitted, isNew := s.tryPutRef(ref, maxRefs)
	if !admitted {
		return false
	}
	if !isNew {
		// s already held this exact ref (a repeated PutRef, e.g. a retried
		// Solve with the same client-chosen Ref) — the registry-wide
		// refcount was already incremented for it once; see tryPutRef's doc
		// comment for why incrementing again here would leak the count.
		return true
	}

	if r.refOwners == nil {
		r.refOwners = make(map[SessionKey]map[string]int)
	}
	owners, ok := r.refOwners[s.Key]
	if !ok {
		owners = make(map[string]int)
		r.refOwners[s.Key] = owners
	}
	owners[ref]++
	return true
}

// OwnsRef reports whether ref was admitted via PutRef by ANY session sharing
// key — see refOwners's doc comment for why ownership is checked at the
// client-identity+profile granularity, not per individual connection.
func (r *SessionRegistry) OwnsRef(key SessionKey, ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refOwners[key][ref] > 0
}
