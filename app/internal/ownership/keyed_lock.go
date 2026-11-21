package ownership

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/codeswhat/sockguard/v3/app/internal/dockerresource"
	"github.com/codeswhat/sockguard/v3/app/internal/httpjson"
	"github.com/codeswhat/sockguard/v3/app/internal/logging"
)

// keyed_lock.go serializes the create-by-name routes across owners.
//
// With several owners in one instance, two clients can race each other's
// lookup-then-write windows: a preflight inspect finds a name free, another
// owner's create takes it, and the first request's write then lands on the
// other owner's resource (Podman's secret replace deletes it, a retag moves
// the name off its image). The preflight can't close that window, because the
// daemon offers no compare-and-set. Holding one lock per (kind, name) from the
// preflight until the upstream response is finished closes it for every client
// of this instance. It is in-process on purpose: the guarantee is scoped to
// one instance, as security.mdx already says for the single-owner races.

const (
	// DefaultLockTimeout is how long one request waits for a name another
	// request holds before it is refused with 503.
	DefaultLockTimeout = 10 * time.Second
	// DefaultMaxLockKeys bounds the keys held or waited on at once. Entries
	// are removed when the last holder or waiter leaves, so this only bites
	// under that many concurrent creates.
	DefaultMaxLockKeys = 4096
	// maxLockKeysPerRequest bounds how many names one request locks. A
	// request naming more is refused rather than half locked.
	maxLockKeysPerRequest = 64

	reasonCodeOwnerLockTimeout  = "owner_name_lock_timeout"
	reasonCodeOwnerLockCapacity = "owner_name_lock_capacity"
	ownerLockTimeoutMessage     = "owner policy could not serialize this create: another request holds the same name, retry"
	ownerLockCapacityMessage    = "owner policy could not serialize this create: too many names are locked, retry"
)

var (
	errLockTimeout  = errors.New("owner name lock wait timed out")
	errLockCapacity = errors.New("owner name lock table is full")
)

type lockKey struct {
	kind dockerresource.Kind
	name string
}

type lockEntry struct {
	// sem holds one token while a request owns the key.
	sem chan struct{}
	// users counts the holder and every waiter; the entry is deleted at zero.
	users int
}

// KeyedLocks is a bounded in-process mutex per (resource kind, name).
type KeyedLocks struct {
	timeout time.Duration
	maxKeys int

	mu      sync.Mutex
	entries map[lockKey]*lockEntry
}

// NewKeyedLocks returns a lock set. A non-positive timeout or maxKeys takes
// the default.
func NewKeyedLocks(timeout time.Duration, maxKeys int) *KeyedLocks {
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}
	if maxKeys <= 0 {
		maxKeys = DefaultMaxLockKeys
	}
	return &KeyedLocks{timeout: timeout, maxKeys: maxKeys, entries: map[lockKey]*lockEntry{}}
}

// size reports the live entries, for tests.
func (l *KeyedLocks) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// acquire takes one key, waiting up to the timeout or until ctx ends.
func (l *KeyedLocks) acquire(ctx context.Context, key lockKey) error {
	l.mu.Lock()
	entry, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.maxKeys {
			l.mu.Unlock()
			return errLockCapacity
		}
		entry = &lockEntry{sem: make(chan struct{}, 1)}
		l.entries[key] = entry
	}
	entry.users++
	l.mu.Unlock()

	timer := time.NewTimer(l.timeout)
	defer timer.Stop()
	select {
	case entry.sem <- struct{}{}:
		return nil
	case <-timer.C:
		l.leave(key, entry)
		return errLockTimeout
	case <-ctx.Done():
		l.leave(key, entry)
		return ctx.Err()
	}
}

// release hands the key back and drops its entry when nobody else wants it.
func (l *KeyedLocks) release(key lockKey) {
	l.mu.Lock()
	entry := l.entries[key]
	l.mu.Unlock()
	if entry != nil {
		<-entry.sem
		l.leave(key, entry)
	}
}

func (l *KeyedLocks) leave(key lockKey, entry *lockEntry) {
	l.mu.Lock()
	entry.users--
	if entry.users == 0 && l.entries[key] == entry {
		delete(l.entries, key)
	}
	l.mu.Unlock()
}

// Acquire takes every key in a fixed order, so two requests that name the same
// set can't deadlock, and returns a release for them all. On a failure it
// releases what it took and returns the error.
func (l *KeyedLocks) Acquire(ctx context.Context, keys []lockKey) (func(), error) {
	sorted := append([]lockKey(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].kind != sorted[j].kind {
			return sorted[i].kind < sorted[j].kind
		}
		return sorted[i].name < sorted[j].name
	})
	held := make([]lockKey, 0, len(sorted))
	for i, key := range sorted {
		if i > 0 && key == sorted[i-1] {
			continue
		}
		if err := l.acquire(ctx, key); err != nil {
			for j := len(held) - 1; j >= 0; j-- {
				l.release(held[j])
			}
			return nil, err
		}
		held = append(held, key)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for j := len(held) - 1; j >= 0; j-- {
				l.release(held[j])
			}
		})
	}, nil
}

// lockName is a name a request creates or takes over, as the daemon compares
// it.
type lockName struct {
	kind dockerresource.Kind
	name string
}

// normalizeLockName reduces a name to the form the daemon compares. Docker
// stores container and pod names with a leading slash and accepts the create
// with or without one, so both spellings are one name. Other kinds compare
// exactly.
func normalizeLockName(kind dockerresource.Kind, name string) string {
	switch kind {
	case dockerresource.KindContainer, dockerresource.KindLibpodPod:
		if len(name) > 1 && name[0] == '/' {
			return name[1:]
		}
	}
	return name
}

// addLockName records a created name on refs, skipping an empty one: the
// daemon generates those, so there is nothing to race for.
func (refs *ownershipRequestReferences) addLockName(kind dockerresource.Kind, name string) {
	if name == "" {
		return
	}
	refs.lockNames = append(refs.lockNames, lockName{kind: kind, name: normalizeLockName(kind, name)})
}

// lockKeysFor returns every name the request writes, with the image names a
// pull, retag, commit, import or load assigns.
func lockKeysFor(refs *ownershipRequestReferences) []lockKey {
	if refs == nil {
		return nil
	}
	var keys []lockKey
	for _, n := range refs.lockNames {
		keys = append(keys, lockKey{kind: n.kind, name: n.name})
	}
	if refs.imageTag != nil {
		for _, ref := range []string{refs.imageTag.target, refs.imageTag.storedTarget} {
			if ref != "" {
				keys = append(keys, lockKey{kind: dockerresource.KindImage, name: ref})
			}
		}
	}
	if refs.imageDestinations != nil {
		for _, dest := range refs.imageDestinations.destinations {
			for _, ref := range []string{dest.target, dest.storedTarget} {
				if ref != "" {
					keys = append(keys, lockKey{kind: dockerresource.KindImage, name: ref})
				}
			}
		}
	}
	return keys
}

var noRelease = func() {}

// acquireCreateLocks takes the request's name locks when the instance has
// several owners. It answers 503 and reports false when it can't, failing
// closed: the request is never forwarded unserialized. A request that names
// nothing, or an instance with one owner, costs nothing.
func acquireCreateLocks(w http.ResponseWriter, r *http.Request, opts Options, refs *ownershipRequestReferences) (func(), bool) {
	if opts.Locks == nil {
		return noRelease, true
	}
	keys := lockKeysFor(refs)
	if len(keys) == 0 {
		return noRelease, true
	}
	if len(keys) > maxLockKeysPerRequest {
		writeLockRefusal(w, r, reasonCodeOwnerLockCapacity, ownerLockCapacityMessage)
		return nil, false
	}
	release, err := opts.Locks.Acquire(r.Context(), keys)
	if err != nil {
		switch {
		case errors.Is(err, errLockCapacity):
			writeLockRefusal(w, r, reasonCodeOwnerLockCapacity, ownerLockCapacityMessage)
		default:
			writeLockRefusal(w, r, reasonCodeOwnerLockTimeout, ownerLockTimeoutMessage)
		}
		return nil, false
	}
	return release, true
}

func writeLockRefusal(w http.ResponseWriter, r *http.Request, code, message string) {
	logging.SetDeniedWithCode(w, r, code, message, nil)
	_ = httpjson.Write(w, http.StatusServiceUnavailable, httpjson.ErrorResponse{Message: message})
}
