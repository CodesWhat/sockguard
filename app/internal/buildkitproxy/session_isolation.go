package buildkitproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// daemonSessionID scopes the daemon's global callback lookup to a verified
// client/profile. Unlike build refs, session IDs can also appear inside LLB
// source attributes that the daemon resolves without another proxy request.
// A keyed namespace prevents clients from calculating a foreign backend ID.
// The key lives for the registry's lifetime, matching its active tunnels.
func (r *SessionRegistry) daemonSessionID(key SessionKey, id string) string {
	h := hmac.New(sha256.New, r.sessionSecret[:])
	_, _ = h.Write([]byte("sockguard-build-session-v1"))
	var size [8]byte
	for _, component := range []string{key.ClientIdentity, key.Profile, id} {
		binary.BigEndian.PutUint64(size[:], uint64(len(component)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(component))
	}
	return "sg-" + hex.EncodeToString(h.Sum(nil))
}
