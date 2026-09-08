package buildkitproxy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

// daemonBuildRef keeps daemon-global jobs and history in the same trust
// boundary as Sockguard's client/profile ownership index. Length prefixes
// keep distinct tuples distinct even when their components contain separators.
func daemonBuildRef(key SessionKey, ref string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("sockguard-build-ref-v1"))
	var size [8]byte
	for _, component := range []string{key.ClientIdentity, key.Profile, ref} {
		binary.BigEndian.PutUint64(size[:], uint64(len(component)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(component))
	}
	return "sg-" + hex.EncodeToString(h.Sum(nil))
}

// controlRefFrame replaces top-level Ref (field 1 in Solve and Status) and,
// for Solve, Session (field 5). All other wire bytes, including digest-approved
// LLB operations, remain untouched. Duplicate identity fields collapse to the
// validated values. An empty session leaves field 5 untouched for Status.
func controlRefFrame(payload []byte, ref, session string, maxBytes int64) ([]byte, error) {
	out := make([]byte, grpcMessageHeaderLen, grpcMessageHeaderLen+len(payload))
	identities := map[protowire.Number]string{1: ref}
	if session != "" {
		identities[5] = session
	}
	found := make(map[protowire.Number]bool, len(identities))
	for len(payload) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(payload)
		if tagLen < 0 {
			return nil, errUnaryFrameProtocolError
		}
		valueLen := protowire.ConsumeFieldValue(num, typ, payload[tagLen:])
		if valueLen < 0 {
			return nil, errUnaryFrameProtocolError
		}
		end := tagLen + valueLen
		if value, replace := identities[num]; replace {
			if typ != protowire.BytesType {
				return nil, errUnaryFrameProtocolError
			}
			if !found[num] {
				out = protowire.AppendTag(out, num, protowire.BytesType)
				out = protowire.AppendString(out, value)
				found[num] = true
			}
		} else {
			out = append(out, payload[:end]...)
		}
		payload = payload[end:]
	}
	if len(found) != len(identities) {
		return nil, errUnaryFrameProtocolError
	}
	payloadSize := int64(len(out)) - grpcMessageHeaderLen
	if payloadSize < 0 || payloadSize > math.MaxUint32 || (maxBytes > 0 && int64(len(out)) > maxBytes) {
		return nil, errMessageTooLarge
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(payloadSize))
	return out, nil
}
