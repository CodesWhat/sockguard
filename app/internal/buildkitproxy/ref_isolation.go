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

// controlRefFrame replaces only top-level Ref (field 1 in both Solve and
// Status). All other wire bytes, including digest-approved LLB operations,
// remain untouched. Duplicate Ref fields collapse to the validated value.
func controlRefFrame(payload []byte, ref string, maxBytes int64) ([]byte, error) {
	out := make([]byte, grpcMessageHeaderLen, grpcMessageHeaderLen+len(payload))
	found := false
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
		if num == 1 {
			if typ != protowire.BytesType {
				return nil, errUnaryFrameProtocolError
			}
			if !found {
				out = protowire.AppendTag(out, 1, protowire.BytesType)
				out = protowire.AppendString(out, ref)
				found = true
			}
		} else {
			out = append(out, payload[:end]...)
		}
		payload = payload[end:]
	}
	if !found {
		return nil, errUnaryFrameProtocolError
	}
	payloadSize := int64(len(out)) - grpcMessageHeaderLen
	if payloadSize < 0 || payloadSize > math.MaxUint32 || (maxBytes > 0 && int64(len(out)) > maxBytes) {
		return nil, errMessageTooLarge
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(payloadSize))
	return out, nil
}
