package dockerresource

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

var fuzzLabelKinds = []Kind{
	KindContainer, KindImage, KindNetwork, KindVolume, KindService, KindTask,
	KindSecret, KindConfig, KindNode, KindSwarm, KindLibpodPod, KindLibpodNetwork,
	Kind("bogus"), Kind(""),
}

// FuzzDecodeLabels feeds daemon-shaped (and hostile) inspect JSON to
// DecodeLabels for every Kind. Ownership and visibility trust the result to
// decide who may see or touch a resource, so beyond not panicking it must be
// deterministic, return no labels alongside an error, reject unknown kinds,
// and keep kinds that share a wire shape in agreement.
func FuzzDecodeLabels(f *testing.F) {
	f.Add([]byte("\f[{}]"), uint8(11))
	f.Add([]byte(`{"Config":{"Labels":{"com.sockguard.owner":"a"}}}`), uint8(0))
	f.Add([]byte(`{"Config":{"Labels":{}},"ContainerConfig":{"Labels":{"k":"v"}}}`), uint8(1))
	f.Add([]byte(`{"Labels":{"k":"v"}}`), uint8(2))
	f.Add([]byte(`{"Spec":{"Labels":{"k":"v"}}}`), uint8(4))
	f.Add([]byte(`{"Labels":{},"Spec":{"ContainerSpec":{"Labels":{"k":"v"}}}}`), uint8(5))
	f.Add([]byte(`{"Labels":{"k":"v"}}`), uint8(10))
	f.Add([]byte(`[{"labels":{"k":"v"}}]`), uint8(11))
	f.Add([]byte(`[{"labels":{"k":"v"}},{"labels":{}}]`), uint8(11))
	f.Add([]byte(`null`), uint8(11))
	f.Add([]byte(`{"Config":{"Labels":{"k":1}}}`), uint8(0))
	f.Add([]byte(`{"labels":{"k":"v"}} trailing`), uint8(11))
	f.Add([]byte(``), uint8(0))

	f.Fuzz(func(t *testing.T, data []byte, kindIdx uint8) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		kind := fuzzLabelKinds[int(kindIdx)%len(fuzzLabelKinds)]

		labels, err := DecodeLabels(bytes.NewReader(data), kind)
		if err != nil && labels != nil {
			t.Fatalf("DecodeLabels(%q, %q) returned labels %v alongside error %v", data, kind, labels, err)
		}

		again, err2 := DecodeLabels(bytes.NewReader(data), kind)
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(labels, again) {
			t.Fatalf("DecodeLabels(%q, %q) not deterministic: (%v, %v) then (%v, %v)", data, kind, labels, err, again, err2)
		}

		switch kind {
		case KindContainer, KindImage, KindNetwork, KindVolume, KindService, KindTask,
			KindSecret, KindConfig, KindNode, KindSwarm, KindLibpodPod, KindLibpodNetwork:
		default:
			if err == nil {
				t.Fatalf("DecodeLabels(%q, %q) accepted an unsupported kind", data, kind)
			}
			return
		}

		if err == nil && kind == KindLibpodNetwork && !json.Valid(data) {
			t.Fatalf("libpod network decode accepted invalid JSON %q", data)
		}

		// Kinds that share a wire shape must decode identically.
		for _, group := range [][]Kind{
			{KindNetwork, KindVolume},
			{KindService, KindSecret, KindConfig, KindNode, KindSwarm},
		} {
			if !containsKind(group, kind) {
				continue
			}
			for _, other := range group {
				got, gotErr := DecodeLabels(bytes.NewReader(data), other)
				if (err == nil) != (gotErr == nil) || !reflect.DeepEqual(labels, got) {
					t.Fatalf("kinds %q and %q share a wire shape but disagree on %q: (%v, %v) vs (%v, %v)",
						kind, other, data, labels, err, got, gotErr)
				}
			}
		}
	})
}

func containsKind(kinds []Kind, k Kind) bool {
	for _, c := range kinds {
		if c == k {
			return true
		}
	}
	return false
}
