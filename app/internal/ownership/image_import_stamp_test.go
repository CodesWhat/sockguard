package ownership

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func TestMutateImageCreateStampsImports(t *testing.T) {
	t.Parallel()
	const ownerStamp = `LABEL "com.sockguard.owner"="job-123"`
	forged := "LABEL com.sockguard.owner=team-b"

	tests := []struct {
		name        string
		path        string
		rawQuery    string
		wantChanges []string
		wantErr     bool
	}{
		{name: "compat import", path: "/images/create", rawQuery: "fromSrc=-&repo=mine", wantChanges: []string{ownerStamp}},
		{name: "compat import with empty fromImage", path: "/images/create", rawQuery: "fromImage=&fromSrc=-&repo=mine", wantChanges: []string{ownerStamp}},
		{name: "client changes come before the stamp", path: "/images/create", rawQuery: "fromSrc=-&repo=mine&changes=" + url.QueryEscape("LABEL a=b") + "&changes=ENV+A%3Db", wantChanges: []string{"LABEL a=b", "ENV A=b", ownerStamp}},
		{name: "native import", path: "/libpod/images/import", rawQuery: "reference=mine&changes=" + url.QueryEscape("LABEL a=b"), wantChanges: []string{"LABEL a=b", ownerStamp}},
		{name: "forged owner label is refused", path: "/images/create", rawQuery: "fromSrc=-&repo=mine&changes=" + url.QueryEscape(forged), wantErr: true},
		{name: "forged owner label on the native route is refused", path: "/libpod/images/import", rawQuery: "reference=mine&changes=" + url.QueryEscape(forged), wantErr: true},
		{name: "case-variant changes is refused", path: "/images/create", rawQuery: "fromSrc=-&repo=mine&Changes=" + url.QueryEscape(forged), wantErr: true},
		{name: "compat pull is not stamped", path: "/images/create", rawQuery: "fromImage=nginx&tag=1"},
		{name: "native pull is not stamped", path: "/libpod/images/pull", rawQuery: "reference=nginx%3A1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, tt.path+"?"+tt.rawQuery, nil)
			_, err := mutateImageCreateOwnershipRequest(req, tt.path, Options{LabelKey: DefaultLabelKey, Owner: "job-123"})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			got := req.URL.Query()["changes"]
			if !reflect.DeepEqual(got, tt.wantChanges) {
				t.Fatalf("changes = %q, want %q", got, tt.wantChanges)
			}
		})
	}
}

func TestDockerfileLabelInstructionQuoting(t *testing.T) {
	t.Parallel()
	got, ok := dockerfileLabelInstruction("k", `a "b" $HOME \x`)
	if !ok || got != `LABEL "k"="a \"b\" \$HOME \\x"` {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	for _, bad := range []string{"a\nb", "a\x00b", "a\x7fb"} {
		if _, ok := dockerfileLabelInstruction("k", bad); ok {
			t.Fatalf("value %q was spelled, want refusal", bad)
		}
		if _, ok := dockerfileLabelInstruction(bad, "v"); ok {
			t.Fatalf("key %q was spelled, want refusal", bad)
		}
	}
}

func TestImageImportChangeRefusal(t *testing.T) {
	t.Parallel()
	const key = "com.sockguard.owner"
	refused := []string{
		"LABEL z=\\",
		"LABEL z='\\",
		"LABEL z=\\   ",
		"LABEL z='open",
		`LABEL z="open`,
		`LABEL z="a\"`,
		"ENV A=it's",
		"LABEL a=b\nLABEL c=d",
		"LABEL a=b\rLABEL c=d",
		"# escape=`",
		"  # syntax=evil/frontend",
		"LABEL com.sockguard.owner=team-b",
		`LABEL "com.sockguard.owner"="team-b"`,
		`LABEL 'com.sockguard.owner'=team-b`,
		`LABEL com.sock"guard".owner=x`,
		`LABEL com.sockguard.\owner=x`,
		"label=com.sockguard.owner=x",
		"LABEL a=b com.sockguard.owner=x",
	}
	for _, change := range refused {
		if reason := imageImportChangeRefusal(change, key); reason == "" {
			t.Errorf("%q was accepted", change)
		}
	}
	accepted := []string{
		"ENV A=b",
		"CMD=/bin/sh",
		`LABEL a="b c" d='e f'`,
		`LABEL a="it's"`,
		`LABEL a=it\'s`,
		`ENV com.sockguard.owner=x`,
		`LABEL a=b\\ c`,
		"",
	}
	for _, change := range accepted {
		if reason := imageImportChangeRefusal(change, key); reason != "" {
			t.Errorf("%q was refused: %s", change, reason)
		}
	}
}
