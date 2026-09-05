package testhelp

// JSONArrayCase is one upstream list body and the verdict every streaming
// JSON-array parser in this build has to reach on it.
//
// Accept is true when the body is exactly one well-formed top-level JSON
// array, trailing whitespace included, and false when the parser must refuse
// it and let its caller answer 502. There is no third outcome: forwarding a
// body the parser could not account for in full is the failure these cases
// exist to catch, because the client reads the rewritten result as the
// complete list.
type JSONArrayCase struct {
	Name   string
	Body   string
	Accept bool
}

// JSONArrayTerminationCases returns the shared table both list-body filters
// assert against: internal/visibility's patternFilterWriter.flushFiltered and
// internal/responsefilter's streamArrayResponse and decodeJSONObjectArray.
//
// Two packages grew separate streaming decoders over the same Docker list
// bodies, and they drifted: responsefilter required the closing bracket and
// rejected trailing content, visibility did neither until the parsers were
// reconciled. Keeping one table means a case added for either package is a
// case the other has to answer too, instead of each package's own test file
// recording only the gaps someone happened to look for there.
//
// Every body here starts with '[' or is empty, so it is meaningful on any
// route that walks an array. A non-array body like an object or a scalar is
// deliberately absent: responsefilter's libpod network-inspect route accepts
// a bare object on purpose, because Podman changed that response from a
// one-element array to a bare object at v3.1.0, so an object is a legitimate
// shape there and a refusal everywhere else. Each package covers that case in
// its own tests, where the route's expected shape is known.
func JSONArrayTerminationCases() []JSONArrayCase {
	return []JSONArrayCase{
		// (a) Unterminated: the element loop ends on Decoder.More(), which is
		// false both when the array closed and when the input ran out, so
		// without an explicit read of the closing delimiter the parser never
		// established that the array closed at all.
		{Name: "empty body", Body: ``},
		{Name: "open bracket only", Body: `[`},
		{Name: "unclosed object inside the array", Body: `[{`},
		{Name: "element decoded but array never closed", Body: `[{"Id":"a"}`},
		{Name: "truncated between elements", Body: `[{"Id":"a"},{"Id":"b"}`},
		{Name: "trailing comma inside the array", Body: `[{"Id":"a"},`},
		{Name: "unbalanced close", Body: `[{"Id":"a"}}`},

		// (b) A valid array followed by trailing non-whitespace.
		{Name: "trailing garbage after the array", Body: `[{"Id":"a"}]garbage`},
		{Name: "stray byte after the array", Body: `[{"Id":"a"}] x`},
		{Name: "trailing comma after the array", Body: `[{"Id":"a"}],`},

		// (c) A valid array followed by a second JSON document. json.Decoder
		// stops at the end of the first value, so this is the shape that gets
		// silently dropped rather than refused when nothing checks it.
		{Name: "second array after the array", Body: `[{"Id":"a"}] [{"Id":"b"}]`},
		{Name: "second object after the array", Body: `[{"Id":"a"}]{"Id":"b"}`},
		{Name: "trailing null after the array", Body: `[{"Id":"a"}]null`},
		{Name: "trailing number after the array", Body: `[{"Id":"a"}]0`},

		// Accepted: exactly one array, with whitespace after it still fine.
		// encoding/json's whitespace set is space, tab, CR and LF only, so a
		// vertical tab or a NUL byte belongs above, not here.
		{Name: "closed array", Body: `[{"Id":"a"}]`, Accept: true},
		{Name: "two elements", Body: `[{"Id":"a"},{"Id":"b"}]`, Accept: true},
		{Name: "empty array", Body: `[]`, Accept: true},
		{Name: "whitespace inside the array", Body: "[ \n\t]", Accept: true},
		{Name: "trailing whitespace after the array", Body: "[{\"Id\":\"a\"}]  \n\t\r", Accept: true},
		{Name: "leading whitespace before the array", Body: "  \n[{\"Id\":\"a\"}]", Accept: true},
	}
}
