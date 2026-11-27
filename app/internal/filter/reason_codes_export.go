package filter

// ReasonCodeMatchedDenyRule and ReasonCodeNoMatchingAllowRule are the
// reason_code values the rule layer writes to the access log. They are
// exported for tooling that reads the log (sockguard policy suggest), which
// must tell a rule-layer miss, one an allow rule can fix, from every other
// guard's deny.
const (
	ReasonCodeMatchedDenyRule     = reasonCodeMatchedDenyRule
	ReasonCodeNoMatchingAllowRule = reasonCodeNoMatchingAllowRule
)
