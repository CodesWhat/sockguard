package visibility

import "context"

// requestVisible is the original label-selector-only entry point, retained as a
// test-only helper so existing tests can exercise requestVisibleWithPolicy
// through a selector-only path without constructing a compiledPolicy. Production
// code calls requestVisibleWithPolicy directly.
func requestVisible(ctx context.Context, normPath string, selectors []compiledSelector, deps visibilityDeps) (bool, error) {
	return requestVisibleWithPolicy(ctx, normPath, &compiledPolicy{selectors: selectors}, deps)
}
