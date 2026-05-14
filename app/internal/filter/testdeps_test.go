package filter

// testdeps_test.go used to swap package-level IO function vars. The struct
// refactor (see io_deps.go) removed those globals, so tests now construct
// their own ioDeps and inject it directly into the policy or method receiver.
// This file is intentionally empty; it remains as a marker that no shared IO
// dependency state exists in the package.
