// Package compat decodes Sockguard's redacted Docker responses into the real
// Docker client types, so a sentinel written into a non-string wire type
// (netip.Addr, []byte, ...) fails the build instead of a user's Traefik or
// Portainer.
//
// It is a separate module on purpose. moby/moby/api and docker/docker are test
// dependencies here and must never reach the proxy binary's module graph (the
// hot-path dependency constraint in CLAUDE.md). The module path sits under
// app/ so the replace directive to the main module can import internal
// packages.
package compat
