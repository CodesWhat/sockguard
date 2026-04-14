import nextra from "nextra";

const withNextra = nextra({});

// Nextra on Next 16 uses static export so Vercel serves a purely
// static bundle. `turbopack.root` used to be pinned to the monorepo
// parent to silence a lockfile-detection warning during local dev,
// but on Vercel the build root is the `docs/` workspace itself and
// pinning to `../` points at /vercel/, which doesn't match
// `outputFileTracingRoot`. Letting Next auto-detect keeps both
// environments happy.
export default withNextra({
  output: "export",
});
