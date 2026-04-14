import nextra from "nextra";

const withNextra = nextra({});

// The docs app is mounted at /docs inside the marketing site via a
// Vercel rewrite (see website/vercel.json). basePath tells Next to
// prefix every internal link and asset URL with /docs so navigation
// and static imports keep working after the rewrite lands them on
// getsockguard.com/docs/... instead of the standalone
// sockguard-docs.vercel.app root. Nextra honors Next's basePath so
// sidebar links, breadcrumbs, and the table of contents all emit
// the correct absolute URLs without further config.
export default withNextra({
  output: "export",
  basePath: "/docs",
});
