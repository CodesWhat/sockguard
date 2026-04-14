import { createMDX } from "fumadocs-mdx/next";

const withMDX = createMDX();

// The docs app is a separate Next.js workspace mounted at /docs inside
// the marketing site. `output: "export"` produces the static HTML that
// the website's `build:docs-content` script copies into
// `website/public/docs/`. `basePath: "/docs"` tells Next to prefix every
// internal link and asset URL accordingly so navigation keeps working
// after the website serves the static export at getsockguard.com/docs/...
export default withMDX({
  output: "export",
  basePath: "/docs",
  images: {
    unoptimized: true,
  },
});
