// Static server for the e2e suite. Serves the `next build` export from out/
// the way Vercel does and applies the header rules from vercel.json, so the
// browsers run under the real Content-Security-Policy.
//
// Routing mirrors Vercel's static handling: exact file, then `<path>.html`,
// then `<path>/index.html`, and anything else gets 404.html with a 404 status.

import { readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = resolve(here, "../out");
const vercel = JSON.parse(readFileSync(resolve(here, "../vercel.json"), "utf8"));

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".webmanifest": "application/manifest+json",
};

// Vercel source patterns used in vercel.json: a literal path or "/(.*)".
const rules = vercel.headers.map((rule) => ({
  test: rule.source === "/(.*)" ? () => true : (path) => path === rule.source,
  headers: rule.headers,
}));

// The suite runs over plain http. WebKit upgrades even loopback subresources
// under `upgrade-insecure-requests` and then fails the TLS handshake, so that
// one directive is dropped here. Every other directive is served unchanged,
// and site.spec.ts asserts vercel.json still ships the directive.
function plainHttp(key, value) {
  if (key.toLowerCase() !== "content-security-policy") return value;
  return value
    .split(";")
    .map((directive) => directive.trim())
    .filter((directive) => directive !== "upgrade-insecure-requests")
    .join("; ");
}

function fileFor(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return undefined;
  }
  const clean = normalize(decoded).replace(/\/+$/, "");
  const candidates = [clean, `${clean}.html`, join(clean, "index.html")];
  for (const rel of candidates) {
    const abs = join(root, rel);
    if (abs !== root && !abs.startsWith(root + sep)) continue;
    try {
      if (statSync(abs).isFile()) return abs;
    } catch {}
  }
  return null;
}

const server = createServer((req, res) => {
  const { pathname } = new URL(req.url ?? "/", "http://localhost");
  let status = 200;
  let file = pathname === "/" ? join(root, "index.html") : fileFor(pathname);
  if (file === undefined) {
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Bad Request");
    return;
  }
  if (!file) {
    status = 404;
    file = join(root, "404.html");
  }

  const headers = { "Content-Type": TYPES[extname(file)] ?? "application/octet-stream" };
  for (const rule of rules) {
    if (!rule.test(pathname)) continue;
    for (const { key, value } of rule.headers) headers[key] = plainHttp(key, value);
  }

  res.writeHead(status, headers);
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  res.end(readFileSync(file));
});

const port = Number(process.env.E2E_PORT ?? 4317);
server.listen(port, "127.0.0.1", () => {
  console.log(`e2e server on http://127.0.0.1:${port} serving ${root}`);
});
