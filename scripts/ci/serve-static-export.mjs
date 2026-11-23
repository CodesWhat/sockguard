#!/usr/bin/env node
// Serve a Next.js static export (website/out) on localhost with the response
// headers from website/vercel.json applied, so a DAST scan of the local export
// sees the same CSP, Permissions-Policy and friends the CDN would send.
//
// Usage: node scripts/ci/serve-static-export.mjs [--dir website/out]
//        [--config website/vercel.json] [--port 8080] [--host 127.0.0.1]
//
// Stdlib only. Routing follows Next's static export layout: /path resolves to
// path, path.html or path/index.html, and a miss serves 404.html with a 404.
import { createReadStream, existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".map": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json",
};

/**
 * Compile a vercel.json `source` pattern (path-to-regexp subset) to a RegExp.
 * Supports literals, raw `(regex)` groups, `:name` segments and a trailing
 * `*`/`+`/`?` modifier on a named segment.
 */
export function compileSource(source) {
  let out = "";
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (ch === "(") {
      let depth = 0;
      let j = i;
      for (; j < source.length; j++) {
        if (source[j] === "\\") {
          j++;
        } else if (source[j] === "(") {
          depth++;
        } else if (source[j] === ")" && --depth === 0) {
          break;
        }
      }
      if (depth !== 0) {
        throw new Error(`unbalanced group in header source: ${source}`);
      }
      out += source.slice(i, j + 1);
      i = j + 1;
    } else if (ch === ":") {
      const name = /^:[A-Za-z_][A-Za-z0-9_]*/.exec(source.slice(i));
      if (!name) {
        throw new Error(`bad parameter in header source: ${source}`);
      }
      i += name[0].length;
      const mod = source[i];
      if (mod === "*") {
        out += "(?:.*)";
        i++;
      } else if (mod === "+") {
        out += "(?:.+)";
        i++;
      } else if (mod === "?") {
        out += "(?:[^/]+)?";
        i++;
      } else {
        out += "[^/]+";
      }
    } else {
      out += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      i++;
    }
  }
  return new RegExp(`^${out}$`);
}

/** Turn vercel.json `headers` into [{ pattern, headers: [[key, value]] }]. */
export function loadHeaderRules(vercelConfig) {
  return (vercelConfig.headers ?? []).map(({ source, headers }) => ({
    pattern: compileSource(source),
    headers: headers.map(({ key, value }) => [key, value]),
  }));
}

/**
 * Headers for a request path. Rules apply in file order and a later rule
 * overrides an earlier one for the same header name (case-insensitive).
 */
export function headersForPath(rules, pathname) {
  const merged = new Map();
  for (const rule of rules) {
    if (!rule.pattern.test(pathname)) {
      continue;
    }
    for (const [key, value] of rule.headers) {
      merged.set(key.toLowerCase(), [key, value]);
    }
  }
  return [...merged.values()];
}

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * Resolve a request pathname to { file, status }. Returns null file when
 * nothing matches and there is no 404.html. Encoded traversal (%2e%2e, %2f)
 * and NUL bytes never reach the filesystem: they get the 404 page.
 */
export function resolveRoute(rootDir, rawPathname) {
  const root = resolve(rootDir);
  const notFound = () => {
    const page = join(root, "404.html");
    return { file: isFile(page) ? page : null, status: 404 };
  };

  let pathname;
  try {
    pathname = decodeURIComponent(rawPathname);
  } catch {
    return notFound();
  }
  if (pathname.includes("\0") || pathname.includes("\\")) {
    return notFound();
  }
  if (pathname.split("/").some((segment) => segment === "..")) {
    return notFound();
  }

  const base = resolve(root, `.${pathname}`);
  if (base !== root && !base.startsWith(root + sep)) {
    return notFound();
  }

  const candidates = pathname.endsWith("/")
    ? [join(base, "index.html")]
    : [base, `${base}.html`, join(base, "index.html")];
  for (const candidate of candidates) {
    if (isFile(candidate)) {
      return { file: candidate, status: 200 };
    }
  }
  return notFound();
}

export function createHandler({ rootDir, rules }) {
  return (req, res) => {
    const applyHeaders = (pathname) => {
      for (const [key, value] of headersForPath(rules, pathname)) {
        res.setHeader(key, value);
      }
    };

    let pathname;
    try {
      pathname = new URL(req.url ?? "/", "http://localhost").pathname;
    } catch {
      applyHeaders("/");
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" }).end("bad request");
      return;
    }
    applyHeaders(pathname);

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" });
      res.end("method not allowed");
      return;
    }

    const { file, status } = resolveRoute(rootDir, pathname);
    if (!file) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("not found");
      return;
    }

    // A route-specific rule (e.g. security.txt) may already have set the
    // Content-Type; otherwise derive it from the extension.
    if (!res.hasHeader("content-type")) {
      res.setHeader(
        "Content-Type",
        CONTENT_TYPES[extname(file).toLowerCase()] ?? "application/octet-stream",
      );
    }
    res.setHeader("Content-Length", statSync(file).size);
    res.writeHead(status);
    if (req.method === "HEAD") {
      res.end();
      return;
    }
    createReadStream(file)
      .on("error", () => res.destroy())
      .pipe(res);
  };
}

function parseArgs(argv) {
  const opts = {
    dir: "website/out",
    config: "website/vercel.json",
    port: 8080,
    host: "127.0.0.1",
  };
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (value === undefined || !["--dir", "--config", "--port", "--host"].includes(flag)) {
      throw new Error(`usage: serve-static-export.mjs [--dir D] [--config F] [--port N] [--host H]`);
    }
    opts[flag.slice(2)] = flag === "--port" ? Number(value) : value;
  }
  if (!Number.isInteger(opts.port) || opts.port < 0 || opts.port > 65535) {
    throw new Error(`invalid --port: ${opts.port}`);
  }
  return opts;
}

function main() {
  const { dir, config, port, host } = parseArgs(process.argv.slice(2));
  if (!existsSync(dir)) {
    throw new Error(`export directory not found: ${dir} (run the site build first)`);
  }
  const rules = loadHeaderRules(JSON.parse(readFileSync(config, "utf8")));
  const server = createServer(createHandler({ rootDir: dir, rules }));
  server.listen(port, host, () => {
    const { address, port: bound } = server.address();
    console.log(`serving ${resolve(dir)} on http://${address}:${bound}/`);
  });
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => server.close(() => process.exit(0)));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
