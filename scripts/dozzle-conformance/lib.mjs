// Pure parsing helpers for scripts/dozzle-conformance/run.sh. No I/O here so
// node --test can cover them without Docker.
//
// Upstream facts, from amir20/dozzle v11.5.0 (latest release at time of
// writing, `gh release view --repo amir20/dozzle`):
//   - internal/web/routes.go: GET /api/events/stream is the SSE feed the UI
//     reads; POST /api/containers/logs takes a form body of
//     container=<host>/<id> plus stdout/stderr and returns plain text.
//   - internal/web/events.go: the feed emits `event: containers-changed` with
//     a JSON array of containers.
//   - internal/container/types.go: each container carries `id`, `name`,
//     `host`, `state`.

// parseSse splits a Server-Sent Events body into {event, data} records. Data
// lines of one event are joined with "\n"; unparseable JSON is kept as a
// string so a caller can still see it.
export function parseSse(text) {
  const events = [];
  let event = "message";
  let data = [];
  const flush = () => {
    if (data.length === 0) {
      event = "message";
      return;
    }
    const raw = data.join("\n");
    let parsed = raw;
    try {
      parsed = JSON.parse(raw);
    } catch {
      // keep the raw string
    }
    events.push({ event, data: parsed });
    event = "message";
    data = [];
  };
  for (const line of String(text).split(/\r?\n/)) {
    if (line === "") {
      flush();
    } else if (line.startsWith(":")) {
      // comment / keepalive
    } else if (line.startsWith("event:")) {
      event = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      data.push(line.slice(5).replace(/^ /, ""));
    }
  }
  flush();
  return events;
}

// findContainer returns {host, id, name, state} for the container whose name
// matches (leading "/" ignored) in any containers-changed event, or null.
export function findContainer(events, name) {
  const want = name.replace(/^\//, "");
  for (const ev of events) {
    if (ev.event !== "containers-changed" || !Array.isArray(ev.data)) continue;
    for (const c of ev.data) {
      if (c && typeof c.name === "string" && c.name.replace(/^\//, "") === want) {
        return { host: c.host, id: c.id, name: want, state: c.state };
      }
    }
  }
  return null;
}

const ACCESS_MSGS = new Set(["request", "request_denied", "request_would_deny"]);

// parseAccessLog keeps only sockguard's JSON access records and skips every
// other line (startup logs, compose noise, bare JSON scalars).
export function parseAccessLog(text) {
  const records = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.startsWith("{")) continue;
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      continue;
    }
    if (rec === null || typeof rec !== "object") continue;
    if (!ACCESS_MSGS.has(rec.msg)) continue;
    if (typeof rec.method !== "string" || typeof rec.normalized_path !== "string") continue;
    records.push({
      msg: rec.msg,
      method: rec.method,
      path: rec.normalized_path,
      decision: rec.decision ?? "allow",
      status: rec.status ?? null,
    });
  }
  return records;
}

// Fixed Docker API keywords kept literally when shaping a path. Everything
// else is an ID or name and becomes "*", with runs collapsing to "**".
const STATIC_SEGMENTS = new Set([
  "_ping",
  "version",
  "info",
  "events",
  "containers",
  "json",
  "logs",
  "stats",
  "top",
  "changes",
  "start",
  "stop",
  "restart",
  "kill",
  "rename",
  "update",
  "wait",
  "create",
  "images",
  "history",
  "networks",
  "volumes",
  "distribution",
  "services",
  "exec",
  "resize",
  "build",
  "export",
  "archive",
  "attach",
  "system",
  "df",
]);

export function shapePath(path) {
  const out = [];
  for (const seg of path.split("/").filter((s) => s.length > 0)) {
    const s = STATIC_SEGMENTS.has(seg) ? seg : "*";
    if (s === "*" && out.length > 0 && (out.at(-1) === "*" || out.at(-1) === "**")) {
      out[out.length - 1] = "**";
    } else {
      out.push(s);
    }
  }
  return `/${out.join("/")}`;
}

// observedRoutes returns the sorted, de-duplicated {method, path} shapes.
export function observedRoutes(records) {
  const seen = new Map();
  for (const r of records) {
    const route = { method: r.method, path: shapePath(r.path) };
    seen.set(`${route.method} ${route.path}`, route);
  }
  return [...seen.values()].sort((a, b) =>
    `${a.path} ${a.method}`.localeCompare(`${b.path} ${b.method}`),
  );
}

// routeDrift compares observed routes with the reviewed manifest. It fails
// closed on zero observed routes: that means log capture broke, not that
// nothing happened.
export function routeDrift(observed, known) {
  if (observed.length === 0) {
    return {
      status: "FAIL",
      detail: "no access-log records captured, log capture or shape broke",
      unknown: [],
    };
  }
  const knownSet = new Set(known.map((r) => `${r.method} ${r.path}`));
  const unknown = observed.filter((r) => !knownSet.has(`${r.method} ${r.path}`));
  if (unknown.length === 0) {
    return {
      status: "PASS",
      detail: `all ${observed.length} observed route shapes are in known-routes.json`,
      unknown,
    };
  }
  return {
    status: "FAIL",
    detail: `dozzle sent a route the preset has not reviewed, review policy then update known-routes.json: ${JSON.stringify(unknown)}`,
    unknown,
  };
}

// deniedRecords returns every access record the proxy denied (or would deny),
// minus the (method, path shape) pairs listed as expected denials. Dozzle's
// GET /system/df is the one known case: the preset denies it on purpose and
// Dozzle carries on without it.
export function deniedRecords(records, expected = []) {
  const expectedSet = new Set(expected.map((r) => `${r.method} ${r.path}`));
  return records.filter(
    (r) =>
      (r.msg !== "request" || r.decision === "deny" || r.decision === "would_deny") &&
      !expectedSet.has(`${r.method} ${shapePath(r.path)}`),
  );
}
