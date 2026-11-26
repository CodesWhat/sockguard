import assert from "node:assert/strict";
import test from "node:test";
import {
  deniedRecords,
  findContainer,
  observedRoutes,
  parseAccessLog,
  parseSse,
  routeDrift,
  shapePath,
} from "./dozzle-conformance/lib.mjs";

const sse = [
  "event: server-version",
  'data: {"version":"v11.5.0"}',
  "",
  ": keepalive",
  "event: containers-changed",
  'data: [{"id":"abc123","name":"/sg-marker","host":"hostid","state":"running"},{"id":"def","name":"other","host":"hostid","state":"running"}]',
  "",
  "event: ping",
  "data: {}",
  "",
].join("\n");

test("parseSse splits events and parses JSON data", () => {
  const events = parseSse(sse);
  assert.deepEqual(
    events.map((e) => e.event),
    ["server-version", "containers-changed", "ping"],
  );
  assert.equal(events[0].data.version, "v11.5.0");
});

test("parseSse keeps unparseable data as a string and handles CRLF", () => {
  const events = parseSse("event: x\r\ndata: not json\r\n\r\n");
  assert.deepEqual(events, [{ event: "x", data: "not json" }]);
});

test("findContainer matches with or without the leading slash", () => {
  const events = parseSse(sse);
  assert.deepEqual(findContainer(events, "sg-marker"), {
    host: "hostid",
    id: "abc123",
    name: "sg-marker",
    state: "running",
  });
  assert.equal(findContainer(events, "missing"), null);
  assert.equal(findContainer([{ event: "containers-changed", data: "oops" }], "sg-marker"), null);
});

const log = [
  '{"msg":"request","method":"GET","normalized_path":"/containers/json","decision":"allow","status":200}',
  '{"msg":"request","method":"GET","normalized_path":"/containers/abc123/logs","status":200}',
  '{"msg":"request_denied","method":"POST","normalized_path":"/containers/create","decision":"deny","status":403}',
  '{"msg":"startup","method":"GET","normalized_path":"/x"}',
  '"bare string"',
  "not json",
  '{"msg":"request","method":"GET"}',
].join("\n");

test("parseAccessLog keeps only complete access records", () => {
  const records = parseAccessLog(log);
  assert.equal(records.length, 3);
  assert.equal(records[1].decision, "allow");
});

test("shapePath classifies IDs and collapses runs", () => {
  assert.equal(shapePath("/containers/abc123/logs"), "/containers/*/logs");
  assert.equal(shapePath("/containers/json"), "/containers/json");
  assert.equal(shapePath("/images/ghcr.io/o/r/json"), "/images/**/json");
});

test("observedRoutes de-duplicates and sorts", () => {
  const routes = observedRoutes(parseAccessLog(`${log}\n${log}`));
  assert.equal(routes.length, 3);
});

test("deniedRecords finds denials only", () => {
  const denied = deniedRecords(parseAccessLog(log));
  assert.deepEqual(
    denied.map((r) => r.path),
    ["/containers/create"],
  );
});

test("deniedRecords skips expected denials by path shape", () => {
  const records = parseAccessLog(
    '{"msg":"request_denied","method":"GET","normalized_path":"/system/df","decision":"deny","status":403}',
  );
  assert.equal(deniedRecords(records).length, 1);
  assert.equal(deniedRecords(records, [{ method: "GET", path: "/system/df" }]).length, 0);
});

test("routeDrift passes on known routes, fails on unknown and on empty", () => {
  const known = [
    { method: "GET", path: "/containers/json" },
    { method: "GET", path: "/containers/*/logs" },
  ];
  const ok = routeDrift(known, known);
  assert.equal(ok.status, "PASS");
  const drift = routeDrift(observedRoutes(parseAccessLog(log)), known);
  assert.equal(drift.status, "FAIL");
  assert.deepEqual(drift.unknown, [{ method: "POST", path: "/containers/create" }]);
  assert.equal(routeDrift([], known).status, "FAIL");
});
