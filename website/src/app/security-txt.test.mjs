import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { BASE_URL, SITE_CONFIG } from "../lib/site-config.ts";

const SECURITY_TXT = fileURLToPath(
  new URL("../../public/.well-known/security.txt", import.meta.url),
);
const VERCEL_JSON = fileURLToPath(new URL("../../vercel.json", import.meta.url));
const MIN_DAYS_LEFT = 30;

function fields() {
  const map = new Map();
  for (const line of readFileSync(SECURITY_TXT, "utf8").split("\n")) {
    const match = line.match(/^([A-Za-z-]+):\s*(.+)$/u);
    if (match) map.set(match[1], [...(map.get(match[1]) ?? []), match[2].trim()]);
  }
  return map;
}

test("security.txt carries the RFC 9116 required fields", () => {
  const f = fields();
  assert.equal(f.get("Contact")?.length >= 1, true);
  assert.equal(f.get("Expires")?.length, 1);
  assert.deepEqual(f.get("Preferred-Languages"), ["en"]);
});

test("security.txt Expires is a valid date at least 30 days away (renew it before it lapses)", () => {
  const expires = new Date(fields().get("Expires")[0]);
  assert.ok(!Number.isNaN(expires.getTime()), "Expires must be an ISO 8601 date");
  const daysLeft = (expires.getTime() - Date.now()) / 86_400_000;
  assert.ok(
    daysLeft >= MIN_DAYS_LEFT,
    `security.txt Expires ${fields().get("Expires")[0]} is ${Math.floor(daysLeft)} days away; push it out about 6 months`,
  );
});

test("security.txt Canonical points at the canonical host", () => {
  assert.deepEqual(fields().get("Canonical"), [`${BASE_URL}/.well-known/security.txt`]);
  assert.ok(BASE_URL.includes(SITE_CONFIG.domain));
});

test("vercel.json serves security.txt as text/plain", () => {
  const rule = JSON.parse(readFileSync(VERCEL_JSON, "utf8")).headers.find(
    (entry) => entry.source === "/.well-known/security.txt",
  );
  assert.ok(rule, "missing security.txt header rule");
  const type = rule.headers.find((h) => h.key === "Content-Type");
  assert.match(type.value, /^text\/plain/u);
});
