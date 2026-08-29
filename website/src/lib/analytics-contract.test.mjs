import assert from "node:assert/strict";
import test from "node:test";

import { createBeforeSend } from "./analytics-contract.ts";

const ROUTES = new Set(["/"]);
const beforeSend = createBeforeSend("phc_test", ROUTES);

function pageview(extra) {
  return beforeSend({
    uuid: "0199a0e4-0000-7000-8000-000000000000",
    event: "$pageview",
    properties: {
      $raw_user_agent: "Mozilla/5.0",
      $host: "getsockguard.com",
      path: "/",
      ...extra,
    },
  });
}

test("a full referrer URL is never forwarded", () => {
  const result = pageview({
    $referrer: "https://mail.example.com/inbox/private-thread?id=42",
    $referring_domain: "mail.example.com",
  });
  assert.equal(result.properties.$referrer, undefined);
  assert.equal(result.properties.$referring_domain, "mail.example.com");
});

test("the referring domain is lowercased", () => {
  const result = pageview({ $referring_domain: "News.YCombinator.COM" });
  assert.equal(result.properties.$referring_domain, "news.ycombinator.com");
});

test("direct traffic keeps its sentinel", () => {
  const result = pageview({ $referring_domain: "$direct" });
  assert.equal(result.properties.$referring_domain, "$direct");
});

test("a referring domain carrying a path fails closed", () => {
  for (const value of [
    "example.com/private/thread",
    "https://example.com",
    "user:pw@example.com",
    "example.com:8443",
    "localhost",
    "",
    "   ",
    42,
    null,
  ]) {
    const result = pageview({ $referring_domain: value });
    assert.equal(result.properties.$referring_domain, undefined, `leaked for ${String(value)}`);
  }
});

test("an over-length referring domain is dropped", () => {
  const result = pageview({ $referring_domain: `${"a".repeat(200)}.com` });
  assert.equal(result.properties.$referring_domain, undefined);
});

test("campaign parameters are forwarded and trimmed", () => {
  const result = pageview({
    utm_source: "  hn  ",
    utm_medium: "referral",
    utm_campaign: "v2-launch",
    utm_term: "docker socket proxy",
    utm_content: "sidebar",
  });
  assert.equal(result.properties.utm_source, "hn");
  assert.equal(result.properties.utm_medium, "referral");
  assert.equal(result.properties.utm_campaign, "v2-launch");
  assert.equal(result.properties.utm_term, "docker socket proxy");
  assert.equal(result.properties.utm_content, "sidebar");
});

test("click identifiers are not forwarded", () => {
  const result = pageview({
    gclid: "abc123",
    fbclid: "def456",
    msclkid: "ghi789",
    utm_source: "google",
  });
  assert.equal(result.properties.gclid, undefined);
  assert.equal(result.properties.fbclid, undefined);
  assert.equal(result.properties.msclkid, undefined);
  assert.equal(result.properties.utm_source, "google");
});

test("an over-length campaign value is dropped", () => {
  const result = pageview({ utm_campaign: "x".repeat(201), utm_source: "hn" });
  assert.equal(result.properties.utm_campaign, undefined);
  assert.equal(result.properties.utm_source, "hn");
});

test("$pageleave carries acquisition properties too", () => {
  const result = beforeSend({
    uuid: "0199a0e4-0000-7000-8000-000000000001",
    event: "$pageleave",
    properties: {
      $raw_user_agent: "Mozilla/5.0",
      $host: "getsockguard.com",
      path: "/",
      $referring_domain: "example.com",
      utm_source: "hn",
    },
  });
  assert.equal(result.properties.$referring_domain, "example.com");
  assert.equal(result.properties.utm_source, "hn");
});

test("non-pageview events carry no acquisition properties", () => {
  const result = beforeSend({
    uuid: "0199a0e4-0000-7000-8000-000000000002",
    event: "cta activated",
    properties: {
      $raw_user_agent: "Mozilla/5.0",
      $host: "getsockguard.com",
      path: "/",
      cta_id: "docs_root",
      placement: "header",
      $referring_domain: "example.com",
      utm_source: "hn",
    },
  });
  assert.notEqual(result, null);
  assert.equal(result.properties.$referring_domain, undefined);
  assert.equal(result.properties.utm_source, undefined);
});
