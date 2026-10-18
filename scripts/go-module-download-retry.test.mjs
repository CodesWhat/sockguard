import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const modulePath = readFileSync(join(repoRoot, "go.mod"), "utf8").match(/^module (.+)$/m)[1];
const toolchainFailure =
  "go: download go1.27.2: golang.org/toolchain@v0.0.1-go1.27.2.linux-amd64: reading https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go1.27.2.linux-amd64.zip: 403 Forbidden";
const moduleFailure =
  'go: github.com/klauspost/compress@v1.19.2: Get "https://proxy.golang.org/github.com/klauspost/compress/@v/v1.19.2.zip": net/http: TLS handshake timeout';

function runLayoutTest(t, name, failures) {
  const fixture = mkdtempSync(join(tmpdir(), "sockguard-go-download-"));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const calls = join(fixture, "calls.json");
  const plan = join(fixture, "plan.json");
  writeFileSync(calls, "[]");
  writeFileSync(plan, JSON.stringify(failures));
  writeFileSync(
    join(fixture, "go"),
    `#!/usr/bin/env node
const fs = require("node:fs");
const calls = JSON.parse(fs.readFileSync(process.env.GO_TEST_CALLS, "utf8"));
const failures = JSON.parse(fs.readFileSync(process.env.GO_TEST_PLAN, "utf8"));
const attempt = calls.length;
calls.push(process.argv.slice(2));
fs.writeFileSync(process.env.GO_TEST_CALLS, JSON.stringify(calls));
if (attempt < failures.length) {
  process.stderr.write(failures[attempt] + "\\n");
  process.exit(1);
}
if (process.argv.includes("-json")) {
  process.stdout.write(JSON.stringify({
    ImportPath: process.env.GO_TEST_MODULE + "/app/cmd/sockguard",
    Module: { Path: process.env.GO_TEST_MODULE, Dir: process.env.GO_TEST_ROOT },
  }));
} else {
  process.stdout.write(process.env.GO_TEST_MODULE + "/app/cmd/sockguard\\n");
}
`,
    { mode: 0o755 },
  );
  const env = {
    ...process.env,
    PATH: `${fixture}:${process.env.PATH}`,
    GO_TEST_CALLS: calls,
    GO_TEST_PLAN: plan,
    GO_TEST_MODULE: modulePath,
    GO_TEST_ROOT: repoRoot,
  };
  delete env.NODE_TEST_CONTEXT;

  const result = spawnSync(
    process.execPath,
    ["--test", `--test-name-pattern=${name}`, "scripts/go-module-layout.test.mjs"],
    {
      cwd: repoRoot,
      encoding: "utf8",
      timeout: 20_000,
      env,
    },
  );
  return { ...result, calls: JSON.parse(readFileSync(calls, "utf8")) };
}

for (const [name, args] of [
  [
    "the binary has the package path implied by its repository directory",
    ["list", "-json", "./app/cmd/sockguard"],
  ],
  ["Gosec scans canonical app packages with audited suppressions", ["list", "./app/..."]],
]) {
  test(`${name}: toolchain download failure recovers without skipping assertions`, (t) => {
    const result = runLayoutTest(t, name, [toolchainFailure, toolchainFailure]);

    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.deepEqual(result.calls, [args, args, args]);
    assert.match(result.stdout, /pass 1/);
  });
}

test("a transient module download failure recovers", (t) => {
  const result = runLayoutTest(t, "the binary has the package path", [moduleFailure]);

  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(result.calls.length, 2);
});

for (const failure of [
  "stream error: stream ID 1; INTERNAL_ERROR; received from peer",
  "unexpected EOF",
  "connection reset by peer",
  "i/o timeout",
  ...[408, 429, 500, 502, 503, 504].map((status) => `${status} response from proxy`),
]) {
  test(`a public module download recovers from ${failure}`, (t) => {
    const result = runLayoutTest(t, "the binary has the package path", [
      `go: example.com/module@v1.0.0: reading https://proxy.golang.org/example.com/module/@v/v1.0.0.zip: ${failure}`,
    ]);

    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.calls.length, 2);
  });
}

test("persistent download failures remain fatal after three attempts", (t) => {
  const result = runLayoutTest(t, "the binary has the package path", Array(5).fill(moduleFailure));

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.calls.length, 3);
  assert.match(result.stdout + result.stderr, /TLS handshake timeout/);
});

test("a package error is fatal on the first attempt", (t) => {
  const result = runLayoutTest(t, "the binary has the package path", [
    "app/cmd/sockguard/main.go:8:2: undefined: missingPackage",
  ]);

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.calls.length, 1);
  assert.match(result.stdout + result.stderr, /undefined: missingPackage/);
});

test("a private module authorization failure is not retried", (t) => {
  const result = runLayoutTest(t, "the binary has the package path", [
    "go: example.com/private@v1.0.0: reading https://example.com/private?go-get=1: 403 Forbidden",
  ]);

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.calls.length, 1);
});

test("a missing module version is not retried", (t) => {
  const result = runLayoutTest(t, "the binary has the package path", [
    "go: example.com/module@v9.9.9: reading https://proxy.golang.org/example.com/module/@v/v9.9.9.zip: 404 Not Found",
  ]);

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.calls.length, 1);
});

test("HTTP-like numbers in a module path do not make a permanent failure retryable", (t) => {
  const result = runLayoutTest(t, "the binary has the package path", [
    "go: example.com/503/module@v1.0.0: reading https://proxy.golang.org/example.com/503/module/@v/v1.0.0.zip: 404 Not Found",
  ]);

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.calls.length, 1);
});

test("a public proxy module authorization failure is not retried", (t) => {
  const result = runLayoutTest(t, "the binary has the package path", [
    "go: example.com/private@v1.0.0: reading https://proxy.golang.org/example.com/private/@v/v1.0.0.zip: 403 Forbidden",
  ]);

  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.calls.length, 1);
});

for (const address of [
  "https://private.example/cache/https://proxy.golang.org/module.zip",
  "https://proxy.golang.org.private.example/module.zip",
  "https://proxy.golang.org@private.example/module.zip",
  "https://proxy.golang.org:8443/module.zip",
]) {
  test(`a transient failure from ${address} is not retried`, (t) => {
    const result = runLayoutTest(t, "the binary has the package path", [
      `go: example.com/private@v1.0.0: Get "${address}": net/http: TLS handshake timeout`,
    ]);

    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.equal(result.calls.length, 1);
  });
}
