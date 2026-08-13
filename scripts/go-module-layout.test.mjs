import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const rootModule = new URL("../go.mod", import.meta.url);
const nestedModule = new URL("../app/go.mod", import.meta.url);
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

const gosecArgs = (workflow) =>
  workflow.match(
    /^[ \t]+(?:- )?uses:[ \t]+securego\/gosec@[^\n]+\n[ \t]+with:\n[ \t]+args:[ \t]+(.+)$/m,
  )?.[1] ?? "";

test("the repository root is the canonical Go module root", () => {
  assert.ok(existsSync(rootModule), "go.mod must live at the repository root");
  assert.ok(!existsSync(nestedModule), "app must not declare a mismatched nested module");
  assert.match(
    readFileSync(rootModule, "utf8"),
    /^module github\.com\/codeswhat\/sockguard$/m,
  );
});

test("the binary has the package path implied by its repository directory", () => {
  const packageInfo = JSON.parse(
    execFileSync("go", ["list", "-json", "./app/cmd/sockguard"], {
      cwd: repoRoot,
      encoding: "utf8",
    }),
  );

  assert.equal(packageInfo.ImportPath, "github.com/codeswhat/sockguard/app/cmd/sockguard");
  assert.equal(packageInfo.Module.Path, "github.com/codeswhat/sockguard");
  assert.equal(packageInfo.Module.Dir, repoRoot);
});

test("tooling does not point back to the old nested module files", () => {
  const stalePaths = [
    ["app", "go.mod"].join("/"),
    ["app", "go.sum"].join("/"),
  ];
  const grep = spawnSync(
    "git",
    [
      "grep",
      "-n",
      "--fixed-strings",
      "-e",
      stalePaths[0],
      "-e",
      stalePaths[1],
      "--",
      ":!CHANGELOG.md",
      ":!scripts/go-module-layout.test.mjs",
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );

  assert.equal(grep.status, 1, grep.stdout || grep.stderr);
});

test("container and coverage tooling preserve app as the package subdirectory", () => {
  const dockerfile = read("Dockerfile");
  assert.match(dockerfile, /^COPY go\.mod go\.sum \.\/$/m);
  assert.match(dockerfile, /^COPY app\/ \.\/app\/$/m);
  assert.match(dockerfile, /^    -o \/sockguard \.\/app\/cmd\/sockguard\/$/m);

  const workflow = read(".github/workflows/ci-verify.yml");
  assert.match(
    workflow,
    /grep -vE 'github\.com\/codeswhat\/sockguard\/app\/\(differential\|internal\/testcert\|internal\/testhelp\|internal\/buildkitproto\)\/'/,
  );
  assert.match(
    workflow,
    /sed 's#github\.com\/codeswhat\/sockguard\/#\#g' coverage\.prod\.txt > coverage\.qlty\.txt/,
  );
});

test("Gosec scans canonical app packages with audited suppressions", () => {
  const workflow = read(".github/workflows/security-grype.yml");
  const args = gosecArgs(workflow);

  assert.match(args, /(?:^|\s)-exclude-generated(?:\s|$)/);
  assert.match(args, /(?:^|\s)-nosec-require-rules(?:\s|$)/);
  assert.match(args, /(?:^|\s)-nosec-require-justification(?:\s|$)/);
  assert.match(args, /(?:^|\s)\.\/app\/\.\.\.(?:\s|$)/);
  assert.doesNotMatch(args, /(?:^|\s)-(?:no-fail|exclude|exclude-dir|exclude-rules)(?:=|\s|$)/);

  const packages = execFileSync("go", ["list", "./app/..."], {
    cwd: repoRoot,
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .filter(Boolean);
  assert.ok(packages.length > 0, "Gosec target must resolve at least one canonical package");

  const generated = execFileSync("git", ["ls-files", "app"], {
    cwd: repoRoot,
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .filter((path) => path.endsWith(".go"))
    .filter((path) => /^\/\/ Code generated .* DO NOT EDIT\.$/m.test(read(path)));
  assert.equal(generated.length, 11, "approved generated-file inventory changed");
  for (const path of generated) {
    assert.match(path, /^app\/internal\/buildkitproto\/.+\.pb\.go$/);
  }
  assert.ok(generated.includes("app/internal/buildkitproto/health/health.pb.go"));
});

test("Gosec argument selection ignores unrelated action arguments", () => {
  const workflow = `
      - uses: example/unrelated@v1
        with:
          args: -no-fail ./ignored/...
      - uses: securego/gosec@v2
        with:
          args: -exclude-generated ./app/...
  `;
  assert.equal(gosecArgs(workflow), "-exclude-generated ./app/...");
});

test("the pre-push hook compiles every integration build-tag boundary", () => {
  const hook = read("lefthook.yml");

  assert.match(
    hook,
    /go test -run='\^\$' -tags=integration \.\/integration\/\.\.\./,
  );
  assert.match(
    hook,
    /go test -run='\^\$' -tags=podmanintegration \.\/integration\/\.\.\. \.\/internal\/cmd\/\.\.\./,
  );
});
