import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const rootModule = new URL("../go.mod", import.meta.url);
const nestedModule = new URL("../app/go.mod", import.meta.url);
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

function goList(args) {
  for (let attempt = 1; ; attempt++) {
    try {
      return execFileSync("go", ["list", ...args], {
        cwd: repoRoot,
        encoding: "utf8",
        stdio: "pipe",
        timeout: 120_000,
      });
    } catch (error) {
      const stderr = String(error.stderr ?? "");
      const download = (stderr.match(/https:\/\/[^\s"']+/g) ?? []).some((address) => {
        try {
          return ["https://proxy.golang.org", "https://storage.googleapis.com"].includes(
            new URL(address).origin,
          );
        } catch {
          return false;
        }
      });
      const transient =
        /TLS handshake timeout|i\/o timeout|connection reset by peer|unexpected EOF|stream error:.*INTERNAL_ERROR|:\s*(?:408|429|500|502|503|504)\s/.test(
          stderr,
        ) ||
        (/golang\.org\/toolchain@/.test(stderr) && /403 Forbidden/.test(stderr));
      if (attempt === 3 || error.status !== 1 || !download || !transient) {
        throw error;
      }
      console.error(`Go download failed; retrying go list (${attempt + 1}/3)`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, attempt * 1_000);
    }
  }
}

const pathEntryExists = (path) => {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
};

const hasTemporaryInternalCopy = (dockerfile) =>
  /^COPY[ \t]+internal\/?[ \t]+\.\/internal\/?[ \t]*$/im.test(dockerfile);

// Gosec runs either through its action or as the image the action wraps.
const gosecArgs = (workflow) =>
  workflow.match(
    /^[ \t]+(?:- )?uses:[ \t]+(?:securego\/gosec@|docker:\/\/ghcr\.io\/securego\/gosec[:@])[^\n]+\n[ \t]+with:\n[ \t]+args:[ \t]+(.+)$/m,
  )?.[1] ?? "";

test("the repository root is the canonical Go module root", () => {
  assert.ok(existsSync(rootModule), "go.mod must live at the repository root");
  assert.ok(!existsSync(nestedModule), "app must not declare a mismatched nested module");
  assert.match(readFileSync(rootModule, "utf8"), /^module github\.com\/codeswhat\/sockguard\/v3$/m);
});

test("temporary staged compatibility packages are absent from the final tree", () => {
  assert.ok(
    !pathEntryExists(new URL("../internal", import.meta.url)),
    "the temporary root internal package tree must be removed",
  );
  assert.ok(
    !pathEntryExists(new URL("../differential", import.meta.url)),
    "the temporary root differential symlink must be removed",
  );
  assert.equal(hasTemporaryInternalCopy(read("Dockerfile")), false);

  const workflow = read(".github/workflows/ci-verify.yml");
  assert.match(workflow, /"name":"FuzzDecode","pkg":"\.\/internal\/dockerfilters\/"/);
  // The reusable Go Fuzz job cds into module-directory (app) before running
  // the caller-owned fuzzer, same as the old inline working-directory: app.
  assert.match(workflow, /^ {6}module-directory: app$/m);
});

test("temporary Docker COPY detection covers equivalent forms", () => {
  for (const instruction of [
    "COPY internal/ ./internal/",
    "COPY internal ./internal",
    "COPY  internal/   ./internal",
    "COPY\tinternal\t./internal/",
    "copy internal ./internal",
  ]) {
    assert.equal(hasTemporaryInternalCopy(instruction), true, instruction);
  }
});

test("the binary has the package path implied by its repository directory", () => {
  const packageInfo = JSON.parse(goList(["-json", "./app/cmd/sockguard"]));

  assert.equal(packageInfo.ImportPath, "github.com/codeswhat/sockguard/v3/app/cmd/sockguard");
  assert.equal(packageInfo.Module.Path, "github.com/codeswhat/sockguard/v3");
  assert.equal(packageInfo.Module.Dir, repoRoot);
});

test("tooling does not point back to the old nested module files", () => {
  const stalePaths = [["app", "go.mod"].join("/"), ["app", "go.sum"].join("/")];
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
  assert.match(dockerfile, /^ {4}-o \/sockguard \.\/app\/cmd\/sockguard\/$/m);

  // The Go Test coverage-gate filtering moved from an inline workflow step
  // into the fixed scripts/ci/go-test.sh adapter the reusable Go CI test
  // job runs; the qlty-rewrite (coverage.qlty.txt) step was dropped along
  // with the qlty coverage upload (see PR description — accepted loss).
  const goTestScript = read("scripts/ci/go-test.sh");
  assert.match(
    goTestScript,
    /grep -vE 'github\.com\/codeswhat\/sockguard\/v3\/app\/internal\/\(differential\|testcert\|testhelp\|buildkitproto\)\/'/,
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

  const packages = goList(["./app/..."]).trim().split("\n").filter(Boolean);
  assert.ok(packages.length > 0, "Gosec target must resolve at least one canonical package");

  const generated = execFileSync("git", ["ls-files", "app"], {
    cwd: repoRoot,
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .filter((path) => path.endsWith(".go"))
    .filter((path) => /^\/\/ Code generated .* DO NOT EDIT\.$/m.test(read(path)));
  assert.equal(generated.length, 14, "approved generated-file inventory changed");
  for (const path of generated) {
    assert.match(path, /^app\/internal\/buildkitproto\/.+\.pb\.go$/);
  }
  assert.ok(generated.includes("app/internal/buildkitproto/health/health.pb.go"));
});

test("Gosec argument selection ignores unrelated action arguments", () => {
  for (const uses of [
    "securego/gosec@v2",
    "docker://ghcr.io/securego/gosec:2.29.0@sha256:0000",
    "docker://ghcr.io/securego/gosec@sha256:0000",
  ]) {
    const workflow = `
      - uses: example/unrelated@v1
        with:
          args: -no-fail ./ignored/...
      - uses: docker://ghcr.io/example/unrelated:1
        with:
          args: -no-fail ./ignored/...
      - uses: ${uses}
        with:
          args: -exclude-generated ./app/...
  `;
    assert.equal(gosecArgs(workflow), "-exclude-generated ./app/...", uses);
  }
});

test("the pre-push hook compiles every integration build-tag boundary", () => {
  const hook = read("lefthook.yml");

  assert.match(hook, /go test -run='\^\$' -tags=integration \.\/integration\/\.\.\./);
  assert.match(
    hook,
    /go test -run='\^\$' -tags=podmanintegration \.\/integration\/\.\.\. \.\/internal\/cmd\/\.\.\./,
  );
});

test("every release linker targets the v3 version package", () => {
  const versionPackage = "github.com/codeswhat/sockguard/v3/app/internal/version";
  for (const path of ["Dockerfile", "app/.goreleaser.yaml"]) {
    for (const field of ["Version", "Commit", "BuildDate"]) {
      assert.ok(
        read(path).includes(`-X ${versionPackage}.${field}=`),
        `${path} must inject ${field} into v3`,
      );
    }
  }
});

test("reproduction derives its linker package from the exported source module", () => {
  const script = read("scripts/ci/go-reproducible.sh");
  assert.match(script, /module_path=.*first\/go\.mod/);
  assert.match(script, /version_package="\$\{module_path\}\/app\/internal\/version"/);
});
