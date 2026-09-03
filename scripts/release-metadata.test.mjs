import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import { SITE_CONFIG } from "../website/src/lib/site-config.ts";
import { roadmap } from "../website/src/lib/site-content.ts";

const stableVersion = SITE_CONFIG.version;
const stableTag = `v${stableVersion}`;
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("release-facing metadata agrees on the current stable version", () => {
  assert.match(stableVersion, /^\d+\.\d+\.\d+$/, "website version must be a stable semver");

  const chart = read("chart/sockguard/Chart.yaml");
  assert.match(chart, new RegExp(`^version: ${stableVersion.replaceAll(".", "\\.")}$`, "m"));
  assert.match(chart, new RegExp(`^appVersion: "${stableVersion.replaceAll(".", "\\.")}"$`, "m"));

  const readme = read("README.md");
  assert.match(
    readme,
    new RegExp(`\\*\\*${stableTag.replaceAll(".", "\\.")} is the latest stable release\\.\\*\\*`),
  );

  const changelog = read("CHANGELOG.md");
  assert.match(
    changelog,
    new RegExp(`^## \\[${stableVersion.replaceAll(".", "\\.")}\\] - \\d{4}-\\d{2}-\\d{2}$`, "m"),
  );

  const docsRoadmap = read("docs/content/docs/roadmap.mdx").replaceAll(/\s+/gu, " ");
  const stableFeatureLine = stableVersion.split(".").slice(0, 2).join(".");
  assert.match(
    docsRoadmap,
    new RegExp(
      `\\bSockguard v${stableFeatureLine.replaceAll(".", "\\.")} is the current stable feature line, with v${stableVersion.replaceAll(".", "\\.")}\\b,? the latest release\\b`,
    ),
    "docs roadmap must bind the website version to its current stable feature line",
  );
});

test("the current stable version is the roadmap HEAD", () => {
  const milestone = roadmap.find(({ version }) => version === stableTag);
  assert.ok(milestone, `roadmap must include ${stableTag}`);
  assert.equal(milestone.status, "released", `${stableTag} roadmap milestone must be released`);

  const released = roadmap.filter(({ status }) => status === "released");
  assert.equal(
    released.at(-1)?.version,
    stableTag,
    `${stableTag} must be the latest released milestone`,
  );
});

test("README workflow badges reference existing workflow files", () => {
  const readme = read("README.md");
  const workflowBadges = [...readme.matchAll(/\/actions\/workflows\/([^/]+\.ya?ml)\/badge\.svg/g)];

  assert.ok(workflowBadges.length > 0, "README must include at least one workflow badge");
  for (const [, workflow] of workflowBadges) {
    assert.ok(
      existsSync(new URL(`../.github/workflows/${workflow}`, import.meta.url)),
      `README badge references missing workflow: ${workflow}`,
    );
  }
});

test("metrics docs distinguish UNKNOWN and OTHER method fallbacks", () => {
  const observability = read("docs/content/docs/observability.mdx");
  const normalizedObservability = observability.replaceAll(/\s+/gu, " ");

  assert.match(
    normalizedObservability,
    /nil requests and empty methods use `UNKNOWN`; every non-empty nonstandard method collapses to `OTHER`\./iu,
  );
});

test("libpod container risk catalogs name every guarded endpoint", () => {
  const configuration = read("docs/content/docs/configuration.mdx").replaceAll(/\s+/gu, " ");
  const security = read("docs/content/docs/security.mdx").replaceAll(/\s+/gu, " ");
  const podman = read("docs/content/docs/podman.mdx").replaceAll(/\s+/gu, " ");

  const section = (document, start, end) => {
    const startIndex = document.indexOf(start);
    const endIndex = document.indexOf(end, startIndex + start.length);
    assert.notEqual(startIndex, -1, `missing catalog start: ${start}`);
    assert.notEqual(endIndex, -1, `missing catalog end: ${end}`);
    return document.slice(startIndex, endIndex);
  };
  const configurationBlindCatalog = section(
    configuration,
    "`insecure_allow_body_blind_writes` is now reserved",
    "`insecure_allow_read_exfiltration` stays",
  );
  const configurationReadCatalog = section(
    configuration,
    "`insecure_allow_read_exfiltration` stays",
    "`insecure_accept_opaque_buildkit_tunnels` stays",
  );
  const securityReadCatalog = section(
    security,
    "Sockguard now applies the same honesty rule",
    "#### Compose / BuildKit Transport",
  );

  assert.ok(
    configurationBlindCatalog.includes("`POST /libpod/containers/*/restore`"),
    "configuration blind-write catalog must name native container restore",
  );
  for (const endpoint of [
    "POST /libpod/containers/*/checkpoint",
    "POST /libpod/containers/*/mount",
    "GET /libpod/containers/showmounted",
  ]) {
    assert.ok(
      configurationReadCatalog.includes(`\`${endpoint}\``),
      `configuration read-exfiltration catalog must name ${endpoint}`,
    );
    assert.ok(
      securityReadCatalog.includes(`\`${endpoint}\``),
      `security read-exfiltration catalog must name ${endpoint}`,
    );
  }
  assert.match(
    configuration,
    /SOCKGUARD_REQUEST_BODY_CONTAINER_ARCHIVE_ALLOWED_PATHS[^|]+\|[^|]+\|[^|]+\|[^|]+`PUT \/containers\/\*\/archive` and `PUT \/libpod\/containers\/\*\/archive`/u,
  );
  assert.match(
    security,
    /`POST \/containers\/\*\/update`, `POST \/libpod\/containers\/\*\/update`, `PUT \/containers\/\*\/archive`, and `PUT \/libpod\/containers\/\*\/archive` are inspected by default/u,
  );
  assert.match(podman, /plus the libpod-only entries below:/u);
});

test("read-exfiltration warning docs describe representative endpoint probes", () => {
  const documents = [
    ["configuration reference", read("docs/content/docs/configuration.mdx")],
    ["changelog", read("CHANGELOG.md")],
  ];

  for (const [name, document] of documents) {
    const normalized = document.replaceAll(/\s+/gu, " ");
    assert.match(
      normalized,
      /endpoint fields use representative startup-validation probes and are not exhaustive/u,
      `${name} must qualify the warning's endpoint fields`,
    );
    assert.match(
      normalized,
      /Empty endpoint lists can still mean an exact-name or ordered process-list rule needs the acknowledgment/u,
      `${name} must explain why empty endpoint fields can still need the acknowledgment`,
    );
  }
});
test("release docs distinguish candidate and stable source branches", () => {
  const releasing = read("RELEASING.md").replaceAll(/\s+/gu, " ");

  assert.match(
    releasing,
    /Dispatch prerelease tags from `dev\/vX\.Y` or `maintenance\/X\.Y\.x`; dispatch stable tags from `main`\./u,
  );
  assert.match(
    releasing,
    /The workflow rejects a prerelease dispatched from `main` or a branch for another release line, and it rejects a stable release dispatched outside `main`, before it creates a tag\./u,
  );
  assert.match(
    releasing,
    /tag-triggered publisher independently resolves the protected branch that owns the release line/u,
  );
  assert.match(releasing, /manual path cannot bypass promotion through `main`/u);
});

test("signed-policy docs distinguish keyed and keyless startup requirements", () => {
  const readme = read("README.md").replaceAll(/\s+/gu, " ");
  const configuration = read("docs/content/docs/configuration.mdx").replaceAll(/\s+/gu, " ");
  const migration = read("docs/content/docs/migration.mdx").replaceAll(/\s+/gu, " ");
  const security = read("docs/content/docs/security.mdx").replaceAll(/\s+/gu, " ");
  const websiteFeatures = read("website/src/app/data/features.ts").replaceAll(/\s+/gu, " ");
  const websiteFaq = read("website/src/app/data/faq.ts").replaceAll(/\s+/gu, " ");
  const cisExample = read("examples/compose/cis-docker-benchmark/README.md").replaceAll(
    /\s+/gu,
    " ",
  );

  assert.match(configuration, /cosign sign-blob --key \.\/policy-signing\.key/u);
  assert.match(migration, /cosign sign-blob --key \.\/policy-signing\.key/u);
  assert.match(configuration, /For the keyless entry, omit `--key`/u);
  assert.match(migration, /For keyless signing, replace `allowed_signing_keys`/u);
  assert.match(configuration, /cosign sign-blob --yes/u);
  assert.match(configuration, /permissions: id-token: write/u);
  assert.match(migration, /permissions: id-token: write/u);
  assert.match(configuration, /Keyless trust loads the public Sigstore root initially/u);
  assert.match(readme, /Keyless trust loads initially and refreshes about every 24 hours/u);
  assert.match(readme, /startup fails closed if the initial load fails/u);
  assert.match(migration, /Keyless trust fetches the public Sigstore root through TUF initially/u);
  assert.match(migration, /An initial load failure aborts startup/u);
  assert.match(
    security,
    /process loads and memoizes the public Sigstore trust root through TUF initially/u,
  );
  assert.match(configuration, /A keyed-only bootstrap does not load TUF material/u);
  assert.match(configuration, /does not use a local TUF cache/u);
  assert.match(configuration, /refreshes it about every 24 hours/u);
  assert.match(
    configuration,
    /failed background refresh is logged and retains the last valid root/u,
  );
  assert.match(security, /refreshes it about every 24 hours/u);
  assert.match(configuration, /verify_timeout` supplies a cooperative deadline/u);
  assert.match(
    configuration,
    /before beginning and after each synchronous Sigstore verification attempt/u,
  );
  assert.match(configuration, /Sigstore-go cannot preempt an individual crypto call/u);
  assert.match(security, /Rekor inclusion proofs are checked locally from the bundle/u);
  assert.doesNotMatch(configuration, /per-verification network timeout/u);
  assert.doesNotMatch(configuration, /no-op when the image reference is empty/u);
  assert.match(configuration, /empty image reference is denied at Sockguard/u);
  assert.match(configuration, /Every YAML configuration file is capped at 16 MiB/u);
  assert.match(configuration, /Sigstore bundle JSON is capped at 4 MiB/u);
  assert.match(configuration, /Only regular files are accepted/u);
  assert.match(security, /FIFOs, devices, directories, and other non-regular paths are rejected/u);
  assert.match(configuration, /4 MiB for every registry GET response/u);
  assert.match(configuration, /including redirect destinations/u);
  assert.match(configuration, /32 referrer descriptors/u);
  assert.match(configuration, /16 distinct signature images/u);
  assert.match(configuration, /32 layers per signature manifest/u);
  assert.match(configuration, /16 aggregate verification candidates/u);
  assert.match(configuration, /256 KiB of aggregate annotation keys and values/u);
  assert.match(configuration, /In `enforce` mode a limit breach denies the request/u);
  assert.match(configuration, /in `warn` mode it logs the failed discovery and forwards/u);
  assert.match(configuration, /Signature references must resolve directly to image manifests/u);
  assert.match(
    configuration,
    /payload layers with alternate URLs are rejected before blob resolution/u,
  );
  assert.match(configuration, /Legal media-type parameters on direct manifests are accepted/u);
  assert.match(configuration, /Registry deadline and cancellation errors retain their cause/u);
  assert.match(configuration, /1 MiB per simple-signing payload/u);
  assert.match(configuration, /16 MiB across all payload reads for one image/u);
  assert.match(configuration, /even when a valid sibling signature exists/u);
  assert.match(security, /Image-trust discovery stops before hostile registry material/u);
  assert.match(security, /In `enforce` mode that denies the request/u);
  assert.match(security, /in `warn` mode Sockguard logs the failed discovery and forwards/u);
  assert.match(websiteFeatures, /Candidate and trust YAML stop at 16 MiB, bundles at 4 MiB/u);
  assert.match(websiteFeatures, /redirect-safe registry response limits/u);
  assert.match(websiteFeatures, /no alternate payload URLs/u);
  assert.match(websiteFaq, /accepts legal manifest media-type parameters/u);
  assert.match(websiteFaq, /cooperative verification deadline/u);
  assert.match(websiteFaq, /non-regular inputs are refused/u);
  assert.match(cisExample, /subject_pattern: '\^https:\/\/github\\\.com\/your-org\/\.\+\$'/u);
  assert.doesNotMatch(cisExample, /subject_prefix/u);
  assert.match(configuration, /Never mount or deploy the private signing key with the proxy/u);
  assert.match(migration, /Never mount or deploy the private signing key with Sockguard/u);
});

test("release docs keep Helm metadata lockstep and use a two-stage digest flow", () => {
  const releasing = read("RELEASING.md").replaceAll(/\s+/gu, " ");

  assert.match(releasing, /Keep `version` and `appVersion` equal to the stable release version\./u);
  assert.match(
    releasing,
    /Before tagging, leave `image\.tag` empty so the chart falls back to `appVersion`\./u,
  );
  assert.match(
    releasing,
    /After the release images are live, pin `image\.tag` to `<appVersion>@sha256:<digest>` in the active development branch\./u,
  );
  assert.match(releasing, /The tagged chart selects the versioned release tag/u);
  assert.doesNotMatch(releasing, /tagged chart selects the immutable release tag/u);
  assert.doesNotMatch(releasing, /increment independently of the app version/u);
  assert.doesNotMatch(releasing, /follow-up patch commit on `main` before tagging/u);
});
