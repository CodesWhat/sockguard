import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const chartPath = resolve(repoRoot, "chart/sockguard");

function helm(args) {
  return spawnSync("helm", args, {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

function renderChart(args = []) {
  const result = helm(["template", "sockguard", chartPath, ...args]);

  assert.equal(
    result.error,
    undefined,
    `helm is required to test the rendered chart: ${result.error}`,
  );
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

function renderFailure(args) {
  const result = helm(["template", "sockguard", chartPath, ...args]);

  assert.equal(
    result.error,
    undefined,
    `helm is required to test the rendered chart: ${result.error}`,
  );
  assert.notEqual(result.status, 0, "invalid trust references must fail chart rendering");
  return result.stderr;
}

function renderInstallNotes(args) {
  const result = helm(["install", "--dry-run=client", "sockguard-notes", chartPath, ...args]);

  assert.equal(result.error, undefined, `helm install failed to start: ${result.error}`);
  assert.equal(result.status, 0, result.stderr);
  const notes = result.stdout.split("\nNOTES:\n")[1];
  assert.ok(notes, "dry-run install must render NOTES.txt");
  return notes;
}

function documentOfKind(rendered, kind) {
  const document = rendered
    .split(/^---\s*$/m)
    .find((candidate) => new RegExp(`^kind: ${kind}$`, "m").test(candidate));
  assert.ok(document, `rendered chart must contain a ${kind}`);
  return document;
}

describe("Helm policy bundle trust reference", () => {
  it("leaves the unsigned default deployment unchanged", () => {
    const rendered = renderChart();
    const daemonSet = documentOfKind(rendered, "DaemonSet");
    const candidateConfigMap = documentOfKind(rendered, "ConfigMap");

    assert.doesNotMatch(daemonSet, /policy-bundle-trust-config/u);
    assert.doesNotMatch(daemonSet, /policy-bundle-trust/u);
    assert.doesNotMatch(daemonSet, /policy-bundle-signature/u);
    assert.doesNotMatch(candidateConfigMap, /trust\.yaml/u);
  });

  it("mounts externally managed trust and signature Secrets at separate paths", () => {
    const rendered = renderChart([
      "--set-string",
      "policyBundleTrust.secretRef.name=sockguard-policy-trust",
      "--set-string",
      "policyBundleTrust.secretRef.key=trust.yaml",
      "--set-string",
      "policyBundleSignature.secretRef.name=sockguard-policy-signature",
      "--set-string",
      "policyBundleSignature.secretRef.key=signature.json",
    ]);
    const daemonSet = documentOfKind(rendered, "DaemonSet");
    const candidateConfigMap = documentOfKind(rendered, "ConfigMap");

    assert.match(
      daemonSet,
      /- --policy-bundle-trust-config\s+- \/etc\/sockguard-policy-bundle-trust\/trust\.yaml/u,
    );
    assert.match(
      daemonSet,
      /- name: policy-bundle-trust\s+mountPath: \/etc\/sockguard-policy-bundle-trust\s+readOnly: true/u,
    );
    assert.match(
      daemonSet,
      /- name: policy-bundle-trust\s+secret:\s+secretName: "sockguard-policy-trust"\s+items:\s+- key: "trust\.yaml"\s+path: trust\.yaml/u,
    );
    assert.match(
      daemonSet,
      /- name: policy-bundle-signature\s+mountPath: \/etc\/sockguard-policy-bundle-signature\s+readOnly: true/u,
    );
    assert.match(
      daemonSet,
      /- name: policy-bundle-signature\s+secret:\s+secretName: "sockguard-policy-signature"\s+items:\s+- key: "signature\.json"\s+path: signature\.json/u,
    );
    assert.doesNotMatch(candidateConfigMap, /sockguard-policy-trust|trust\.yaml/u);
  });

  it("keeps listener settings inside the candidate policy instead of unsigned env overlays", () => {
    const rendered = renderChart([
      "--set-string",
      "policyBundleTrust.secretRef.name=sockguard-policy-trust",
      "--set-string",
      "policyBundleTrust.secretRef.key=trust.yaml",
      "--set-string",
      "policyBundleSignature.secretRef.name=sockguard-policy-signature",
      "--set-string",
      "policyBundleSignature.secretRef.key=signature.json",
    ]);
    const daemonSet = documentOfKind(rendered, "DaemonSet");
    const candidateConfigMap = documentOfKind(rendered, "ConfigMap");

    assert.doesNotMatch(daemonSet, /SOCKGUARD_LISTEN_/u);
    assert.match(candidateConfigMap, /listen:\s+address: ":2375"/u);
    assert.match(candidateConfigMap, /insecure_allow_plain_tcp: true/u);
    assert.match(candidateConfigMap, /insecure_allow_unauthenticated_clients: true/u);
  });

  it("mounts externally managed ConfigMaps as alternative trust and signature sources", () => {
    const rendered = renderChart([
      "--set-string",
      "policyBundleTrust.configMapRef.name=sockguard-policy-trust",
      "--set-string",
      "policyBundleTrust.configMapRef.key=trust.yaml",
      "--set-string",
      "policyBundleSignature.configMapRef.name=sockguard-policy-signature",
      "--set-string",
      "policyBundleSignature.configMapRef.key=signature.json",
    ]);
    const daemonSet = documentOfKind(rendered, "DaemonSet");

    assert.match(
      daemonSet,
      /- name: policy-bundle-trust\s+configMap:\s+name: "sockguard-policy-trust"\s+items:\s+- key: "trust\.yaml"\s+path: trust\.yaml/u,
    );
    assert.match(
      daemonSet,
      /- name: policy-bundle-signature\s+configMap:\s+name: "sockguard-policy-signature"\s+items:\s+- key: "signature\.json"\s+path: signature\.json/u,
    );
  });

  it("explains trust rotation without rendering trust material", () => {
    const notes = renderInstallNotes([
      "--set-string",
      "policyBundleTrust.secretRef.name=sockguard-policy-trust",
      "--set-string",
      "policyBundleTrust.secretRef.key=trust.yaml",
      "--set-string",
      "policyBundleSignature.secretRef.name=sockguard-policy-signature",
      "--set-string",
      "policyBundleSignature.secretRef.key=signature.json",
    ]);

    assert.match(notes, /Policy bundle trust: enabled from an externally managed Secret/u);
    assert.match(notes, /restart daemonset\/sockguard-notes/u);
    assert.match(notes, /never copies the trust YAML into the candidate policy ConfigMap/u);
    assert.match(notes, /\/etc\/sockguard-policy-bundle-signature\/signature\.json/u);
  });

  it("rejects the chart-generated candidate ConfigMap as the trust source", () => {
    const stderr = renderFailure([
      "--set-string",
      "policyBundleTrust.configMapRef.name=sockguard",
      "--set-string",
      "policyBundleTrust.configMapRef.key=sockguard.yaml",
      "--set-string",
      "policyBundleSignature.secretRef.name=sockguard-policy-signature",
      "--set-string",
      "policyBundleSignature.secretRef.key=signature.json",
    ]);

    assert.match(stderr, /must not reference the chart-generated candidate policy ConfigMap/u);
  });

  it("rejects trust and signature data stored in the same Kubernetes object", () => {
    const secret = renderFailure([
      "--set-string",
      "policyBundleTrust.secretRef.name=combined-policy-object",
      "--set-string",
      "policyBundleTrust.secretRef.key=trust.yaml",
      "--set-string",
      "policyBundleSignature.secretRef.name=combined-policy-object",
      "--set-string",
      "policyBundleSignature.secretRef.key=signature.json",
    ]);
    assert.match(secret, /must reference different Kubernetes objects/u);

    const configMap = renderFailure([
      "--set-string",
      "policyBundleTrust.configMapRef.name=combined-policy-object",
      "--set-string",
      "policyBundleTrust.configMapRef.key=trust.yaml",
      "--set-string",
      "policyBundleSignature.configMapRef.name=combined-policy-object",
      "--set-string",
      "policyBundleSignature.configMapRef.key=signature.json",
    ]);
    assert.match(configMap, /must reference different Kubernetes objects/u);
  });

  it("rejects unpaired trust and signature references", () => {
    const trustOnly = renderFailure([
      "--set-string",
      "policyBundleTrust.secretRef.name=sockguard-policy-trust",
      "--set-string",
      "policyBundleTrust.secretRef.key=trust.yaml",
    ]);
    assert.match(trustOnly, /must be configured together/u);

    const signatureOnly = renderFailure([
      "--set-string",
      "policyBundleSignature.secretRef.name=sockguard-policy-signature",
      "--set-string",
      "policyBundleSignature.secretRef.key=signature.json",
    ]);
    assert.match(signatureOnly, /must be configured together/u);
  });

  it("rejects simultaneous Secret and ConfigMap references", () => {
    const stderr = renderFailure([
      "--set-string",
      "policyBundleTrust.secretRef.name=secret-trust",
      "--set-string",
      "policyBundleTrust.secretRef.key=trust.yaml",
      "--set-string",
      "policyBundleTrust.configMapRef.name=configmap-trust",
      "--set-string",
      "policyBundleTrust.configMapRef.key=trust.yaml",
    ]);

    assert.match(stderr, /only one of secretRef or configMapRef may be configured/u);
  });

  it("rejects incomplete and malformed references", () => {
    const incomplete = renderFailure([
      "--set-string",
      "policyBundleTrust.secretRef.name=secret-trust",
    ]);
    assert.match(incomplete, /secretRef requires non-empty name and key/u);

    const malformed = renderFailure(["--set-string", "policyBundleTrust.configMapRef=not-a-map"]);
    assert.match(malformed, /configMapRef must be a map with name and key/u);
  });
});
