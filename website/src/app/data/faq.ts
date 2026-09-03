export const faqItems: Array<{ question: string; answer: string }> = [
  {
    question: "What is Sockguard and how does the default-deny model work?",
    answer:
      "Sockguard is a Docker socket proxy we built in Go. Every Docker API request is blocked unless an explicit rule in your YAML config allows it — method, path, and request body are all evaluated before the request reaches the daemon. A client that connects without a matching allow rule gets a 403; there is no fallback to 'pass everything'. This posture means a compromised container or CI job can only do what you deliberately permitted.",
  },
  {
    question: "How is Sockguard different from Tecnativa's docker-socket-proxy?",
    answer:
      "Tecnativa filters by URL path using environment variables. Sockguard also inspects request bodies across container, exec, image, Docker and Podman build, volume, network, service, swarm, and plugin writes. Per-client profiles, signed policies, image trust, rollout modes, and (opt-in) bounded Prometheus metrics and hot reload add controls Tecnativa does not provide. The compatibility env surface remains a drop-in path for unsigned mode; convert generated rules to YAML before enabling signed-policy trust.",
  },
  {
    question: "Does Sockguard inspect request bodies?",
    answer:
      "Yes. We inspect container create and exec, image build and load, Docker's classic build, native Podman's /libpod/build, volume, network, secret, config, service, swarm, node, and plugin writes. Native Podman build checks primary and additional remote contexts, host networking, every repeated query control, Dockerfile RUN policy, and resource-usage host-file output. Host/local/multipart and host-file controls require the global blind-write acknowledgment. Oversized bounded bodies return 413, and a 30-second read deadline stops slow clients from pinning an inspector even when logging and metrics are enabled.",
  },
  {
    question: "Can Sockguard listen over TCP, and is remote access secure?",
    answer:
      "Yes. Sockguard can listen on a TCP port in addition to (or instead of) a unix socket. For any non-loopback TCP listener we require mutual TLS 1.3 by default — plaintext remote TCP needs two explicit insecure acknowledgement flags before we accept it. Client identity on TCP is established via mTLS certificate selectors (CN, DNS/IP/URI SAN, SHA-256 SPKI pin). Sockguard can also dial a remote Docker daemon over TCP with mTLS and automatic endpoint failover (added in v1.4.0).",
  },
  {
    question: "What are signed policy bundles and container image trust?",
    answer:
      "Signed policy bundles treat the candidate YAML as untrusted until a cosign bundle verifies it. Keyed or keyless trust, Rekor posture, and a cooperative verification deadline live in a separate bootstrap file; candidate and trust YAML stop at 16 MiB, bundles at 4 MiB, and non-regular inputs are refused. Verification runs at startup and every reload. Container image trust separately resolves workload images to digests, rejects alternate payload URLs, accepts legal manifest media-type parameters, and applies redirect-safe response, signature fan-out, and aggregate payload limits before enforcing signer identity.",
  },
  {
    question: "Is Sockguard production-ready and what license does it use?",
    answer:
      "Sockguard is Apache-2.0 licensed and has been in production use since v1.0.0. The proxy binary ships as a distroless container image (Chainguard's `static` base, built from Wolfi packages — no shell, no package manager), cosign-signed with an SBOM and build provenance attached. We enforce a 96%+ Go statement-coverage floor in CI, run a differential route-oracle fuzzer on every PR plus a real-dockerd differential suite on every change to the proxy, and have a published security policy at security@getsockguard.com. The v1.1.0 release incorporated fixes for 21 HIGH and MEDIUM findings from a full multi-axis security audit.",
  },
  {
    question: "How do I migrate from Tecnativa's docker-socket-proxy?",
    answer:
      "Point DOCKER_HOST at Sockguard and keep the current Tecnativa section and ALLOW_* variables for the initial unsigned migration. Add SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true with them: a broad section grant like CONTAINERS=1 generates an allow rule that also covers the archive, export, log and attach endpoints, and Sockguard refuses to start rather than open those silently. It is a hard error, not a warning, and the goal is to drop the acknowledgment once the rules are narrow enough not to need it. Then translate the generated allow surface into YAML, add body policy and per-client profiles, and use warn mode to measure tighter rules. Signed-policy mode is the final step: it rejects rule-generating compatibility variables so unsigned environment state cannot change a verified policy.",
  },
];
