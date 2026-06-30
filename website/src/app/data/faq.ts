export const faqItems: Array<{ question: string; answer: string }> = [
  {
    question: "What is Sockguard and how does the default-deny model work?",
    answer:
      "Sockguard is a Docker socket proxy we built in Go. Every Docker API request is blocked unless an explicit rule in your YAML config allows it — method, path, and request body are all evaluated before the request reaches the daemon. A client that connects without a matching allow rule gets a 403; there is no fallback to 'pass everything'. This posture means a compromised container or CI job can only do what you deliberately permitted.",
  },
  {
    question: "How is Sockguard different from Tecnativa's docker-socket-proxy?",
    answer:
      "Tecnativa filters by URL path using environment variables. Sockguard adds request body inspection — we parse every container, exec, image, build, volume, network, service, swarm, and plugin write to block privileged workloads, non-allowlisted mounts and devices, unsafe sysctls, and more. We also support per-client policy profiles (route different callers to different rule sets by CIDR, mTLS certificate, or unix peer), signed policy bundles (cosign), container image trust verification, per-profile rollout modes (enforce / warn / audit), Prometheus metrics, and hot-reload with an admin API. Tecnativa has none of these. We also ship a Tecnativa-compatible env surface so you can swap us in without touching your existing config.",
  },
  {
    question: "Does Sockguard inspect request bodies?",
    answer:
      "Yes — request body inspection is one of our core differentiators. We parse the JSON body on every write endpoint: container create and exec, image build and load, volume create, network create, secret and config create, service create and update, swarm init and join, node update, and plugin install. We check for privileged mode, host namespace sharing, non-allowlisted bind mounts and devices, capability additions, unsafe sysctls, non-allowlisted runtimes, and more. Oversized bodies return 413 before the inspector runs. We also inspect multipart plugin uploads and gzip-bomb guard all archive paths.",
  },
  {
    question: "Can Sockguard listen over TCP, and is remote access secure?",
    answer:
      "Yes. Sockguard can listen on a TCP port in addition to (or instead of) a unix socket. For any non-loopback TCP listener we require mutual TLS 1.3 by default — plaintext remote TCP needs two explicit insecure acknowledgement flags before we accept it. Client identity on TCP is established via mTLS certificate selectors (CN, DNS/IP/URI SAN, SHA-256 SPKI pin). Starting in v1.4.0, Sockguard can also dial a remote Docker daemon over TCP with mTLS and automatic endpoint failover.",
  },
  {
    question: "What are signed policy bundles and container image trust?",
    answer:
      "Signed policy bundles let you treat the on-disk YAML config as untrusted until a cosign / sigstore bundle confirms it. We support keyed (PEM ECDSA/RSA/ed25519) and keyless (Fulcio + Rekor) verification. The bundle is checked at startup and on every hot reload — a bad signature rejects the reload and leaves the running policy untouched. Container image trust goes further: before forwarding a POST /containers/create to the daemon, we resolve the image to its registry manifest digest, discover cosign signatures, and verify them against your configured signer identity. In enforce mode a container create is denied if the image is unsigned or signed by the wrong identity.",
  },
  {
    question: "Is Sockguard production-ready and what license does it use?",
    answer:
      "Sockguard is Apache-2.0 licensed and has been in production use since v1.0.0. The proxy binary ships as a minimal Wolfi-based container image, cosign-signed with an SBOM and build provenance attached. We enforce a 96%+ Go statement-coverage floor in CI, run a proxy-vs-daemon differential fuzz harness on every PR, and have a published security policy at security@getsockguard.com. The v1.0.0 release incorporated fixes for 21 HIGH and MEDIUM audit findings before it shipped.",
  },
  {
    question: "How do I migrate from Tecnativa's docker-socket-proxy?",
    answer:
      "We match Tecnativa's full environment-variable surface — CONTAINERS, EVENTS, SERVICES, NETWORKS, VOLUMES, TASKS, NODES, CONFIGS, SECRETS, ALLOW_RESTARTS, SOCKET_PATH, LOG_LEVEL, and the full section-variable set. Point DOCKER_HOST at the Sockguard socket instead of Tecnativa's and your existing env config continues to work. The shipped 'tecnativa-compatible' preset covers the same allow surface. Once migrated you can layer on body inspection, per-client profiles, and signed policies incrementally without breaking running workloads — use a profile in warn mode to measure what would have been denied before flipping to enforce.",
  },
];
