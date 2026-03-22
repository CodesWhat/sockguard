export default function Home() {
  return (
    <main>
      <section>
        <h1>Sockguard</h1>
        <p>Guide what gets through.</p>
        <p>
          A Docker socket proxy that filters by method, path, and request body. Default-deny.
          Per-client policies. Structured audit logging. Drop-in replacement for Tecnativa.
        </p>
      </section>

      <section>
        <h2>Features</h2>
        <ul>
          <li>Default-deny posture — everything blocked unless explicitly allowed</li>
          <li>Granular control — allow start/stop while blocking create/exec</li>
          <li>Request body inspection — block privileged containers, dangerous mounts</li>
          <li>Per-client policies — one proxy, many consumers, tailored permissions</li>
          <li>Response filtering — hide containers, redact environment variables</li>
          <li>Structured logging — JSON access logs with decision reasoning</li>
          <li>Tecnativa compatible — drop-in replacement using the same env vars</li>
          <li>Minimal image — Wolfi-based, ~12MB, near-zero CVEs</li>
        </ul>
      </section>

      <section>
        <h2>Quick Start</h2>
        <pre>
          {`services:
  sockguard:
    image: codeswhat/sockguard:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sockguard-socket:/var/run/sockguard
    environment:
      - CONTAINERS=1
      - EVENTS=1

  your-app:
    depends_on:
      - sockguard
    volumes:
      - sockguard-socket:/var/run/sockguard:ro

volumes:
  sockguard-socket:`}
        </pre>
      </section>

      <section>
        <h2>Comparison</h2>
        <table>
          <thead>
            <tr>
              <th>Feature</th>
              <th>Tecnativa</th>
              <th>LinuxServer</th>
              <th>wollomatic</th>
              <th>Sockguard</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Method + path filtering</td>
              <td>Yes</td>
              <td>Yes</td>
              <td>Yes</td>
              <td>Yes</td>
            </tr>
            <tr>
              <td>Granular POST ops</td>
              <td>No</td>
              <td>Partial</td>
              <td>Via regex</td>
              <td>Yes</td>
            </tr>
            <tr>
              <td>Request body inspection</td>
              <td>No</td>
              <td>No</td>
              <td>No</td>
              <td>Yes</td>
            </tr>
            <tr>
              <td>Per-client policies</td>
              <td>No</td>
              <td>No</td>
              <td>IP only</td>
              <td>Yes</td>
            </tr>
            <tr>
              <td>Response filtering</td>
              <td>No</td>
              <td>No</td>
              <td>No</td>
              <td>Yes</td>
            </tr>
            <tr>
              <td>Structured audit log</td>
              <td>No</td>
              <td>No</td>
              <td>No</td>
              <td>Yes</td>
            </tr>
            <tr>
              <td>YAML config</td>
              <td>No</td>
              <td>No</td>
              <td>No</td>
              <td>Yes</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
  );
}
