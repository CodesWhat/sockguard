// Real output recorded from the sockguard binary (see provenance on the page).
// Scenes replay in the "See it in action" terminal.
export type TerminalEvent = { k: "cmd" | "out" | "note"; s: string; p?: string };
export type TerminalScene = { id: string; title: string; events: TerminalEvent[] };
export const TERMINAL = {
  product: "sockguard",
  version: "2.4.2",
  commit: "f3a332f",
  date: "2026-11-01",
  scenes: [
    {
      id: "audit",
      title: "serve, audit mode",
      events: [
        {
          k: "cmd",
          s: "sockguard serve -c discovery.yaml",
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:01.289517-05:00","level":"INFO","msg":"upstream flavor resolved","flavor":"docker","probed":true,"endpoints":1,"podman_conjunctive_volume_filters":false}',
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: "                   ▓▓▒",
        },
        {
          k: "out",
          s: "                  ▓██▓▒▒",
        },
        {
          k: "out",
          s: "           ▓▓▒▓▓  ▓█▓▓▓▓▓",
        },
        {
          k: "out",
          s: "           ██▓▓▓▓▓▓█▓▓▓▓▓▓",
        },
        {
          k: "out",
          s: "           ▓▓▓▒▒▓▒▓▓▓▓▓▓▒▓▒",
        },
        {
          k: "out",
          s: "        ▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓",
        },
        {
          k: "out",
          s: "      ▒▒▒▓▒░▒▒▒▒▒▒▒▓▓▓▓▓▓▓▒▒▒",
        },
        {
          k: "out",
          s: "     ▒▒▓▓▒▒▒▒▒▒░▒▒▓▓▓▓▓▓▓▓▓▓▒",
        },
        {
          k: "out",
          s: "     ▒▒▓▓▓▓▓▒░▒▒▒░▒▓▓▓▒▒▓▓▓▓▓▒",
        },
        {
          k: "out",
          s: " ██▓█░  ░▒▓▓▒░▓▓▓░░▓▓▓▒▒▓▓▓▓▓▒",
        },
        {
          k: "out",
          s: " ███▒     ░▓▓▒░░░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒               ▓▓▓▓",
        },
        {
          k: "out",
          s: " ░░░░░░░ ░ ░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▒▒▒▒▒▒▒▒▒▒    ▓▒▓▓",
        },
        {
          k: "out",
          s: " ░░░░░░░░░░░░▒▓▓▓▓▓▓▓▓▓▓▓▓█▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▓▓▓▓▓",
        },
        {
          k: "out",
          s: " ░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        },
        {
          k: "out",
          s: "  ░░░░░░░░░░░░▓▓▓▓▓████▒▓█▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒",
        },
        {
          k: "out",
          s: "    ░▒▒▒░░░░░▒▓███▒▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒",
        },
        {
          k: "out",
          s: "           ▓█▓▓█████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▒",
        },
        {
          k: "out",
          s: "           ▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▒▒",
        },
        {
          k: "out",
          s: "             ░▒░▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒",
        },
        {
          k: "out",
          s: "             ░░░░░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒",
        },
        {
          k: "out",
          s: "              ░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒",
        },
        {
          k: "out",
          s: "               ▒▒░░░▒▓▓▓▓▓▒▒▓█▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▒▒▓▒",
        },
        {
          k: "out",
          s: "               ▓▓▓▓▒▒▒▓▓▓▓▓▒▓▓▓▓▓▓▓▓▓▓▓▓████▓▓▓▒▒▓▓",
        },
        {
          k: "out",
          s: "               ▒▓▓▓██▓▓▓▓▓▓▓▓▓███▓██▓██████▓▓▓▓▓▓▓▓",
        },
        {
          k: "out",
          s: "               ▓▓▓▓██▓▓▓▓▓▓▓▓▓       ██████▓▓▓▓▓▓▓▓",
        },
        {
          k: "out",
          s: "                  ███▓▓▓▓▓▓▓▓▓             ██▓▓▓▓▓",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: "  sockguard 2.4.2  (commit f3a332f, built 2026-11-01, go1.27.3)",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: "  listen    discovery unix:/tmp/sg/sockguard.sock",
        },
        {
          k: "out",
          s: "  upstream  /tmp/dsw/run/docker.sock",
        },
        {
          k: "out",
          s: "  rules     1  (log json/info, access=on)",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:01.290541-05:00","level":"INFO","msg":"sockguard started","version":"2.4.2","listeners":["discovery unix:/tmp/sg/sockguard.sock"],"upstream":"/tmp/dsw/run/docker.sock","rules":1,"log_level":"info","upstream_request_timeout":"60s"}',
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:01.290654-05:00","level":"INFO","msg":"upstream endpoint health changed","endpoint":"unix:///tmp/dsw/run/docker.sock","healthy":true}',
        },
        {
          k: "cmd",
          s: 'curl -s -o /dev/null -w "%{http_code}\\n" --unix-socket sockguard.sock -X GET http://localhost/_ping',
          p: "client",
        },
        {
          k: "out",
          s: "200",
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:03.617695-05:00","level":"INFO","msg":"request_would_deny","method":"GET","path":"/_ping","request_id":"4933d7bab426c83b79504310a7e24ad1","listener_name":"discovery","normalized_path":"/_ping","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"a2db93b7f7fba3d8d0484a5a0ce5ffef","trace_span_id":"ab80355548653bd1","trace_sampled":false,"status":200,"latency_ms":0.981,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-11-02T03:10:03.617684Z","request_id":"4933d7bab426c83b79504310a7e24ad1","client_request_id":"","trace_id":"a2db93b7f7fba3d8d0484a5a0ce5ffef","trace_parent_id":"","trace_span_id":"ab80355548653bd1","trace_sampled":false,"method":"GET","raw_path":"/_ping","normalized_path":"/_ping","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
        },
        {
          k: "cmd",
          s: 'curl -s -o /dev/null -w "%{http_code}\\n" --unix-socket sockguard.sock -X GET http://localhost/v1.45/containers/json',
          p: "client",
        },
        {
          k: "out",
          s: "200",
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:04.439007-05:00","level":"INFO","msg":"request_would_deny","method":"GET","path":"/v1.45/containers/json","request_id":"d777abd731eac19a1ee598d235827fe9","listener_name":"discovery","normalized_path":"/containers/json","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"c55aec00cb844557dbc8e9e57b3861d5","trace_span_id":"415e5410d7e221d9","trace_sampled":false,"status":200,"latency_ms":0.304,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-11-02T03:10:04.438999Z","request_id":"d777abd731eac19a1ee598d235827fe9","client_request_id":"","trace_id":"c55aec00cb844557dbc8e9e57b3861d5","trace_parent_id":"","trace_span_id":"415e5410d7e221d9","trace_sampled":false,"method":"GET","raw_path":"/v1.45/containers/json","normalized_path":"/containers/json","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
        },
        {
          k: "cmd",
          s: 'curl -s -o /dev/null -w "%{http_code}\\n" --unix-socket sockguard.sock -X GET http://localhost/containers/abc123/json',
          p: "client",
        },
        {
          k: "out",
          s: "200",
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:05.259236-05:00","level":"INFO","msg":"request_would_deny","method":"GET","path":"/containers/abc123/json","request_id":"81d0ed27a6f509c6586b18ce4c475bd1","listener_name":"discovery","normalized_path":"/containers/abc123/json","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"e6a6339a80f12943d2fb93ea465c671c","trace_span_id":"ccac9f8bdefe0577","trace_sampled":false,"status":200,"latency_ms":0.3,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-11-02T03:10:05.25923Z","request_id":"81d0ed27a6f509c6586b18ce4c475bd1","client_request_id":"","trace_id":"e6a6339a80f12943d2fb93ea465c671c","trace_parent_id":"","trace_span_id":"ccac9f8bdefe0577","trace_sampled":false,"method":"GET","raw_path":"/containers/abc123/json","normalized_path":"/containers/abc123/json","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
        },
        {
          k: "cmd",
          s: 'curl -s -o /dev/null -w "%{http_code}\\n" --unix-socket sockguard.sock -X POST http://localhost/containers/abc123/exec',
          p: "client",
        },
        {
          k: "out",
          s: "200",
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:06.074123-05:00","level":"INFO","msg":"request_would_deny","method":"POST","path":"/containers/abc123/exec","request_id":"b217818700cf2d5c8708329747d49d80","listener_name":"discovery","normalized_path":"/containers/abc123/exec","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"adfea2b1d1c502c4b293876aafa20594","trace_span_id":"ada74f4ca7070457","trace_sampled":false,"status":200,"latency_ms":0.273,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-11-02T03:10:06.074115Z","request_id":"b217818700cf2d5c8708329747d49d80","client_request_id":"","trace_id":"adfea2b1d1c502c4b293876aafa20594","trace_parent_id":"","trace_span_id":"ada74f4ca7070457","trace_sampled":false,"method":"POST","raw_path":"/containers/abc123/exec","normalized_path":"/containers/abc123/exec","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
        },
        {
          k: "cmd",
          s: 'curl -s -o /dev/null -w "%{http_code}\\n" --unix-socket sockguard.sock -X DELETE http://localhost/images/sha256:abc',
          p: "client",
        },
        {
          k: "out",
          s: "200",
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:06.894312-05:00","level":"INFO","msg":"request_would_deny","method":"DELETE","path":"/images/sha256:abc","request_id":"c5522f5fd55c0a0a3c87579c5604557f","listener_name":"discovery","normalized_path":"/images/sha256:abc","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"cf16f6fe14e7f65386f0d7ba175a319d","trace_span_id":"93208a3071532f03","trace_sampled":false,"status":200,"latency_ms":0.262,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-11-02T03:10:06.894305Z","request_id":"c5522f5fd55c0a0a3c87579c5604557f","client_request_id":"","trace_id":"cf16f6fe14e7f65386f0d7ba175a319d","trace_parent_id":"","trace_span_id":"93208a3071532f03","trace_sampled":false,"method":"DELETE","raw_path":"/images/sha256:abc","normalized_path":"/images/sha256:abc","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
        },
      ],
    },
    {
      id: "harvest",
      title: "harvest with jq",
      events: [
        {
          k: "cmd",
          s: 'jq -r \'select(.decision == "would_deny") | "\\(.method) \\(.normalized_path)"\' audit.log | sort -u',
        },
        {
          k: "out",
          s: "DELETE /images/sha256:abc",
        },
        {
          k: "out",
          s: "GET /_ping",
        },
        {
          k: "out",
          s: "GET /containers/abc123/json",
        },
        {
          k: "out",
          s: "GET /containers/json",
        },
        {
          k: "out",
          s: "POST /containers/abc123/exec",
        },
      ],
    },
    {
      id: "match",
      title: "sockguard match",
      events: [
        {
          k: "cmd",
          s: "sockguard match -c portwing.yaml -X GET --path /v1.45/containers/json",
        },
        {
          k: "out",
          s: "Config:          portwing.yaml",
        },
        {
          k: "out",
          s: "Method:          GET",
        },
        {
          k: "out",
          s: "Path:            /v1.45/containers/json",
        },
        {
          k: "out",
          s: "Normalized path: /containers/json",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: "Decision:        allow",
        },
        {
          k: "out",
          s: "Matched rule:    #6",
        },
        {
          k: "out",
          s: "Rule:            allow GET /containers/json",
        },
        {
          k: "cmd",
          s: "sockguard match -c portwing.yaml -X POST --path /containers/abc/exec",
        },
        {
          k: "out",
          s: "Config:          portwing.yaml",
        },
        {
          k: "out",
          s: "Method:          POST",
        },
        {
          k: "out",
          s: "Path:            /containers/abc/exec",
        },
        {
          k: "out",
          s: "Normalized path: /containers/abc/exec",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: "Decision:        deny",
        },
        {
          k: "out",
          s: "Matched rule:    #33",
        },
        {
          k: "out",
          s: "Rule:            deny * /**",
        },
        {
          k: "out",
          s: "Reason:          not allowed by portwing preset",
        },
        {
          k: "cmd",
          s: "sockguard match -c portwing.yaml -X DELETE --path /images/sha256:abc",
        },
        {
          k: "out",
          s: "Config:          portwing.yaml",
        },
        {
          k: "out",
          s: "Method:          DELETE",
        },
        {
          k: "out",
          s: "Path:            /images/sha256:abc",
        },
        {
          k: "out",
          s: "Normalized path: /images/sha256:abc",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: "Decision:        allow",
        },
        {
          k: "out",
          s: "Matched rule:    #25",
        },
        {
          k: "out",
          s: "Rule:            allow DELETE /images/**",
        },
      ],
    },
    {
      id: "validate",
      title: "sockguard validate",
      events: [
        {
          k: "cmd",
          s: "sockguard validate -c portwing.yaml",
        },
        {
          k: "out",
          s: "  Config    portwing.yaml",
        },
        {
          k: "out",
          s: "  Listen    tcp://127.0.0.1:2375",
        },
        {
          k: "out",
          s: "  Upstream  /var/run/docker.sock",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: "  Rules (33)",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /_ping",
        },
        {
          k: "out",
          s: "    ✓ allow  HEAD   /_ping",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /version",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /info",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /events",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /containers/json",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /containers/*/json",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /containers/*/logs",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /containers/*/stats",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /containers/*/top",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /containers/*/changes",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /containers/*/start",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /containers/*/stop",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /containers/*/restart",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /containers/*/kill",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /containers/*/rename",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /containers/*/update",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /containers/*/wait",
        },
        {
          k: "out",
          s: "    ✓ allow  DELETE /containers/*",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /containers/create",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /images/json",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /images/**/json",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /images/**/history",
        },
        {
          k: "out",
          s: "    ✓ allow  POST   /images/create",
        },
        {
          k: "out",
          s: "    ✓ allow  DELETE /images/**",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /networks",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /networks/*",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /volumes",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /volumes/*",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /distribution/**/json",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /services",
        },
        {
          k: "out",
          s: "    ✓ allow  GET    /services/*",
        },
        {
          k: "out",
          s: "    ✗ deny   *      /**",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: "  ✓ validation passed",
        },
      ],
    },
    {
      id: "enforce",
      title: "flip to enforce",
      events: [
        {
          k: "cmd",
          s: "perl -pi -e 's/mode: audit/mode: enforce/' discovery.yaml",
        },
        {
          k: "cmd",
          s: "sockguard serve -c discovery.yaml",
        },
        {
          k: "note",
          s: "# startup banner and lines as before, omitted on the restart",
        },
        {
          k: "cmd",
          s: "curl -si --unix-socket sockguard.sock -X POST http://localhost/containers/abc123/exec",
          p: "client",
        },
        {
          k: "out",
          s: "HTTP/1.1 403 Forbidden",
        },
        {
          k: "out",
          s: "Content-Type: application/json",
        },
        {
          k: "out",
          s: "Traceparent: 00-c28e452f180ed5573e772e03cbfe88a8-80123d5cfd3d2573-00",
        },
        {
          k: "out",
          s: "X-Content-Type-Options: nosniff",
        },
        {
          k: "out",
          s: "X-Request-Id: b8424691466b9aa4757a46941a7cc49a",
        },
        {
          k: "out",
          s: "Date: Mon, 02 Nov 2026 03:10:10 GMT",
        },
        {
          k: "out",
          s: "Content-Length: 49",
        },
        {
          k: "out",
          s: "",
        },
        {
          k: "out",
          s: '{"message":"request denied by sockguard policy"}',
        },
        {
          k: "out",
          s: '{"time":"2026-11-01T22:10:10.116774-05:00","level":"WARN","msg":"request_denied","method":"POST","path":"/containers/abc123/exec","request_id":"b8424691466b9aa4757a46941a7cc49a","listener_name":"discovery","normalized_path":"/containers/abc123/exec","decision":"deny","rule":0,"profile":"discovery","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"c28e452f180ed5573e772e03cbfe88a8","trace_span_id":"80123d5cfd3d2573","trace_sampled":false,"status":403,"latency_ms":0.09,"bytes":49,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-11-02T03:10:10.116763Z","request_id":"b8424691466b9aa4757a46941a7cc49a","client_request_id":"","trace_id":"c28e452f180ed5573e772e03cbfe88a8","trace_parent_id":"","trace_span_id":"80123d5cfd3d2573","trace_sampled":false,"method":"POST","raw_path":"/containers/abc123/exec","normalized_path":"/containers/abc123/exec","decision":"deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"enforce","status":403,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
        },
      ],
    },
  ],
} as {
  product: string;
  version: string;
  commit: string;
  date: string;
  scenes: TerminalScene[];
};
