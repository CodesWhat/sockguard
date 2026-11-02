// Real output recorded from the sockguard binary (see provenance on the page).
// Scenes replay in the "See it in action" terminal.
export type TerminalEvent = { k: "cmd" | "out" | "note"; s: string; p?: string };
export type TerminalScene = { id: string; title: string; events: TerminalEvent[] };
export const TERMINAL = {
  product: "sockguard",
  version: "2.3.1",
  commit: "bb4f886",
  date: "2026-10-29",
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
          s: '{"time":"2026-10-29T09:39:41.531575-04:00","level":"INFO","msg":"upstream flavor resolved","flavor":"docker","probed":true,"endpoints":1}',
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
          s: "  sockguard 2.3.1  (commit bb4f886, built 2026-10-29, go1.27.3)",
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
          s: '{"time":"2026-10-29T09:39:41.53384-04:00","level":"INFO","msg":"sockguard started","version":"2.3.1","listeners":["discovery unix:/tmp/sg/sockguard.sock"],"upstream":"/tmp/dsw/run/docker.sock","rules":1,"log_level":"info","upstream_request_timeout":"60s"}',
        },
        {
          k: "out",
          s: '{"time":"2026-10-29T09:39:41.53402-04:00","level":"INFO","msg":"upstream endpoint health changed","endpoint":"unix:///tmp/dsw/run/docker.sock","healthy":true}',
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
          s: '{"time":"2026-10-29T09:39:43.839377-04:00","level":"INFO","msg":"request_would_deny","method":"GET","path":"/_ping","request_id":"ebc5dd69db3e7d99f07aa0768e278724","listener_name":"discovery","normalized_path":"/_ping","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"02825bb39e1faf682320842f0f4d14e1","trace_span_id":"e0ff38edb4273a4b","trace_sampled":false,"status":200,"latency_ms":0.826,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-10-29T13:39:43.839368Z","request_id":"ebc5dd69db3e7d99f07aa0768e278724","client_request_id":"","trace_id":"02825bb39e1faf682320842f0f4d14e1","trace_parent_id":"","trace_span_id":"e0ff38edb4273a4b","trace_sampled":false,"method":"GET","raw_path":"/_ping","normalized_path":"/_ping","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
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
          s: '{"time":"2026-10-29T09:39:44.658915-04:00","level":"INFO","msg":"request_would_deny","method":"GET","path":"/v1.45/containers/json","request_id":"5001c3df5aa11a300875f291473485ac","listener_name":"discovery","normalized_path":"/containers/json","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"ba230326a9f48e83978942db70d2a63e","trace_span_id":"a0e6301146c6d726","trace_sampled":false,"status":200,"latency_ms":0.295,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-10-29T13:39:44.658908Z","request_id":"5001c3df5aa11a300875f291473485ac","client_request_id":"","trace_id":"ba230326a9f48e83978942db70d2a63e","trace_parent_id":"","trace_span_id":"a0e6301146c6d726","trace_sampled":false,"method":"GET","raw_path":"/v1.45/containers/json","normalized_path":"/containers/json","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
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
          s: '{"time":"2026-10-29T09:39:45.478991-04:00","level":"INFO","msg":"request_would_deny","method":"GET","path":"/containers/abc123/json","request_id":"78c14d575425a02a509c6afeca7f8deb","listener_name":"discovery","normalized_path":"/containers/abc123/json","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"0b434b069b48347e36bfd0e04b6cf36d","trace_span_id":"034ccfdd2c05ddda","trace_sampled":false,"status":200,"latency_ms":0.271,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-10-29T13:39:45.478985Z","request_id":"78c14d575425a02a509c6afeca7f8deb","client_request_id":"","trace_id":"0b434b069b48347e36bfd0e04b6cf36d","trace_parent_id":"","trace_span_id":"034ccfdd2c05ddda","trace_sampled":false,"method":"GET","raw_path":"/containers/abc123/json","normalized_path":"/containers/abc123/json","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
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
          s: '{"time":"2026-10-29T09:39:46.303974-04:00","level":"INFO","msg":"request_would_deny","method":"POST","path":"/containers/abc123/exec","request_id":"f0c5d95c2336b32bdec07a0c97a65f9a","listener_name":"discovery","normalized_path":"/containers/abc123/exec","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"19c95fd9d3ecf30533fb18f22dcc60a2","trace_span_id":"da31c88e772e29cf","trace_sampled":false,"status":200,"latency_ms":1.068,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-10-29T13:39:46.303965Z","request_id":"f0c5d95c2336b32bdec07a0c97a65f9a","client_request_id":"","trace_id":"19c95fd9d3ecf30533fb18f22dcc60a2","trace_parent_id":"","trace_span_id":"da31c88e772e29cf","trace_sampled":false,"method":"POST","raw_path":"/containers/abc123/exec","normalized_path":"/containers/abc123/exec","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
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
          s: '{"time":"2026-10-29T09:39:47.126078-04:00","level":"INFO","msg":"request_would_deny","method":"DELETE","path":"/images/sha256:abc","request_id":"6c7a7d00c247857e233b2824f733ebca","listener_name":"discovery","normalized_path":"/images/sha256:abc","decision":"would_deny","rule":0,"profile":"discovery","rollout_mode":"audit","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"c6d21163d5825473149309db0c03c6de","trace_span_id":"52178e2f1010ec6e","trace_sampled":false,"status":200,"latency_ms":0.295,"bytes":2,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-10-29T13:39:47.126069Z","request_id":"6c7a7d00c247857e233b2824f733ebca","client_request_id":"","trace_id":"c6d21163d5825473149309db0c03c6de","trace_parent_id":"","trace_span_id":"52178e2f1010ec6e","trace_sampled":false,"method":"DELETE","raw_path":"/images/sha256:abc","normalized_path":"/images/sha256:abc","decision":"would_deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"audit","status":200,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
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
          s: "Traceparent: 00-b199ceaea1275dc07fb8df471eed08f9-395567b3f3b2bf07-00",
        },
        {
          k: "out",
          s: "X-Content-Type-Options: nosniff",
        },
        {
          k: "out",
          s: "X-Request-Id: 0598d476e1ad08643a35351e75f52b6a",
        },
        {
          k: "out",
          s: "Date: Thu, 29 Oct 2026 13:39:50 GMT",
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
          s: '{"time":"2026-10-29T09:39:50.369252-04:00","level":"WARN","msg":"request_denied","method":"POST","path":"/containers/abc123/exec","request_id":"0598d476e1ad08643a35351e75f52b6a","listener_name":"discovery","normalized_path":"/containers/abc123/exec","decision":"deny","rule":0,"profile":"discovery","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","trace_id":"b199ceaea1275dc07fb8df471eed08f9","trace_span_id":"395567b3f3b2bf07","trace_sampled":false,"status":403,"latency_ms":0.133,"bytes":49,"client":"unix"}',
        },
        {
          k: "out",
          s: '{"event_type":"http_request","timestamp":"2026-10-29T13:39:50.369234Z","request_id":"0598d476e1ad08643a35351e75f52b6a","client_request_id":"","trace_id":"b199ceaea1275dc07fb8df471eed08f9","trace_parent_id":"","trace_span_id":"395567b3f3b2bf07","trace_sampled":false,"method":"POST","raw_path":"/containers/abc123/exec","normalized_path":"/containers/abc123/exec","decision":"deny","reason_code":"matched_deny_rule","reason":"discovery preset — logged only, not enforced","matched_rule":0,"selected_profile":"discovery","rollout_mode":"enforce","status":403,"actor_remote_addr":"","actor_source_ip":"","transport_listener":"tcp","transport_scheme":"http","transport_protocol":"HTTP/1.1","ownership":{"enabled":false,"owner":"","label_key":"com.sockguard.owner"},"listener_name":"discovery"}',
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
