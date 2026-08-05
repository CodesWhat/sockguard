# normalize-routes.jq — route-drift tripwire normalizer (#150)
#
# Reads sockguard's structured access log as raw newline-delimited text
# (log.format: json, access_log: true -- app/internal/logging/access.go)
# and emits a de-duplicated, sorted JSON array of {"method","path"} route
# SHAPES observed on the wire.
#
# Invocation:  jq -n -R -f normalize-routes.jq <access-log-file>
#
# Non-JSON lines (anything sockguard or docker compose's log plumbing
# writes that isn't a clean JSON object -- there shouldn't be any with
# --no-log-prefix, but this stays defensive) are silently skipped rather
# than failing the whole run. Only the three access-log message names are
# considered; sockguard's other structured logs (startup, config reload,
# etc.) use different `msg` values and are ignored.
#
# Shape rules mirror the glob patterns already written by hand in
# app/configs/portwing.yaml / portwing-with-exec.yaml -- this file does not
# invent a new normalization scheme, it reproduces the existing preset
# author's segment classification so the manifest in known-routes.json can
# be a flat list of those same shapes:
#   - a path segment that is one of the fixed Docker API keywords below is
#     kept literally (these are the constant segments every preset rule
#     matches on -- "containers", "json", "start", etc.)
#   - any other segment (container/network/volume/service/exec IDs and
#     names, image references) is "dynamic" and becomes "*"
#   - a run of two or more consecutive dynamic segments collapses to a
#     single "**" (this is what lets a multi-part image reference like
#     ghcr.io/owner/repo collapse the same way the images/** and
#     distribution/** preset rules do)
#
# `normalized_path` (not the raw `path`) is used as input: sockguard's
# access logger already strips the /vX.YZ/ Docker API version prefix into
# that field, so this normalizer only has to handle the ID/name segments,
# not engine-API versioning.

def static_segments:
  [
    "_ping", "version", "info", "events",
    "containers", "json", "logs", "stats", "top", "changes",
    "start", "stop", "restart", "kill", "rename", "update", "wait", "create",
    "images", "history",
    "networks", "volumes", "distribution", "services",
    "exec", "resize",
    "build", "export", "archive", "attach"
  ];

def shape_path:
  ((. / "/") | map(select(length > 0))) as $parts
  | (reduce $parts[] as $seg
       ([]; . + [ if (static_segments | index($seg)) then $seg else "*" end ])
    ) as $shaped
  | (reduce $shaped[] as $s
       ([];
         if $s == "*" and (length > 0) and (.[-1] == "*" or .[-1] == "**")
         then (.[:-1] + ["**"])
         else . + [$s]
         end)
    ) as $collapsed
  | "/" + ($collapsed | join("/"));

[
  inputs
  | (try fromjson catch empty)
  | select(.msg == "request" or .msg == "request_denied" or .msg == "request_would_deny")
  | select(.method != null and .normalized_path != null)
  | { method: .method, path: (.normalized_path | shape_path) }
]
| unique
