#!/usr/bin/env python3
"""Refresh advisory route facts from pinned upstream API sources.

The output is deterministic: routes are sorted and nothing is timestamped, so
running this at the pinned revisions must reproduce
app/internal/cmd/known_api_routes.json byte for byte. The offline parser tests
(scripts/update-route-catalog.test.mjs) are the CI gate. Manual reproducibility
check, which needs network access:

    python3 scripts/update-route-catalog.py
    git diff --exit-code app/internal/cmd/known_api_routes.json

The catalog lists HTTP routes only. Native gRPC on the Docker socket, such as
the moby Jobs extension (org.mobyproject.extension.jobs.api.v0.Jobs), is not an
HTTP route and never appears here. Sockguard refuses it because its listener
has no h2c support; see TestServeHandlerRefusesJobsGRPCOverH2C.
"""

import concurrent.futures
import json
import os
import pathlib
import re
import urllib.parse
import urllib.request

# Commit behind the docker-v29.10.0 tag (Engine API 1.57). The monthly API
# watch overrides it with SOCKGUARD_ENGINE_REV to re-derive at the latest tag.
ENGINE_REV = os.environ.get("SOCKGUARD_ENGINE_REV") or "06db1734267bf7770914b417bff6556d835bf8cc"
# Commit behind the v6.2.0 tag (Podman 6.2.0). Override: SOCKGUARD_PODMAN_REV.
PODMAN_REV = os.environ.get("SOCKGUARD_PODMAN_REV") or "055de046937d29450f310fce0fe3071485d8bed9"
ROOT = pathlib.Path(__file__).resolve().parents[1]


def fetch(url):
    headers = {"User-Agent": "sockguard-route-catalog"}
    # Anonymous api.github.com calls share the runner IP's 60/hour limit, so
    # send the workflow's credential when one is set. Only to api.github.com.
    auth = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if auth and urllib.parse.urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {auth}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode()


METHODS = {"Get": "GET", "Head": "HEAD", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Options": "OPTIONS"}
VERSION_PREFIX = re.compile(r"^/v\{version:[^}]*\}")
PREFIX_DECL = re.compile(r'(?m)^\s*(\w+)\s*:=\s*r\.PathPrefix\("([^"]+)"\)\.Subrouter\(\)')
PREFIX_STUB = re.compile(r'(?m)^\s*r\.PathPrefix\("[^"]+"\)\.HandlerFunc\(noSwarm\)\s*$')
REGISTRATION = re.compile(r'(?m)^\s*(\w+)\.Handle(?:Func)?\((?:VersionedPath\()?"([^"]+)"[^\n]*?\.Methods\(([^\n]*)\)')
HANDLE_CALL = re.compile(r"\b\w+\.Handle(?:Func)?\(")


def parse_engine_swagger(text):
    routes = set()
    current = None
    for line in text.split("\npaths:\n", 1)[1].splitlines():
        path = re.fullmatch(r"  (/.*):", line)
        if path:
            current = path[1]
        method = re.fullmatch(r"    (get|head|post|put|patch|delete|options):", line)
        if current and method:
            # Engine image/plugin/distribution names include registry slashes.
            template = current
            if template.startswith(("/images/", "/plugins/", "/distribution/")):
                template = template.replace("{name}", "{name:.*}")
            routes.add((method[1].upper(), template))
    return routes


def parse_podman_register(source, name):
    """Extract (method, path) pairs from one Podman register_*.go file.

    Handles r.Handle/r.HandleFunc (optionally via VersionedPath) and
    <var>.Handle/<var>.HandleFunc on a `<var> := r.PathPrefix(...).Subrouter()`
    declared in the same file. Raises ValueError when any registration call or
    subrouter declaration is left unparsed.
    """
    source = "\n".join(line for line in source.splitlines() if "UnsupportedHandler" not in line and not line.lstrip().startswith("//"))
    prefixes = {}
    for var, prefix in PREFIX_DECL.findall(source):
        prefixes[var] = VERSION_PREFIX.sub("", prefix)
    # PathPrefix(...).HandlerFunc(noSwarm) catch-alls are unsupported stubs, not routes.
    stubs = len(PREFIX_STUB.findall(source))
    if len(prefixes) + stubs != len(re.findall(r"\.PathPrefix\(", source)) or len(prefixes) != len(re.findall(r"\.Subrouter\(", source)):
        raise ValueError(f"Podman subrouter format changed in {name}; update the extractor")
    registrations = list(REGISTRATION.finditer(source))
    if len(registrations) != len(HANDLE_CALL.findall(source)):
        raise ValueError(f"Podman registration format changed in {name}; update the extractor")
    routes = set()
    for match in registrations:
        var = match[1]
        if var == "r":
            prefix = ""
        elif var in prefixes:
            prefix = prefixes[var]
        else:
            raise ValueError(f"unknown router variable {var} in {name}; update the extractor")
        path = prefix + VERSION_PREFIX.sub("", match[2])
        found = re.findall(r"http\.Method(\w+)", match[3])
        if not found:
            raise ValueError(f"no HTTP method in a registration for {path} in {name}")
        for method in found:
            if method not in METHODS:
                raise ValueError(f"unknown HTTP method {method}")
            routes.add((METHODS[method], path))
    return routes


def build_routes(engine_swagger, podman_sources, root):
    """podman_sources maps register_*.go file name to its source text."""
    routes = parse_engine_swagger(engine_swagger)
    for name in sorted(podman_sources):
        routes |= parse_podman_register(podman_sources[name], name)
    # The Engine OpenAPI does not enumerate the daemon's debug router, which
    # moby installs on every API listener (daemon/server/router/debug).
    for method, path in [
        ("GET", "/debug/vars"),
        ("GET", "/debug/pprof/"),
        ("GET", "/debug/pprof/cmdline"),
        ("GET", "/debug/pprof/profile"),
        ("GET", "/debug/pprof/symbol"),
        ("POST", "/debug/pprof/symbol"),
        ("GET", "/debug/pprof/trace"),
        ("GET", "/debug/pprof/{name}"),
    ]:
        routes.add((method, path))
    # The Engine OpenAPI does not enumerate BuildKit's hijacked/RPC paths.
    for path in ["/session", "/grpc"]:
        routes.add(("POST", path))
    for source in sorted((root / "app/internal/buildkitproto/proto").rglob("*.proto")):
        text = source.read_text()
        package = re.search(r"(?m)^package ([\w.]+);", text)
        if not package:
            continue
        for service, body in re.findall(r"service (\w+)\s*\{(.*?)\n\}", text, re.S):
            for method in re.findall(r"\brpc (\w+)\s*\(", body):
                routes.add(("POST", f"/{package[1]}.{service}/{method}"))
    registry = (root / "app/internal/buildkitproxy/registry.go").read_text()
    for service, method in re.findall(r'\{Endpoint(?:GRPC|Session),\s*"([^"]+)",\s*"([^"]+)"\}', registry):
        routes.add(("POST", f"/{service}/{method}"))
    if len(routes) < 250 or not any(path.startswith("/libpod/") for _, path in routes):
        raise ValueError("upstream route extraction is incomplete")
    return routes


def render(routes, engine_url):
    document = {
        "sources": {"engine": engine_url, "podman": f"https://github.com/containers/podman/tree/{PODMAN_REV}/pkg/api/server", "buildkit": "app/internal/buildkitproto/proto and app/internal/buildkitproxy/registry.go"},
        "routes": [{"method": method, "path": path} for method, path in sorted(routes)],
    }
    return json.dumps(document, indent=2) + "\n"


def main():
    engine_url = f"https://raw.githubusercontent.com/moby/moby/{ENGINE_REV}/api/swagger.yaml"
    engine = fetch(engine_url)
    files = json.loads(fetch(f"https://api.github.com/repos/containers/podman/contents/pkg/api/server?ref={PODMAN_REV}"))
    entries = [entry for entry in files if entry["name"].startswith("register_")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        sources = dict(zip((entry["name"] for entry in entries), pool.map(fetch, [entry["download_url"] for entry in entries])))
    routes = build_routes(engine, sources, ROOT)
    output = ROOT / "app/internal/cmd/known_api_routes.json"
    output.write_text(render(routes, engine_url))
    print(f"Wrote {len(routes)} routes to {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
