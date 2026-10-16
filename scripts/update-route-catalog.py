#!/usr/bin/env python3
"""Refresh advisory route facts from pinned upstream API sources."""

import concurrent.futures
import json
import pathlib
import re
import urllib.request

ENGINE_REV = "3f38b15147b14ce0ce7b11558a1aa9e9f14db103"
PODMAN_REV = "a859fc66702c23e869c282c63e92d9b6cd264229"
ROOT = pathlib.Path(__file__).resolve().parents[1]


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "sockguard-route-catalog"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode()


def main():
    engine_url = f"https://raw.githubusercontent.com/moby/moby/{ENGINE_REV}/api/swagger.yaml"
    engine = fetch(engine_url)
    routes = set()
    current = None
    for line in engine.split("\npaths:\n", 1)[1].splitlines():
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
    files = json.loads(fetch(f"https://api.github.com/repos/containers/podman/contents/pkg/api/server?ref={PODMAN_REV}"))
    urls = [entry["download_url"] for entry in files if entry["name"].startswith("register_")]
    methods = {"Get": "GET", "Head": "HEAD", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Options": "OPTIONS"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for url, source in zip(urls, pool.map(fetch, urls)):
            source = "\n".join(line for line in source.splitlines() if "UnsupportedHandler" not in line)
            registrations = list(re.finditer(r'(?m)^\s*r\.Handle(?:Func)?\((?:VersionedPath\()?"([^"]+)"[^\n]*?\.Methods\(([^\n]*)\)', source))
            if len(registrations) != len(re.findall(r"(?m)^\s*r\.Handle(?:Func)?\(", source)):
                raise ValueError(f"Podman registration format changed in {url}; update the extractor")
            for match in registrations:
                for method in re.findall(r"http\.Method(\w+)", match[2]):
                    if method not in methods:
                        raise ValueError(f"unknown HTTP method {method}")
                    routes.add((methods[method], match[1]))
    # The Engine OpenAPI does not enumerate BuildKit's hijacked/RPC paths.
    for path in ["/session", "/grpc"]:
        routes.add(("POST", path))
    for source in (ROOT / "app/internal/buildkitproto/proto").rglob("*.proto"):
        text = source.read_text()
        package = re.search(r"(?m)^package ([\w.]+);", text)
        if not package:
            continue
        for service, body in re.findall(r"service (\w+)\s*\{(.*?)\n\}", text, re.S):
            for method in re.findall(r"\brpc (\w+)\s*\(", body):
                routes.add(("POST", f"/{package[1]}.{service}/{method}"))
    registry = (ROOT / "app/internal/buildkitproxy/registry.go").read_text()
    for service, method in re.findall(r'\{Endpoint(?:GRPC|Session),\s*"([^"]+)",\s*"([^"]+)"\}', registry):
        routes.add(("POST", f"/{service}/{method}"))
    if len(routes) < 250 or not any(path.startswith("/libpod/") for _, path in routes):
        raise ValueError("upstream route extraction is incomplete")
    document = {
        "sources": {"engine": engine_url, "podman": f"https://github.com/containers/podman/tree/{PODMAN_REV}/pkg/api/server", "buildkit": "app/internal/buildkitproto/proto and app/internal/buildkitproxy/registry.go"},
        "routes": [{"method": method, "path": path} for method, path in sorted(routes)],
    }
    output = ROOT / "app/internal/cmd/known_api_routes.json"
    output.write_text(json.dumps(document, indent=2) + "\n")
    print(f"Wrote {len(routes)} routes to {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
