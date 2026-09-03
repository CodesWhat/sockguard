"use strict";

const net = require("node:net");

function parseResponseHead(head) {
  const lines = head.split("\r\n");
  const statusMatch = /^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s|$)/i.exec(lines[0] || "");
  let reason = null;

  for (const line of lines.slice(1)) {
    const separator = line.indexOf(":");
    if (separator === -1) continue;
    if (line.slice(0, separator).trim().toLowerCase() === "x-portwing-reason") {
      reason = line.slice(separator + 1).trim() || null;
      break;
    }
  }

  return {
    event: "portwing-response",
    status: statusMatch ? Number(statusMatch[1]) : 0,
    reason,
  };
}

function logEvent(event) {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

function startProxy() {
  const upstreamHost = process.env.TT_PROXY_UPSTREAM_HOST;
  const upstreamPort = Number(process.env.TT_PROXY_UPSTREAM_PORT || "4100");
  const listenPort = Number(process.env.TT_PROXY_LISTEN_PORT || "4100");

  if (!upstreamHost || !Number.isInteger(upstreamPort) || !Number.isInteger(listenPort)) {
    throw new Error("valid TT_PROXY_UPSTREAM_HOST, TT_PROXY_UPSTREAM_PORT, and TT_PROXY_LISTEN_PORT are required");
  }

  const server = net.createServer((client) => {
    const upstream = net.createConnection({ host: upstreamHost, port: upstreamPort });
    let responseHead = Buffer.alloc(0);
    let responseObserved = false;

    client.pipe(upstream);
    upstream.pipe(client);

    upstream.on("data", (chunk) => {
      if (responseObserved) return;
      responseHead = Buffer.concat([responseHead, chunk], Math.min(responseHead.length + chunk.length, 65536));
      const end = responseHead.indexOf("\r\n\r\n");
      if (end !== -1) {
        responseObserved = true;
        logEvent(parseResponseHead(responseHead.subarray(0, end).toString("latin1")));
        responseHead = Buffer.alloc(0);
      } else if (responseHead.length >= 65536) {
        responseObserved = true;
        logEvent({ event: "portwing-response", status: 0, reason: null });
      }
    });

    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
  });

  server.on("error", (error) => {
    process.stderr.write(`identity header observer failed: ${error.message}\n`);
    process.exitCode = 1;
  });
  server.listen(listenPort, "0.0.0.0", () => {
    logEvent({ event: "identity-header-proxy-listening", listenPort, upstreamHost, upstreamPort });
  });
}

module.exports = { parseResponseHead };

if (require.main === module) {
  startProxy();
}
