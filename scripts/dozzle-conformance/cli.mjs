#!/usr/bin/env node
// Thin CLI over lib.mjs so run.sh can stay in bash. Reads stdin, writes JSON.
//   cli.mjs find-container <name>     stdin: SSE body      -> {host,id,name,state} or exit 3
//   cli.mjs denied <known-routes.json> stdin: sockguard log -> JSON array of unexpected denials
//   cli.mjs routes                    stdin: sockguard log -> JSON array of route shapes
//   cli.mjs drift <known-routes.json> stdin: sockguard log -> {status,detail,unknown}
import { readFileSync } from "node:fs";
import {
  deniedRecords,
  findContainer,
  observedRoutes,
  parseAccessLog,
  parseSse,
  routeDrift,
} from "./lib.mjs";

const [cmd, arg] = process.argv.slice(2);
const input = readFileSync(0, "utf8");

switch (cmd) {
  case "find-container": {
    const c = findContainer(parseSse(input), arg ?? "");
    if (!c) process.exit(3);
    console.log(JSON.stringify(c));
    break;
  }
  case "denied":
    console.log(
      JSON.stringify(
        deniedRecords(
          parseAccessLog(input),
          arg ? (JSON.parse(readFileSync(arg, "utf8")).expected_denials ?? []) : [],
        ),
      ),
    );
    break;
  case "routes":
    console.log(JSON.stringify(observedRoutes(parseAccessLog(input))));
    break;
  case "drift": {
    const known = JSON.parse(readFileSync(arg, "utf8")).routes;
    console.log(JSON.stringify(routeDrift(observedRoutes(parseAccessLog(input)), known)));
    break;
  }
  default:
    console.error("usage: cli.mjs find-container|denied|routes|drift [arg]");
    process.exit(2);
}
