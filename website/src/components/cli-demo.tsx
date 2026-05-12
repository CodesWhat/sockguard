"use client";

import { useCallback, useEffect, useRef, useState } from "react";

// ───────────────────────────────────────────────────────────────
// Terminal color tokens. Tailwind-free JSX so the component is
// self-contained and easy to drop anywhere. The container sets
// base fg/bg; tokens below are evaluated inside that context.
// ───────────────────────────────────────────────────────────────
const tok = {
  dim: "opacity-60",
  bold: "font-semibold text-neutral-900 dark:text-neutral-50",
  green: "text-emerald-600 dark:text-emerald-400",
  red: "text-rose-600 dark:text-rose-400",
  yellow: "text-amber-600 dark:text-amber-400",
  cyan: "text-cyan-600 dark:text-cyan-400",
  magenta: "text-fuchsia-600 dark:text-fuchsia-400",
} as const;

type RawFrameLine =
  | { kind: "text"; content: React.ReactNode }
  | { kind: "art"; content: string }
  | { kind: "blank" };

type FrameLine = RawFrameLine & { id: string };

type RawFrame = {
  comment?: string;
  command: string;
  output: RawFrameLine[];
  pauseAfterMs?: number;
};

type Frame = Omit<RawFrame, "output"> & { output: FrameLine[] };

// TERMINAL_COLS is the notional terminal width the CliDemo pretends
// to run inside. The real CLI detects the live tty's column count
// via TIOCGWINSZ and pads the banner to center the dog; this demo
// mirrors that exact logic against a fixed 100-col target so the
// visual result matches what a user running `sockguard serve` in a
// 100×32 terminal would see. Bump this if the real CLI's banner padding ever changes width.
const TERMINAL_COLS = 100;

// padArt mirrors banner.centerArt from the Go side — left-pads every
// non-empty row by the same number of spaces so the full block is
// centered inside a `cols`-wide terminal. Narrow targets return the
// art unchanged, same fallback as the real binary.
function padArt(block: string, cols: number): string {
  const lines = block.split("\n");
  let max = 0;
  for (const line of lines) {
    if (line.length > max) max = line.length;
  }
  if (cols <= max) return block;
  const pad = " ".repeat((cols - max) >> 1);
  return lines.map((l) => (l === "" ? l : pad + l)).join("\n");
}

// The real sockguard serve banner. Kept in sync with
// app/internal/banner/banner.go so the demo stays true-to-life.
const RAW_ART = `                ...                              ...
         .=+=..                           .=+=..
       ..=--**..                        ..=*--+.:
       .:=-:=#*:..                     .:*#+:--=..
      .:+--..+++=:..:..................=+++:.:-=:.
     :.-=--...=+=:.-+***************=::-++:..:-=+..
     ..==--....:***++++++++++++####*+***=... ---+:.
     ..==--..-+++++++++++++++++++***++++++=:.:--+:.
     ..:+=::++++++++++++++++++++++++++++++++=.-=+..
      ....:++++%@%++#@%++++++++++@@%**#@%++++=.. ..
        ..+++++*%@@@@@*+++++++++++%@@@@@*+++++-.:
       :.:=+++++#@@@@#*++.++++=-++%@@@@#+++++==..
       ..-=++++%@@#*@%#:.:::::::.+%@**@@@*+++==:..
      ..:++++++++++::%@%..:**=:.-%@=.=+++++++++=...
     ..=+==+=.:%@@%@@@.==.... .:=:-@@%@@@+..+===+:..
    ..:+===.*@@%:@*+@@:..:+...+...*@@:@*=@@@-:===+..
    ..====.#%%@@%:@==@@@*.. ...:%@@%:@=*@@@#%::===:.:
    ...==-.#%-%%@@@@@%%%%%%=.*%%%%%@@@@@@%**%=.==-..:
     ...:..+*#:.:-----::=*:::=*:::-----::.*%*..=-...
       ..-====+#@*.#@@=:-:...::=:#@@@.=:#%*:.......
     ..:+**%@#*===*+.:#%@@@@@@@@%=:::*%#:#@@@@%=..
    ..+%#*====+#@#===#@@@@@@@@@@@@=%%%@@%:+@@@@@@:.
   ..*@@@@@@@%+==+%%+==%@%%%%%%%%%+*@@@@@@*.*%%%%:.
  ..#@%%@@@@@@@@%===%@=-=+:........:%@@@@@@@=.....:
  ..**...:*#%@@@@@@===%=.:**#***++=.#@@@@@@@@@=..
   ..**:.....=%%@@@@*-..-==========.*%@@@@@@@@@-.:
    ...=#*:.. .-%%%%*.......:::... ..#%%%@@@@%%:.:
       ...:*%#=:-%%-..     :...:    ..:*#%%%#=...
           .........                  ... . ..`;

// ART is the banner string after runtime-style centering has been
// applied — what `sockguard serve` would print into a 100-col tty.
// Computed once at module load so React renders cheap.
const ART = padArt(RAW_ART, TERMINAL_COLS);

// ───────────────────────────────────────────────────────────────
// Output helpers — build lines that mirror what the real CLI
// prints, using the Tailwind color tokens above.
// ───────────────────────────────────────────────────────────────
const dim = (s: string) => <span className={tok.dim}>{s}</span>;
const bold = (s: string) => <span className={tok.bold}>{s}</span>;
const green = (s: string) => <span className={tok.green}>{s}</span>;
const red = (s: string) => <span className={tok.red}>{s}</span>;

const CHECK = "✓";
const CROSS = "✗";

// ───────────────────────────────────────────────────────────────
// The script. Each frame is one beat of the CLI tour. Raw frames
// are defined without the `id` field on output lines; the block at
// the bottom of this section stamps stable sequential IDs onto
// every line so React keys never fall back to array indexes.
// ───────────────────────────────────────────────────────────────
const RAW_FRAMES: RawFrame[] = [
  {
    comment: "What version are we running?",
    command: "sockguard version",
    output: [
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {bold("sockguard")} {dim("v0.3.1")}
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("commit")} {"  "}a8c742f
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("built ")} {"  "}2026-04-13T21:18:11Z
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("go    ")} {"  "}go1.26.3
          </>
        ),
      },
    ],
    pauseAfterMs: 1600,
  },
  {
    comment: "Show me the rules this config compiles to.",
    command: "sockguard validate --config ./sockguard.yaml",
    output: [
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("Config  ")}
            {"  "}./sockguard.yaml
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("Listen  ")}
            {"  "}unix:/var/run/sockguard/sockguard.sock
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("Upstream")}
            {"  "}/var/run/docker.sock
          </>
        ),
      },
      { kind: "blank" },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {bold("Rules (6)")}
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"    "}
            {green(CHECK)} {green("allow")} {"  GET    /_ping"}
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"    "}
            {green(CHECK)} {green("allow")} {"  GET    /version"}
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"    "}
            {green(CHECK)} {green("allow")} {"  GET    /containers/json"}
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"    "}
            {green(CHECK)} {green("allow")} {"  GET    /containers/*/json"}
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"    "}
            {red(CROSS)} {red("deny ")} {"  POST   /containers/*/exec"}
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"    "}
            {red(CROSS)} {red("deny ")} {"  *      /**"}
          </>
        ),
      },
      { kind: "blank" },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {green(CHECK)} {green("validation passed")}
          </>
        ),
      },
    ],
    pauseAfterMs: 2400,
  },
  {
    comment: "Would sockguard let Traefik list containers?",
    command: "sockguard match -X GET --path /v1.45/containers/json",
    output: [
      {
        kind: "text",
        content: <>{dim("Config:         ")} ./sockguard.yaml</>,
      },
      {
        kind: "text",
        content: <>{dim("Method:         ")} GET</>,
      },
      {
        kind: "text",
        content: <>{dim("Path:           ")} /v1.45/containers/json</>,
      },
      {
        kind: "text",
        content: <>{dim("Normalized path:")} /containers/json</>,
      },
      { kind: "blank" },
      {
        kind: "text",
        content: (
          <>
            {dim("Decision:       ")} {green("allow")}
          </>
        ),
      },
      {
        kind: "text",
        content: <>{dim("Matched rule:   ")} #3</>,
      },
      {
        kind: "text",
        content: (
          <>
            {dim("Rule:           ")} {green("allow")} GET /containers/json
          </>
        ),
      },
    ],
    pauseAfterMs: 2000,
  },
  {
    comment: "What if Portainer tries to exec into a container?",
    command: "sockguard match -X POST --path /containers/abc/exec",
    output: [
      {
        kind: "text",
        content: <>{dim("Config:         ")} ./sockguard.yaml</>,
      },
      {
        kind: "text",
        content: <>{dim("Method:         ")} POST</>,
      },
      {
        kind: "text",
        content: <>{dim("Path:           ")} /containers/abc/exec</>,
      },
      {
        kind: "text",
        content: <>{dim("Normalized path:")} /containers/abc/exec</>,
      },
      { kind: "blank" },
      {
        kind: "text",
        content: (
          <>
            {dim("Decision:       ")} {red("deny")}
          </>
        ),
      },
      {
        kind: "text",
        content: <>{dim("Matched rule:   ")} #5</>,
      },
      {
        kind: "text",
        content: (
          <>
            {dim("Rule:           ")} {red("deny")} POST /containers/*/exec
          </>
        ),
      },
      {
        kind: "text",
        content: <>{dim("Reason:         ")} exec disabled</>,
      },
    ],
    pauseAfterMs: 2200,
  },
  {
    comment: "And deleting an image? Nothing explicit — default deny.",
    command: "sockguard match -X DELETE --path /images/sha256:abc",
    output: [
      {
        kind: "text",
        content: <>{dim("Config:         ")} ./sockguard.yaml</>,
      },
      {
        kind: "text",
        content: <>{dim("Method:         ")} DELETE</>,
      },
      {
        kind: "text",
        content: <>{dim("Path:           ")} /images/sha256:abc</>,
      },
      {
        kind: "text",
        content: <>{dim("Normalized path:")} /images/sha256:abc</>,
      },
      { kind: "blank" },
      {
        kind: "text",
        content: (
          <>
            {dim("Decision:       ")} {red("deny")}
          </>
        ),
      },
      {
        kind: "text",
        content: <>{dim("Matched rule:   ")} none</>,
      },
      {
        kind: "text",
        content: <>{dim("Reason:         ")} no matching allow rule</>,
      },
    ],
    pauseAfterMs: 2400,
  },
  {
    comment: "Time to actually run it.",
    command: "sockguard serve --config ./sockguard.yaml",
    output: [
      { kind: "art", content: ART },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {bold("sockguard")} v0.3.1{"  "}
            {dim("(commit a8c742f, built 2026-04-13T21:18:11Z, go1.26.3)")}
          </>
        ),
      },
      { kind: "blank" },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("listen   ")} unix:/var/run/sockguard/sockguard.sock
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("upstream ")} /var/run/docker.sock
          </>
        ),
      },
      {
        kind: "text",
        content: (
          <>
            {"  "}
            {dim("rules    ")} 6{"  "}
            {dim("(log text/info, access=on)")}
          </>
        ),
      },
      { kind: "blank" },
      ...buildLogLines(),
    ],
    pauseAfterMs: 5000,
  },
];

// buildLogLines builds the fake sockguard runtime access log stream
// that plays under the serve banner so it looks like the proxy is
// actually handling traffic, not a dead screenshot.
function buildLogLines(): RawFrameLine[] {
  type LogEntry = {
    level: "INFO" | "WARN";
    msg: string;
    fields: Array<[string, string]>;
  };
  // Field order and field names mirror sockguard's real access log
  // from app/internal/logging/access.go: allows log `msg="request"`
  // at INFO with method/path/status/latency_ms/bytes/client, denies
  // log `msg="request_denied"` at WARN with an extra rule+reason.
  // The "sockguard started" boot line carries version/listen/
  // upstream/rules/log_level per app/internal/cmd/serve.go.
  const entries: LogEntry[] = [
    {
      level: "INFO",
      msg: "sockguard started",
      fields: [
        ["version", "v0.3.1"],
        ["listen", "unix:/var/run/sockguard/sockguard.sock"],
        ["upstream", "/var/run/docker.sock"],
        ["rules", "6"],
        ["log_level", "info"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/_ping"],
        ["status", "200"],
        ["latency_ms", "0.412"],
        ["bytes", "2"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/v1.45/version"],
        ["status", "200"],
        ["latency_ms", "1.823"],
        ["bytes", "713"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/v1.45/containers/json"],
        ["status", "200"],
        ["latency_ms", "6.104"],
        ["bytes", "4081"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        [
          "path",
          "/v1.45/containers/json?filters=%7B%22label%22%3A%5B%22traefik.enable%3Dtrue%22%5D%7D",
        ],
        ["status", "200"],
        ["latency_ms", "3.917"],
        ["bytes", "2411"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/v1.45/containers/a3f1b9c/json"],
        ["status", "200"],
        ["latency_ms", "2.641"],
        ["bytes", "3127"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/_ping"],
        ["status", "200"],
        ["latency_ms", "0.388"],
        ["bytes", "2"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "WARN",
      msg: "request_denied",
      fields: [
        ["method", "POST"],
        ["path", "/v1.45/containers/a3f1b9c/exec"],
        ["decision", "deny"],
        ["rule", "5"],
        ["reason", "exec disabled"],
        ["status", "403"],
        ["latency_ms", "0.094"],
        ["bytes", "73"],
        ["client", "10.0.4.91:41218"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/v1.45/events"],
        ["status", "200"],
        ["latency_ms", "1.512"],
        ["bytes", "0"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/v1.45/containers/json"],
        ["status", "200"],
        ["latency_ms", "4.731"],
        ["bytes", "4081"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "WARN",
      msg: "request_denied",
      fields: [
        ["method", "DELETE"],
        ["path", "/v1.45/images/sha256:bc3e..."],
        ["decision", "deny"],
        ["rule", "6"],
        ["reason", "no matching allow rule"],
        ["status", "403"],
        ["latency_ms", "0.087"],
        ["bytes", "94"],
        ["client", "10.0.4.91:41218"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/v1.45/containers/a3f1b9c/json"],
        ["status", "200"],
        ["latency_ms", "3.018"],
        ["bytes", "3127"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/_ping"],
        ["status", "200"],
        ["latency_ms", "0.402"],
        ["bytes", "2"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "GET"],
        ["path", "/v1.45/containers/json"],
        ["status", "200"],
        ["latency_ms", "4.216"],
        ["bytes", "4081"],
        ["client", "172.17.0.4:52104"],
      ],
    },
    {
      level: "INFO",
      msg: "request",
      fields: [
        ["method", "HEAD"],
        ["path", "/v1.45/containers/a3f1b9c/json"],
        ["status", "200"],
        ["latency_ms", "1.812"],
        ["bytes", "0"],
        ["client", "172.17.0.4:52104"],
      ],
    },
  ];

  // Timestamps cascade a few ms apart so the eye registers them as a
  // live stream rather than a bulk dump.
  let t = new Date("2026-04-13T21:18:48.803Z").getTime();
  return entries.map((e) => {
    t += 120 + Math.floor(Math.random() * 180);
    const iso = new Date(t).toISOString();
    const levelCls = e.level === "INFO" ? tok.cyan : tok.yellow;
    return {
      kind: "text",
      content: (
        <span className="whitespace-nowrap text-[0.72rem]">
          <span className={tok.dim}>time={iso}</span> <span className={tok.dim}>level=</span>
          <span className={levelCls}>{e.level}</span> <span className={tok.dim}>msg=</span>
          &quot;{e.msg}&quot;{" "}
          {e.fields.map(([k, v]) => (
            <span key={k}>
              <span className={tok.dim}>{k}=</span>
              {v}{" "}
            </span>
          ))}
        </span>
      ),
    } as RawFrameLine;
  });
}

// Stamp stable sequential IDs onto every output line so React keys
// don't fall back to the array index (which biome's noArrayIndexKey
// rule rightly flags). Generated once at module load — the frames
// array never mutates at runtime, so the IDs stay stable across
// re-renders for the full lifetime of the component.
const frames: Frame[] = RAW_FRAMES.map((f, fi) => ({
  ...f,
  output: f.output.map((line, li) => ({
    ...line,
    id: `f${fi}-l${li}`,
  })),
}));

// ───────────────────────────────────────────────────────────────
// Component
// ───────────────────────────────────────────────────────────────
type Props = {
  className?: string;
  typeMs?: number; // ms per character while typing
  lineMs?: number; // ms between each output line reveal
  autoStart?: boolean;
};

type RunState = {
  frameIdx: number;
  typedChars: number; // how far into frames[frameIdx].command
  revealedLines: number; // how many output lines are visible
  playing: boolean;
  speed: number; // 1, 1.5, 2
};

export function CliDemo({ className, typeMs = 35, lineMs = 55, autoStart = true }: Props) {
  const [state, setState] = useState<RunState>({
    frameIdx: 0,
    typedChars: 0,
    revealedLines: 0,
    playing: autoStart,
    speed: 1,
  });

  const reset = useCallback(() => {
    setState({
      frameIdx: 0,
      typedChars: 0,
      revealedLines: 0,
      playing: autoStart,
      speed: 1,
    });
  }, [autoStart]);

  // Driver effect — walks the state machine one step per tick. The
  // four phases per frame are: typing the command → holding the fully
  // typed prompt → cascading output lines one at a time → pausing on
  // the finished frame → advancing.
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (!state.playing) {
      return;
    }
    const frame = frames[state.frameIdx];
    if (!frame) {
      // End of tour — wait a beat, then loop back to the top.
      timerRef.current = setTimeout(() => {
        setState((s) => ({
          ...s,
          frameIdx: 0,
          typedChars: 0,
          revealedLines: 0,
        }));
      }, 1500 / state.speed);
      return () => {
        if (timerRef.current) clearTimeout(timerRef.current);
      };
    }
    // Phase 1: typing the command character-by-character.
    if (state.typedChars < frame.command.length) {
      timerRef.current = setTimeout(() => {
        setState((s) => ({ ...s, typedChars: s.typedChars + 1 }));
      }, typeMs / state.speed);
      return () => {
        if (timerRef.current) clearTimeout(timerRef.current);
      };
    }
    // Phase 2 + 3: hold for a beat after typing, then cascade lines.
    if (state.revealedLines < frame.output.length) {
      const isFirstLine = state.revealedLines === 0;
      const delay = isFirstLine ? 280 / state.speed : lineMs / state.speed;
      timerRef.current = setTimeout(() => {
        setState((s) => ({ ...s, revealedLines: s.revealedLines + 1 }));
      }, delay);
      return () => {
        if (timerRef.current) clearTimeout(timerRef.current);
      };
    }
    // Phase 4: all output shown, hold for pauseAfterMs, then advance.
    timerRef.current = setTimeout(
      () => {
        setState((s) => ({
          ...s,
          frameIdx: s.frameIdx + 1,
          typedChars: 0,
          revealedLines: 0,
        }));
      },
      (frame.pauseAfterMs ?? 1500) / state.speed,
    );
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [state, typeMs, lineMs]);

  const currentFrame = frames[state.frameIdx];
  const typedCommand = currentFrame ? currentFrame.command.slice(0, state.typedChars) : "";
  const showCursor = state.playing;
  const visibleLines = currentFrame ? currentFrame.output.slice(0, state.revealedLines) : [];

  // Auto-scroll the terminal body to the bottom whenever a new line
  // is revealed. Content flows top-down; when it exceeds the body
  // height, the oldest content scrolls off the top and the newest
  // line stays pinned at the bottom edge — the tail -f feel. At the
  // start of a new frame (revealedLines === 0) we reset to the top
  // so the beat opens with the prompt in view instead of mid-scroll.
  const bodyRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    if (state.revealedLines === 0) {
      el.scrollTop = 0;
      return;
    }
    // Referencing frameIdx here keeps biome's exhaustive-deps rule
    // happy without changing observable behavior; the value is used
    // as part of the scroll decision indirectly (new frame → reset).
    void state.frameIdx;
    el.scrollTop = el.scrollHeight;
  }, [state.frameIdx, state.revealedLines]);

  return (
    <div className={`w-full ${className ?? ""}`}>
      <div className="overflow-hidden rounded-xl border border-neutral-300 bg-neutral-50 shadow-2xl dark:border-neutral-800 dark:bg-neutral-950">
        {/* macOS window chrome */}
        <div className="flex items-center gap-2 border-b border-neutral-300 bg-neutral-200 px-4 py-3 dark:border-neutral-800 dark:bg-neutral-900">
          <span className="size-3 rounded-full bg-red-500" />
          <span className="size-3 rounded-full bg-yellow-500" />
          <span className="size-3 rounded-full bg-green-500" />
          <span className="ml-3 select-none text-xs text-neutral-500 dark:text-neutral-400">
            sockguard — zsh
          </span>
          <div className="ml-auto flex items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
            <button
              type="button"
              onClick={() => setState((s) => ({ ...s, playing: !s.playing }))}
              className="rounded border border-neutral-400 px-2 py-0.5 hover:border-fuchsia-500 hover:text-fuchsia-600 dark:border-neutral-700 dark:hover:text-fuchsia-400"
            >
              {state.playing ? "pause" : "play"}
            </button>
            <button
              type="button"
              onClick={reset}
              className="rounded border border-neutral-400 px-2 py-0.5 hover:border-fuchsia-500 hover:text-fuchsia-600 dark:border-neutral-700 dark:hover:text-fuchsia-400"
            >
              restart
            </button>
            {[1, 1.5, 2].map((speed) => (
              <button
                key={speed}
                type="button"
                onClick={() => setState((s) => ({ ...s, speed }))}
                className={`rounded border px-2 py-0.5 ${
                  state.speed === speed
                    ? "border-fuchsia-500 text-fuchsia-600 dark:text-fuchsia-400"
                    : "border-neutral-400 hover:border-fuchsia-500 dark:border-neutral-700"
                }`}
              >
                {speed}×
              </button>
            ))}
          </div>
        </div>

        {/* Terminal body. Content flows top-down from the comment
            line, and the effect auto-scrolls the body so the newest
            revealed line is always pinned at the bottom edge when
            the content overflows. Scrollbar hidden via arbitrary CSS
            to keep the terminal chrome clean. */}
        <div
          ref={bodyRef}
          className="h-[34rem] overflow-y-auto px-5 py-4 font-mono text-sm leading-[1.6] text-neutral-800 [scrollbar-width:none] dark:text-neutral-200 [&::-webkit-scrollbar]:hidden"
        >
          {currentFrame && (
            <div key={state.frameIdx}>
              {currentFrame.comment && (
                <div className={`${tok.dim} ${tok.yellow}`}># {currentFrame.comment}</div>
              )}
              <div>
                <span className={tok.green}>$</span>{" "}
                <span className={tok.bold}>{typedCommand}</span>
                {showCursor && state.typedChars < currentFrame.command.length && (
                  <span className="inline-block h-[1.1em] w-[0.55em] translate-y-[0.15em] bg-neutral-800 dark:bg-neutral-200" />
                )}
              </div>
              {visibleLines.map((line) => {
                if (line.kind === "blank") {
                  return <div key={line.id}>&nbsp;</div>;
                }
                if (line.kind === "art") {
                  return (
                    <pre
                      key={line.id}
                      className={`${tok.cyan} whitespace-pre font-mono text-[0.52rem] leading-[1.02] tracking-normal`}
                    >
                      {line.content}
                    </pre>
                  );
                }
                return (
                  <div key={line.id}>
                    <span>{line.content}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
      <p className="mt-3 text-center text-xs text-neutral-500 dark:text-neutral-400">
        A hand-rendered recreation of the real CLI — every frame mirrors what{" "}
        <code className="rounded bg-neutral-200 px-1 dark:bg-neutral-800">sockguard</code> actually
        prints. Use the controls above to pause, restart, or change speed.
      </p>
    </div>
  );
}
