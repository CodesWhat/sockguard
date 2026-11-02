"use client";

import { Fragment, type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { TERMINAL, type TerminalEvent, type TerminalScene } from "@/app/data/terminal";

// Replays real output recorded from the sockguard binary. The first scene is
// rendered in full on the server, so the page reads without JS. With JS the
// terminal replays that scene (typed commands, streamed output) the first time
// it scrolls into view, and each button below replays one scene. Reduced
// motion never animates: scenes render in full.

const SCENE_LABEL: Record<string, string> = {
  audit: "sockguard serve",
  harvest: "jq harvest",
  match: "sockguard match",
  validate: "sockguard validate",
  enforce: "flip to enforce",
};

const ART = /[▀-▟]/;

type Seg = { t: string; c?: string };

// Split the unclassed segments on `re`, tagging each match with `cls`.
function tag(segs: Seg[], re: RegExp, cls: (m: string) => string): Seg[] {
  const out: Seg[] = [];
  for (const seg of segs) {
    if (seg.c) {
      out.push(seg);
      continue;
    }
    let last = 0;
    for (const m of seg.t.matchAll(re)) {
      const i = m.index ?? 0;
      if (i > last) out.push({ t: seg.t.slice(last, i) });
      out.push({ t: m[0], c: cls(m[0]) });
      last = i + m[0].length;
    }
    if (last < seg.t.length) out.push({ t: seg.t.slice(last) });
  }
  return out;
}

function highlight(s: string): Seg[] {
  let segs: Seg[] = [{ t: s }];
  segs = tag(segs, /<redacted[^>]*>|<hostname>/g, () => "redact");
  if (/^\s*\{/.test(s)) {
    segs = tag(segs, /"[A-Za-z_][\w-]*"(?=:)/g, () => "jk");
    segs = tag(
      segs,
      /"(?:would_deny|deny|denied|WARN|ERROR|unauthorized|timestamp-skew|replay|unknown-key|invalid-signature)"/g,
      (m) => (m === '"WARN"' ? "warn" : "bad"),
    );
    segs = tag(segs, /"(?:allowed|allow|INFO)"/g, () => "ok");
  } else if (/^(< |HTTP)/.test(s)) {
    segs = tag(segs, /40[13] [A-Za-z ]+/g, () => "bad");
    segs = tag(segs, /200 OK/g, () => "ok");
  } else if (/^\s*Decision:/.test(s)) {
    segs = tag(segs, /(?:allow|deny)\s*$/g, (m) => (m.startsWith("allow") ? "ok" : "bad"));
  } else if (/^\s*[✓✗]/.test(s)) {
    segs = tag(segs, /^\s*[✓✗]/g, (m) => (m.includes("✓") ? "ok" : "bad"));
  } else if (/^[45]\d\d$/.test(s)) {
    segs = [{ t: s, c: "bad" }];
  } else if (/^2\d\d$/.test(s)) {
    segs = [{ t: s, c: "ok" }];
  }
  return segs;
}

function Line({ ev, typed, caret }: { ev: TerminalEvent; typed?: number; caret?: boolean }) {
  if (ev.k === "cmd") {
    const text = typed === undefined ? ev.s : ev.s.slice(0, typed);
    return (
      <div className={`tl cmd${ev.p === "client" ? " client" : ""}`}>
        <span className="ps" aria-hidden="true">
          $
        </span>
        <span>
          {text}
          {caret ? <span className="caret" aria-hidden="true" /> : null}
        </span>
      </div>
    );
  }
  if (ev.k === "note") return <div className="tl note">{ev.s}</div>;
  const art = ART.test(ev.s);
  let body: ReactNode = " ";
  if (ev.s) {
    body = highlight(ev.s).map((seg, i) => {
      const key = `${i}-${seg.t.length}`;
      return seg.c ? (
        <span key={key} className={seg.c}>
          {seg.t}
        </span>
      ) : (
        <Fragment key={key}>{seg.t}</Fragment>
      );
    });
  }
  return <div className={`tl ${art ? "art" : "out"}`}>{body}</div>;
}

const sceneById = (id: string) => TERMINAL.scenes.find((s) => s.id === id) as TerminalScene;
const flatten = (scenes: TerminalScene[]) => scenes.flatMap((s) => s.events);
const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export function RecordedTerminal() {
  const first = sceneById("audit");
  const [active, setActive] = useState(first.id);
  const [shown, setShown] = useState<TerminalEvent[]>(() => flatten([first]));
  const [typing, setTyping] = useState<{ ev: TerminalEvent; n: number } | null>(null);
  const [live, setLive] = useState("");
  const [state, setState] = useState<"idle" | "playing" | "done">("idle");
  const rootRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const token = useRef(0);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const follow = useRef(false);

  // biome-ignore lint/correctness/useExhaustiveDependencies: scroll after every render of new lines
  useEffect(() => {
    const el = bodyRef.current;
    if (el && follow.current) el.scrollTop = el.scrollHeight;
  }, [shown, typing]);

  const play = useCallback((scene: TerminalScene) => {
    const my = ++token.current;
    clearTimeout(timer.current);
    follow.current = true;
    if (reducedMotion()) {
      setTyping(null);
      setShown(scene.events);
      setState("done");
      return;
    }
    setShown([]);
    setTyping(null);
    setState("playing");
    const queue = scene.events;
    let i = 0;
    const step = () => {
      if (my !== token.current) return;
      if (i >= queue.length) {
        setTyping(null);
        setState("done");
        return;
      }
      const ev = queue[i++];
      if (ev.k !== "cmd") {
        setShown((s) => [...s, ev]);
        timer.current = setTimeout(step, ART.test(ev.s) ? 22 : ev.s.startsWith("{") ? 70 : 34);
        return;
      }
      const speed = ev.p === "client" ? 7 : 22;
      let n = 0;
      const typeNext = () => {
        if (my !== token.current) return;
        if (n >= ev.s.length) {
          setTyping(null);
          setShown((s) => [...s, ev]);
          timer.current = setTimeout(step, 220);
          return;
        }
        n = Math.min(ev.s.length, n + 1 + (Math.random() < 0.25 ? 1 : 0));
        setTyping({ ev, n });
        timer.current = setTimeout(typeNext, speed + Math.random() * speed);
      };
      typeNext();
    };
    step();
  }, []);

  // Autoplay the opening scene once, when the terminal first scrolls into view.
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    if (reducedMotion()) {
      follow.current = true;
      setShown((s) => [...s]);
      setState("done");
      return;
    }
    if (!("IntersectionObserver" in window)) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          io.disconnect();
          play(first);
        }
      },
      { threshold: 0.2 },
    );
    io.observe(root);
    return () => {
      io.disconnect();
      token.current++;
      clearTimeout(timer.current);
    };
  }, [first, play]);

  const pick = (scene: TerminalScene) => {
    setActive(scene.id);
    setLive(`Playing ${scene.title}`);
    play(scene);
  };

  const scene = sceneById(active);
  const title = `sockguard ${TERMINAL.version} · ${active === first.id ? "discovery preset" : scene.title}`;

  return (
    <section
      className="term"
      id="term"
      ref={rootRef}
      aria-label="Recorded terminal session"
      data-state={state}
    >
      <div className="term-bar">
        <span className="dots" aria-hidden="true">
          <i />
          <i />
          <i />
        </span>
        <b>{title}</b>
      </div>
      <div
        className="term-body"
        ref={bodyRef}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable log must be keyboard reachable
        tabIndex={0}
        role="log"
        aria-label="Terminal output, scrollable"
        aria-live="off"
      >
        {shown.map((ev, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: append-only list of static lines
          <Line key={i} ev={ev} />
        ))}
        {typing ? <Line ev={typing.ev} typed={typing.n} caret /> : null}
      </div>
      {/* biome-ignore lint/a11y/useSemanticElements: a button row, not a form control group */}
      <div className="term-cmds" role="group" aria-label="Replay a recorded scene">
        {TERMINAL.scenes.map((s) => (
          <button
            key={s.id}
            type="button"
            className="tcmd"
            aria-pressed={active === s.id}
            onClick={() => pick(s)}
          >
            <span className="ps" aria-hidden="true">
              $
            </span>
            <span>{SCENE_LABEL[s.id] ?? s.title}</span>
          </button>
        ))}
      </div>
      <p className="term-cap">Recorded from sockguard v{TERMINAL.version} · local stub</p>
      <details className="term-more">
        <summary>Provenance and redactions</summary>
        <div>
          Real output from the binary built from the v{TERMINAL.version} tag (commit{" "}
          {TERMINAL.commit}), recorded {TERMINAL.date}. The upstream is a local stub on a unix
          socket, not a Docker daemon, and the requests are curl through the proxy. Configs are the
          repo&apos;s <code>discovery.yaml</code> and <code>portwing.yaml</code> with only the
          socket paths changed to /tmp. Stdout and stderr are interleaved in arrival order. The
          enforce scene flips <code>mode: audit</code> to <code>mode: enforce</code> and restarts;
          its startup banner is omitted. No redactions were needed (paths are /tmp scratch).
        </div>
      </details>
      <p className="sr" aria-live="polite">
        {live}
      </p>
    </section>
  );
}
