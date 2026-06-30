"use client";

import { ShieldCheck, Terminal, TriangleAlert, Zap } from "lucide-react";
import { useState } from "react";
import { DockerRunSnippet } from "@/components/docker-run-snippet";
import { SectionHeading } from "@/components/section-heading";
import { YamlBlock } from "@/components/yaml-block";
import { SITE_CONFIG } from "@/lib/site-config";

type Tab = "quick" | "secure";

const TABS: { id: Tab; label: string; icon: typeof Zap }[] = [
  { id: "quick", label: "Quick", icon: Zap },
  { id: "secure", label: "Secure", icon: ShieldCheck },
];

const dockerCompose = `services:
  sockguard:
    image: ${SITE_CONFIG.dockerImage}:latest
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sockguard-socket:/var/run/sockguard
    environment:
      - SOCKGUARD_LISTEN_SOCKET=/var/run/sockguard/sockguard.sock
      - SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true
      - CONTAINERS=1
      - EVENTS=1

  your-app:
    depends_on:
      - sockguard
    volumes:
      - sockguard-socket:/var/run/sockguard:ro
    environment:
      - DOCKER_HOST=unix:///var/run/sockguard/sockguard.sock

volumes:
  sockguard-socket:`;

export function GetStarted() {
  const [tab, setTab] = useState<Tab>("quick");

  return (
    <section className="border-t border-border/60 px-4 py-16">
      <div className="mx-auto max-w-3xl">
        <SectionHeading
          eyebrow="Get running"
          title="Get started in minutes"
          subtitle="Add sockguard to your compose file and point your app at its scoped socket."
          align="right"
        />

        {/* Quick / Secure tab toggle */}
        <div className="mb-5 flex justify-center">
          <div
            role="tablist"
            aria-label="Install method"
            className="inline-flex gap-1 rounded-xl border border-neutral-200 bg-white/60 p-1 backdrop-blur-sm dark:border-neutral-800 dark:bg-neutral-900/60"
            onKeyDown={(e) => {
              const currentIndex = TABS.findIndex((t) => t.id === tab);
              if (e.key === "ArrowRight") {
                e.preventDefault();
                setTab(TABS[(currentIndex + 1) % TABS.length].id);
              } else if (e.key === "ArrowLeft") {
                e.preventDefault();
                setTab(TABS[(currentIndex - 1 + TABS.length) % TABS.length].id);
              } else if (e.key === "Home") {
                e.preventDefault();
                setTab(TABS[0].id);
              } else if (e.key === "End") {
                e.preventDefault();
                setTab(TABS[TABS.length - 1].id);
              }
            }}
          >
            {TABS.map(({ id, label, icon: Icon }) => {
              const active = tab === id;
              return (
                <button
                  key={id}
                  id={`tab-${id}`}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  aria-controls="get-started-panel"
                  tabIndex={active ? 0 : -1}
                  onClick={() => setTab(id)}
                  className={[
                    "flex items-center gap-1.5 rounded-lg px-4 py-1.5 text-sm font-medium transition-colors",
                    active
                      ? "bg-neutral-900 text-white dark:bg-neutral-100 dark:text-neutral-900"
                      : "text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100",
                  ].join(" ")}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        <div role="tabpanel" id="get-started-panel" aria-labelledby={`tab-${tab}`}>
          {tab === "quick" ? (
            <DockerRunSnippet />
          ) : (
            <div className="overflow-hidden rounded-xl border border-neutral-800 bg-neutral-950 shadow-2xl">
              <div className="flex items-center gap-2 border-b border-neutral-800 px-4 py-3">
                <Terminal className="h-4 w-4 text-neutral-500" />
                <span className="text-xs font-medium text-neutral-500">docker-compose.yml</span>
              </div>
              <YamlBlock
                code={dockerCompose}
                className="overflow-x-auto p-6 font-[family-name:var(--font-mono)] text-sm leading-relaxed text-neutral-300"
              />
            </div>
          )}

          <div className="mt-4 flex items-center justify-center gap-2 text-center text-sm">
            {tab === "quick" ? (
              <p className="flex items-center gap-2 text-neutral-500 dark:text-neutral-400">
                <TriangleAlert className="h-4 w-4 shrink-0 text-amber-500" />
                Mounts the Docker socket directly — fine for a local try, not for production.
              </p>
            ) : (
              <p className="flex items-center gap-2 text-neutral-500 dark:text-neutral-400">
                <ShieldCheck className="h-4 w-4 shrink-0 text-amber-500" />
                We own the real socket. Your app only sees what you allow.{" "}
                <a
                  href="/docs"
                  className="font-medium text-neutral-900 underline-offset-4 hover:underline dark:text-neutral-100"
                >
                  Full configuration docs →
                </a>
              </p>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
