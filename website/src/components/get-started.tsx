"use client";

import { usePathname } from "next/navigation";
import { type KeyboardEvent, type ReactNode, useState } from "react";
import { Icon, type IconName } from "@/components/icon";
import { TrackedLink } from "@/components/tracked-link";
import { captureCta } from "@/lib/analytics";
import { SITE_CONFIG } from "@/lib/site-config";

type Tab = "quick" | "secure";

const TABS: { id: Tab; label: string; icon: IconName }[] = [
  { id: "quick", label: "Quick", icon: "lightning" },
  { id: "secure", label: "Secure", icon: "shield-check" },
];

const K = ({ children }: { children: ReactNode }) => <span className="y-k">{children}</span>;
const V = ({ children }: { children: ReactNode }) => <span className="y-v">{children}</span>;
const C = ({ children }: { children: ReactNode }) => <span className="y-c">{children}</span>;

function Quick() {
  return (
    <div className="code">
      <div className="lab">
        <Icon name="terminal-window" />
        Quick start · docker run
      </div>
      <pre>
        <code>
          <C>$</C> <V>docker run</V> -d \{"\n"}
          {"  "}--name sockguard \{"\n"}
          {"  "}-v /var/run/docker.sock:/var/run/docker.sock:ro \{"\n"}
          {"  "}-v /var/run/sockguard:/var/run/sockguard \{"\n"}
          {"  "}-e SOCKGUARD_LISTEN_SOCKET=/var/run/sockguard/sockguard.sock \{"\n"}
          {"  "}
          <V>{SITE_CONFIG.dockerImage}</V>
        </code>
      </pre>
    </div>
  );
}

function ComposeFile() {
  return (
    <div className="code">
      <div className="lab">
        <Icon name="terminal-window" />
        docker-compose.yml
      </div>
      <pre>
        <code>
          <K>services</K>:{"\n"}
          {"  "}
          <K>sockguard</K>:{"\n"}
          {"    "}
          <K>image</K>: <V>{SITE_CONFIG.dockerImage}:latest</V>
          {"\n"}
          {"    "}
          <K>restart</K>: <V>unless-stopped</V>
          {"\n"}
          {"    "}
          <K>volumes</K>:{"\n"}
          {"      "}- /var/run/docker.sock:/var/run/docker.sock:ro{"\n"}
          {"      "}- ./sockguard.yaml:/etc/sockguard/sockguard.yaml:ro{"\n"}
          {"      "}- sockguard-socket:/var/run/sockguard{"\n"}
          {"    "}
          <K>environment</K>:{"\n"}
          {"      "}- SOCKGUARD_LISTEN_SOCKET=/var/run/sockguard/sockguard.sock{"\n"}
          {"\n"}
          {"  "}
          <K>your-app</K>:{"\n"}
          {"    "}
          <K>depends_on</K>:{"\n"}
          {"      "}- sockguard{"\n"}
          {"    "}
          <K>volumes</K>:{"\n"}
          {"      "}- sockguard-socket:/var/run/sockguard:ro{"\n"}
          {"    "}
          <K>environment</K>:{"\n"}
          {"      "}- DOCKER_HOST=unix:///var/run/sockguard/sockguard.sock{"\n"}
          {"\n"}
          <K>volumes</K>:{"\n"}
          {"  "}
          <K>sockguard-socket</K>:
        </code>
      </pre>
    </div>
  );
}

function PolicyFile() {
  const rule = (path: string) => (
    <>
      {"  "}- match: {"{"} method: GET, path: <V>&quot;{path}&quot;</V> {"}"}
      {"\n"}
      {"    "}
      <K>action</K>: <V>allow</V>
      {"\n"}
    </>
  );
  return (
    <div className="code" style={{ marginTop: 12 }}>
      <div className="lab">
        <Icon name="file-code" />
        sockguard.yaml
      </div>
      <pre>
        <code>
          <C># Default-deny: any request not matched below gets a 403.</C>
          {"\n"}
          <K>rules</K>:{"\n"}
          {rule("/_ping")}
          {rule("/version")}
          {rule("/containers/json")}
          {rule("/containers/*/json")}
          {"  "}- match: {"{"} method: GET, path: <V>&quot;/events&quot;</V> {"}"}
          {"\n"}
          {"    "}
          <K>action</K>: <V>allow</V>
        </code>
      </pre>
    </div>
  );
}

export function GetStarted() {
  const [tab, setTab] = useState<Tab>("quick");
  const pathname = usePathname();

  const activate = (id: Tab, focus = false) => {
    setTab(id);
    captureCta(pathname, `install_${id}`, "get_started");
    if (focus) document.getElementById(`tab-${id}`)?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = TABS.findIndex((t) => t.id === tab);
    let next = -1;
    if (e.key === "ArrowRight") next = (i + 1) % TABS.length;
    else if (e.key === "ArrowLeft") next = (i - 1 + TABS.length) % TABS.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = TABS.length - 1;
    if (next < 0) return;
    e.preventDefault();
    activate(TABS[next].id, true);
  };

  return (
    <>
      <div className="tabs" role="tablist" aria-label="Install method" onKeyDown={onKeyDown}>
        {TABS.map((t) => (
          <button
            key={t.id}
            id={`tab-${t.id}`}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => activate(t.id)}
          >
            <Icon name={t.icon} />
            {t.label}
          </button>
        ))}
      </div>
      <noscript>
        <style>{"#panel-secure[hidden]{display:block;margin-top:24px}"}</style>
      </noscript>
      <div id="panel-quick" role="tabpanel" aria-labelledby="tab-quick" hidden={tab !== "quick"}>
        <Quick />
        <p className="note t-warning">
          <span className="chip">
            <Icon name="warning" />
            Heads up
          </span>
          Mounts the Docker socket directly. Fine for a local try, not for production.
        </p>
      </div>
      <div id="panel-secure" role="tabpanel" aria-labelledby="tab-secure" hidden={tab !== "secure"}>
        <ComposeFile />
        <PolicyFile />
        <p className="note t-success">
          <span className="chip">
            <Icon name="shield-check" />
            Scoped
          </span>
          We own the real socket. Your app only sees what you allow.{" "}
          <TrackedLink href="/docs" ctaId="docs_root" placement="get_started">
            Full configuration docs →
          </TrackedLink>
        </p>
      </div>
    </>
  );
}
