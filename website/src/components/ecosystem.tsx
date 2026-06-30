import { ArrowUpRight } from "lucide-react";
import Image from "next/image";
import { SectionHeading } from "@/components/section-heading";
import { SITE_CONFIG } from "@/lib/site-config";

// Ecosystem = CodesWhat family lineup — sockguard (current), drydock, portwing.

const GH = "https://github.com/CodesWhat";

type Project = {
  name: string;
  tagline: string;
  light: string;
  dark: string | null;
  box: string;
  href: string | null;
  current?: boolean;
  invert?: boolean;
};

const PROJECTS: Project[] = [
  {
    name: SITE_CONFIG.name,
    tagline: "Default-deny Docker socket proxy",
    light: "/sockguard-logo.png",
    dark: "/sockguard-logo-dark.png",
    box: "h-24 w-24",
    href: null,
    current: true,
  },
  {
    name: "drydock",
    tagline: "Container update monitoring",
    light: "/whale-logo.png",
    dark: null,
    box: "h-[4.8rem] w-[7.2rem]",
    href: `${GH}/drydock`,
    invert: true,
  },
  {
    name: "portwing",
    tagline: "Secure remote Docker agent",
    light: "/portwing-logo.png",
    dark: "/portwing-logo-dark.png",
    box: "h-24 w-24",
    href: `${GH}/portwing`,
  },
];

const SUB =
  "Sockguard is one piece of a small, focused toolkit — each tool does one job, and they compose.";

const CARD =
  "rounded-2xl border border-neutral-200 bg-white/50 backdrop-blur-sm dark:border-neutral-800 dark:bg-neutral-900/50";

function Mascot({ p }: { p: Project }) {
  if (p.invert) {
    return (
      <span className={`relative block shrink-0 ${p.box}`}>
        <Image
          src={p.light}
          alt={p.name}
          width={128}
          height={128}
          className="h-full w-full object-contain drop-shadow-sm dark:invert"
        />
      </span>
    );
  }
  // Project has separate dark logo
  return (
    <span className={`relative block shrink-0 ${p.box}`}>
      <Image
        src={p.light}
        alt={p.name}
        width={128}
        height={128}
        className="h-full w-full object-contain drop-shadow-sm dark:hidden"
      />
      <Image
        src={p.dark as string}
        alt=""
        aria-hidden="true"
        width={128}
        height={128}
        className="hidden h-full w-full object-contain drop-shadow-sm dark:block"
      />
    </span>
  );
}

function HereChip() {
  return (
    <span className="text-lg leading-none" role="img" aria-label="You're here">
      📍
    </span>
  );
}

function Arrow() {
  return (
    <ArrowUpRight className="h-4 w-4 shrink-0 text-neutral-400 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
  );
}

export function Ecosystem() {
  return (
    <section className="border-t border-border/60 px-4 py-16">
      <div className="mx-auto max-w-5xl px-4">
        <SectionHeading
          eyebrow="Ecosystem"
          title="Part of the CodesWhat stack"
          subtitle={SUB}
          align="left"
        />
        <div className={`${CARD} p-8`}>
          <div className="grid gap-8 sm:grid-cols-3">
            {PROJECTS.map((p) => {
              const body = (
                <>
                  <div className="flex h-28 items-center justify-center">
                    <Mascot p={p} />
                  </div>
                  <div className="mt-4 flex items-center gap-2">
                    <span className="font-mono text-base font-semibold text-neutral-900 dark:text-neutral-100">
                      {p.name}
                    </span>
                    {p.current ? <HereChip /> : <Arrow />}
                  </div>
                  <p className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">{p.tagline}</p>
                </>
              );
              return p.href ? (
                <a
                  key={p.name}
                  href={p.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group flex flex-col items-center text-center"
                >
                  {body}
                </a>
              ) : (
                <div key={p.name} className="flex flex-col items-center text-center">
                  {body}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
