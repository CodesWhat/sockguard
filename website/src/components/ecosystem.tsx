import Image from "next/image";
import { SITE_CONFIG } from "@/lib/site-config";

// Ecosystem = CodesWhat family lineup: sockguard (current), drydock, portwing.

const CODESWHAT = "https://github.com/CodesWhat";

export function Ecosystem() {
  return (
    <>
      <div className="eco">
        <div>
          <Image src="/img/dog-192.webp" alt="" width={96} height={96} loading="lazy" unoptimized />
          <h3>{SITE_CONFIG.name}</h3>
          <p>Default-deny Docker socket proxy</p>
          <span className="chip t-primary">You&apos;re here</span>
        </div>
        <a className="ec" href="https://getdrydock.com" target="_blank" rel="noopener noreferrer">
          <Image
            className="wh"
            src="/img/whale-264.webp"
            alt=""
            width={132}
            height={88}
            loading="lazy"
            unoptimized
          />
          <h3>Drydock</h3>
          <p>Container update monitoring</p>
        </a>
        <a
          className="ec"
          href="https://portwing.codeswhat.com"
          target="_blank"
          rel="noopener noreferrer"
        >
          <Image
            src="/img/pigeon-192.webp"
            alt=""
            width={96}
            height={96}
            loading="lazy"
            unoptimized
          />
          <h3>Portwing</h3>
          <p>Secure remote Docker agent</p>
        </a>
      </div>
      <div className="project">
        <a className="pill" href={CODESWHAT} target="_blank" rel="noopener noreferrer">
          <Image
            src="/img/codeswhat-52.webp"
            alt=""
            width={26}
            height={26}
            loading="lazy"
            unoptimized
          />
          A CodesWhat project
        </a>
      </div>
    </>
  );
}
