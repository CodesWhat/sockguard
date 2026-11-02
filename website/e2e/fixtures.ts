import { test as base, expect, type Page } from "@playwright/test";

const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost"]);

// 1x1 transparent SVG: stands in for badge and chart images from third-party
// hosts, so a slow or flaky shields.io/qlty.sh never decides a test result.
const STUB_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="20"><rect width="80" height="20" fill="#888"/></svg>';

type PageIssue = { kind: "console" | "pageerror" | "csp"; text: string };

type Fixtures = {
  // Every console error, uncaught exception and CSP violation seen so far.
  issues: PageIssue[];
  // Third-party hosts the page tried to reach (all stubbed, none hit the network).
  externalHosts: Set<string>;
};

type Watch = { issues: PageIssue[]; hosts: Set<string> };
const watches = new WeakMap<Page, Watch>();

export const test = base.extend<Fixtures>({
  // Every test gets the third-party stubs and the issue collector without
  // asking for them. `issues` and `externalHosts` just expose what this
  // override collected.
  page: async ({ page }, use) => {
    const issues: PageIssue[] = [];
    const hosts = new Set<string>();
    watches.set(page, { issues, hosts });

    page.on("console", (msg) => {
      if (msg.type() === "error") issues.push({ kind: "console", text: msg.text() });
    });
    page.on("pageerror", (err) => issues.push({ kind: "pageerror", text: err.message }));
    await page.exposeFunction("__reportCsp", (text: string) => issues.push({ kind: "csp", text }));
    await page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (e) => {
        (window as unknown as { __reportCsp: (t: string) => void }).__reportCsp(
          `${e.violatedDirective} blocked ${e.blockedURI}`,
        );
      });
    });

    await page.route(
      (url) => !LOCAL_HOSTS.has(url.hostname),
      (route) => {
        const request = route.request();
        hosts.add(new URL(request.url()).hostname);
        if (request.resourceType() === "image") {
          return route.fulfill({ status: 200, contentType: "image/svg+xml", body: STUB_SVG });
        }
        return route.fulfill({ status: 204, body: "" });
      },
    );
    await use(page);
  },

  issues: async ({ page }, use) => {
    await use((watches.get(page) as Watch).issues);
  },

  externalHosts: async ({ page }, use) => {
    await use((watches.get(page) as Watch).hosts);
  },
});

export { expect };
