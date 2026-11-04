import { readFileSync } from "node:fs";
import { expect, test } from "./fixtures";

// Playwright runs from website/, so this resolves to website/vercel.json.
const vercelCsp = (
  JSON.parse(readFileSync("vercel.json", "utf8")) as {
    headers: { headers: { key: string; value: string }[] }[];
  }
).headers
  .flatMap((rule) => rule.headers)
  .find((h) => h.key === "Content-Security-Policy")?.value;

test.describe("home", () => {
  test("loads with no console errors or CSP violations", async ({ page, issues }) => {
    const response = await page.goto("/");
    expect(response?.status()).toBe(200);
    // The served policy is vercel.json's, minus only upgrade-insecure-requests
    // (see e2e/serve.mjs), which the production file must keep.
    expect(vercelCsp).toContain("upgrade-insecure-requests");
    const served = response?.headers()["content-security-policy"] ?? "";
    expect(served).toBe(
      (vercelCsp ?? "")
        .split(";")
        .map((d) => d.trim())
        .filter((d) => d !== "upgrade-insecure-requests")
        .join("; "),
    );
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    // Let images, hydration and deferred scripts settle before judging.
    await page.waitForLoadState("networkidle");
    expect(issues).toEqual([]);
  });
});

test.describe("mobile menu at 375px", () => {
  test.use({ viewport: { width: 375, height: 812 } });

  test("opens, closes on Escape, outside click and link activation", async ({ page }) => {
    await page.goto("/");
    const menu = page.locator("details.menu");
    const panel = menu.locator(".panel");
    await expect(page.locator("nav.nav")).toBeHidden();

    await menu.locator("summary").click();
    await expect(menu).toHaveJSProperty("open", true);
    await expect(panel).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(menu).toHaveJSProperty("open", false);
    await expect(panel).toBeHidden();

    await menu.locator("summary").click();
    await expect(panel).toBeVisible();
    await page.locator("main").click({ position: { x: 5, y: 300 } });
    await expect(menu).toHaveJSProperty("open", false);

    await menu.locator("summary").click();
    await panel.getByRole("link", { name: "Compare" }).click();
    await expect(page).toHaveURL(/\/compare$/);
    await expect(menu).toHaveJSProperty("open", false);
  });
});

test.describe("theme", () => {
  test("toggle flips the mode and the stored preference survives a reload", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto("/");
    const html = page.locator("html");
    await expect(html).toHaveAttribute("data-mode", "light");

    await page.getByRole("button", { name: "Switch between dark and light mode" }).click();
    await expect(html).toHaveAttribute("data-mode", "dark");
    await expect(html).toHaveClass(/dark/);
    expect(await page.evaluate(() => localStorage.getItem("theme"))).toBe("dark");

    await page.reload();
    await expect(html).toHaveAttribute("data-mode", "dark");

    await page.getByRole("button", { name: "Switch between dark and light mode" }).click();
    await expect(html).toHaveAttribute("data-mode", "light");
    expect(await page.evaluate(() => localStorage.getItem("theme"))).toBe("light");
  });

  test("a stored preference beats the system scheme before first paint", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "light" });
    await page.addInitScript(() => localStorage.setItem("theme", "dark"));
    await page.goto("/");
    await expect(page.locator("html")).toHaveAttribute("data-mode", "dark");
  });
});

test.describe("capability search", () => {
  test("filters by typing and moves the selection with the arrow keys", async ({ page }) => {
    await page.goto("/");
    const input = page.getByRole("combobox", { name: "Search capabilities" });
    const options = page.locator("#cap-list li.it:not([hidden])");
    await input.scrollIntoViewIfNeeded();

    const total = await options.count();
    expect(total).toBeGreaterThan(3);

    await input.click();
    await input.fill("exec");
    const filtered = await options.count();
    expect(filtered).toBeGreaterThan(0);
    expect(filtered).toBeLessThan(total);

    await input.fill("");
    await input.press("ArrowDown");
    await expect(options.first()).toHaveAttribute("aria-selected", "true");
    await expect(input).toHaveAttribute("aria-activedescendant", /^cap-opt-\d+$/);
    await input.press("ArrowDown");
    await expect(options.nth(1)).toHaveAttribute("aria-selected", "true");
    await expect(options.first()).toHaveAttribute("aria-selected", "false");
    await input.press("ArrowUp");
    await expect(options.first()).toHaveAttribute("aria-selected", "true");

    await input.fill("zzz-no-such-capability");
    await expect(page.locator(".pal .empty")).toContainText("No capabilities match");

    await input.press("Escape");
    await expect(input).toHaveValue("");
    await expect(options).toHaveCount(total);
  });
});

test.describe("terminal replay", () => {
  test("replays a scene when its button is pressed", async ({ page }) => {
    await page.goto("/");
    const term = page.locator("#term");
    await term.scrollIntoViewIfNeeded();
    // The opening scene autoplays on first view and settles to "done".
    await expect(term).toHaveAttribute("data-state", "done", { timeout: 60_000 });

    const body = term.locator(".term-body");
    const validate = term.getByRole("button", { name: /sockguard validate/ });
    await validate.click();
    await expect(validate).toHaveAttribute("aria-pressed", "true");
    await expect(term).toHaveAttribute("data-state", "playing");
    await expect(term).toHaveAttribute("data-state", "done", { timeout: 60_000 });
    await expect(body.locator(".tl.cmd").first()).toContainText("sockguard");
    expect(await body.locator(".tl").count()).toBeGreaterThan(2);
  });

  test("renders scenes in full under reduced motion", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/");
    const term = page.locator("#term");
    await term.scrollIntoViewIfNeeded();
    await expect(term).toHaveAttribute("data-state", "done");
    await term.getByRole("button", { name: /sockguard match/ }).click();
    await expect(term).toHaveAttribute("data-state", "done");
    expect(await term.locator(".term-body .tl").count()).toBeGreaterThan(2);
  });
});

test.describe("faq", () => {
  test("ownership references are navigable by keyboard", async ({ page, browserName }) => {
    await page.goto("/");
    const item = page.locator(".faq details.fq").filter({
      has: page.getByText("Is this the same project as Buildkite's Sockguard?", { exact: true }),
    });
    await item.locator("summary").click();

    const website = item.getByRole("link", { name: "Sockguard website", exact: true });
    const repository = item.getByRole("link", { name: "CodesWhat/sockguard", exact: true });
    await expect(website).toHaveAttribute("href", "https://www.getsockguard.com");
    await expect(repository).toHaveAttribute("href", "https://github.com/CodesWhat/sockguard");
    await website.focus();
    await expect(website).toBeFocused();
    const nextLink = browserName === "webkit" && process.platform === "darwin" ? "Alt+Tab" : "Tab";
    await page.keyboard.press(nextLink);
    await expect(repository).toBeFocused();
  });

  test("opens one answer at a time", async ({ page }) => {
    await page.goto("/");
    const items = page.locator(".faq details.fq");
    expect(await items.count()).toBeGreaterThan(2);
    await items.first().scrollIntoViewIfNeeded();

    await items.nth(0).locator("summary").click();
    await expect(items.nth(0)).toHaveJSProperty("open", true);
    await expect(items.nth(0).locator(".a")).toBeVisible();

    await items.nth(1).locator("summary").click();
    await expect(items.nth(1)).toHaveJSProperty("open", true);
    await expect(items.nth(0)).toHaveJSProperty("open", false);

    await items.nth(1).locator("summary").click();
    await expect(items.nth(1)).toHaveJSProperty("open", false);
  });
});

test.describe("compare page", () => {
  test.use({ viewport: { width: 375, height: 812 } });

  test("has no horizontal page overflow at 375px and keeps the first column sticky", async ({
    page,
    issues,
  }) => {
    await page.goto("/compare");
    await expect(page.locator("table.cmp.mxt")).toBeVisible();
    await page.waitForLoadState("networkidle");

    const overflow = await page.evaluate(() => ({
      doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      body: document.body.scrollWidth - document.documentElement.clientWidth,
    }));
    expect(overflow.doc).toBeLessThanOrEqual(0);
    expect(overflow.body).toBeLessThanOrEqual(0);

    const cell = page.locator("table.cmp.mxt tbody th").first();
    expect(await cell.evaluate((el) => getComputedStyle(el).position)).toBe("sticky");

    // The matrix scrolls inside its own wrapper. Scroll it and check the first
    // column stays pinned to the left while the rest of the row moves.
    const second = page.locator("table.cmp.mxt tbody tr").first().locator("td").first();
    const pinnedBefore = await cell.boundingBox();
    const movingBefore = await second.boundingBox();
    const scrolled = await page.evaluate(() => {
      let moved = 0;
      for (const el of document.querySelectorAll("*")) {
        if (el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).overflowX !== "visible") {
          el.scrollLeft = 120;
          if (el.scrollLeft > 0) moved++;
        }
      }
      return moved;
    });
    expect(scrolled).toBeGreaterThan(0);
    const pinnedAfter = await cell.boundingBox();
    const movingAfter = await second.boundingBox();
    expect(pinnedAfter?.x).toBeCloseTo(pinnedBefore?.x ?? -1, 0);
    expect(movingAfter?.x).toBeLessThan((movingBefore?.x ?? 0) - 20);
    expect(issues).toEqual([]);
  });
});

test.describe("404", () => {
  test("serves the not-found page with a 404 status and searchable docs", async ({ page }) => {
    const response = await page.goto("/definitely/not/a/page");
    expect(response?.status()).toBe(404);
    await expect(page.getByRole("heading", { level: 1, name: "404" })).toBeVisible();

    const search = page.getByRole("searchbox", { name: /Search the Sockguard docs/ });
    await search.fill("security");
    const first = page.locator(".nf-r a").first();
    await expect(first).toBeVisible();
    expect(await first.getAttribute("href")).toMatch(/^\/docs\//);

    await search.fill("zzzzqqqq");
    await expect(page.locator(".nf-s")).toContainText("No docs match");
  });
});

test.describe("security.txt", () => {
  test("is served as text/plain with the security headers", async ({ request }) => {
    const response = await request.get("/.well-known/security.txt");
    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toBe("text/plain; charset=utf-8");
    expect(response.headers()["x-content-type-options"]).toBe("nosniff");
    expect(await response.text()).toContain("Contact: mailto:");
  });
});
