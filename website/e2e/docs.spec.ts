import { expect, test } from "./fixtures";

test.describe("docs search", () => {
  test("opens with the keyboard shortcut, finds a page and closes", async ({
    page,
    browserName,
  }) => {
    await page.goto("/docs/getting-started");
    await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
    // Wait for hydration: the search button only renders once the provider is up.
    await expect(page.getByRole("button", { name: "Search docs" }).first()).toBeVisible();

    const mod = process.platform === "darwin" && browserName !== "firefox" ? "Meta" : "Control";
    await page.keyboard.press(`${mod}+k`);
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();

    const input = dialog.getByRole("combobox").or(dialog.getByRole("searchbox")).first();
    await input.fill("presets");
    await expect(dialog.getByRole("option").first()).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
  });

  test("opens from the search button at the top of the sidebar", async ({ page }) => {
    await page.goto("/docs/getting-started");
    const button = page.locator("#nd-sidebar").getByRole("button", { name: "Search docs" });
    await expect(button).toBeVisible();
    await expect(
      page.locator("header.top").getByRole("button", { name: "Search docs" }),
    ).toHaveCount(0);
    await button.click();
    await expect(page.getByRole("dialog")).toBeVisible();
  });
});

test.describe("docs header and sidebar controls", () => {
  test("header carries only the logo, Docs and GitHub", async ({ page }) => {
    await page.goto("/docs/getting-started");
    const nav = page.locator("header.top").getByRole("navigation", { name: "Main" });
    await expect(nav.getByRole("link")).toHaveText(["Docs", "GitHub"]);
    await expect(nav.getByRole("link", { name: "Compare" })).toHaveCount(0);
    await expect(
      page.locator("header.top").getByRole("button", { name: /dark and light/ }),
    ).toHaveCount(0);
  });

  test("theme picker sits at the bottom of the sidebar and persists", async ({ page }) => {
    await page.goto("/docs/getting-started");
    const toggle = page.locator("#nd-sidebar").getByRole("button", {
      name: "Switch between dark and light mode",
    });
    await expect(toggle).toBeVisible();
    await toggle.click();
    const first = await page.evaluate(() => localStorage.getItem("theme"));
    expect(["light", "dark"]).toContain(first);
    await page.reload();
    expect(await page.evaluate(() => localStorage.getItem("theme"))).toBe(first);
  });

  test("keeps the comparison links in the docs footer", async ({ page }) => {
    await page.goto("/docs/getting-started");
    await expect(
      page.locator("footer").getByRole("link", { name: "All comparisons" }),
    ).toBeVisible();
  });
});

test.describe("docs mobile drawer at 375px", () => {
  test.use({ viewport: { width: 375, height: 812 } });

  test("opens from the docs bar, navigates and closes", async ({ page }) => {
    await page.goto("/docs/getting-started");
    const trigger = page.locator(".docs-bar-btn");
    await expect(trigger).toBeVisible();

    await trigger.click();
    const drawer = page
      .locator("#nd-sidebar-mobile, [data-state='open'] #nd-sidebar, #nd-sidebar")
      .first();
    await expect(drawer.getByRole("link", { name: "Configuration" }).first()).toBeVisible();

    await expect(drawer.getByRole("button", { name: "Search docs" })).toBeVisible();
    await expect(
      drawer.getByRole("button", { name: "Switch between dark and light mode" }),
    ).toBeVisible();

    await drawer.getByRole("link", { name: "Configuration" }).first().click();
    await expect(page).toHaveURL(/\/docs\/configuration/);
  });

  test("search opens from the docs bar", async ({ page }) => {
    await page.goto("/docs/getting-started");
    await page.locator(".docs-bar").getByRole("button", { name: "Search docs" }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
  });
});
