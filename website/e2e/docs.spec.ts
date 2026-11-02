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

  test("opens from the search button", async ({ page }) => {
    await page.goto("/docs/getting-started");
    await page.getByRole("button", { name: "Search docs" }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
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

    await drawer.getByRole("link", { name: "Configuration" }).first().click();
    await expect(page).toHaveURL(/\/docs\/configuration/);
  });
});
