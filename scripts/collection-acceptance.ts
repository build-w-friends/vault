import { chromium } from "playwright";
import { resolve } from "node:path";
import { startSecretCollection } from "../src/collection.ts";
import { startLocalVault } from "./local-vault.ts";

const { output, store, api, origin, client } = await startLocalVault(
  "collection-acceptance",
);
const browser = await chromium.launch({ headless: true });
const results: string[] = [];
try {
  for (const theme of ["light", "dark"] as const) {
    const target = {
      project: "demo",
      env: "dev",
      name: `SYNTHETIC_${theme.toUpperCase()}`,
      kind: "secret" as const,
    };
    const helper = startSecretCollection({
      target,
      vaultOrigin: origin,
      save: (value) => client.createCollectedSecret(target, value),
    });
    const context = await browser.newContext({
      colorScheme: theme,
      viewport:
        theme === "dark" ? { width: 390, height: 844 } : { width: 900, height: 850 },
    });
    const page = await context.newPage();
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => {
      if (message.type() === "error") errors.push(message.text());
    });
    const responses: string[] = [];
    page.on("response", (response) => {
      if (response.url().endsWith("/submit"))
        void response.text().then((text) => responses.push(text));
    });
    try {
      await page.goto(helper.url);
      await page.getByRole("button", { name: "Save secret" }).waitFor();
      await page.locator("#save:not([disabled])").waitFor();
      await page.screenshot({
        path: resolve(output, `${theme}-ready.png`),
        fullPage: true,
      });
      const synthetic = `synthetic-browser-${theme}`;
      await page.getByLabel("Secret value").fill(synthetic);
      await page.getByRole("button", { name: "Save secret" }).click();
      await page.getByRole("status").filter({ hasText: "Secret saved." }).waitFor();
      if ((await helper.completed).state !== "stored")
        throw new Error("No storage receipt");
      const { environmentId } = await store.requireEnvironment("demo", "dev");
      if ((await store.getSecretByName(environmentId, target.name))?.value !== synthetic)
        throw new Error("Stored value mismatch");
      if ((await page.getByLabel("Secret value").inputValue()) !== "")
        throw new Error("Input was retained");
      if (responses.some((text) => text.includes(synthetic)))
        throw new Error("Value leaked in response");
      if (errors.length) throw new Error("Browser reported errors");
      await page.screenshot({
        path: resolve(output, `${theme}-stored.png`),
        fullPage: true,
      });
      results.push(
        `${theme}: browser submission, encrypted-store round trip, cleared input, metadata-only response`,
      );
    } finally {
      await context.close();
      await helper.stop();
    }
  }
  const target = {
    project: "demo",
    env: "dev",
    name: "SYNTHETIC_CANCEL",
    kind: "secret" as const,
  };
  const helper = startSecretCollection({
    target,
    vaultOrigin: origin,
    save: (value) => client.createCollectedSecret(target, value),
  });
  try {
    const page = await browser.newPage();
    await page.goto(helper.url);
    await page.locator("#value:not([disabled])").waitFor();
    await page.getByLabel("Secret value").fill("synthetic-discard");
    page.once("dialog", (dialog) => {
      void dialog.accept();
    });
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await page.getByRole("status").filter({ hasText: "Cancelled." }).waitFor();
    if ((await helper.completed).state !== "cancelled")
      throw new Error("Cancellation failed");
    results.push("dirty cancellation: confirmed and no submission");
  } finally {
    await helper.stop();
  }
  await Bun.write(resolve(output, "receipt.json"), JSON.stringify(results, null, 2));
  console.log(results.join("\n"));
  console.log(`Synthetic acceptance evidence: ${output}`);
} finally {
  await browser.close();
  await api.stop(true);
}
