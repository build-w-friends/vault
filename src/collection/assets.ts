import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

/** Build-time only: embed the form in the standalone CLI, with no runtime CDN.
 * A subprocess avoids reentering the bundler from its own macro callback. */
export function buildCollectionAssets() {
  const directory = mkdtempSync(join(tmpdir(), "vault-collection-assets-"));
  try {
    const build = Bun.spawnSync(
      [
        process.execPath,
        "build",
        import.meta.dir + "/index.html",
        import.meta.dir + "/approval.ts",
        "--target=browser",
        "--minify",
        "--outdir",
        directory,
      ],
      { stdout: "ignore", stderr: "pipe" },
    );
    if (build.exitCode !== 0)
      throw new Error("Could not bundle the secret collection form");
    return readdirSync(directory).map((name) => ({
      name,
      type: name.endsWith(".html")
        ? "text/html; charset=utf-8"
        : name.endsWith(".css")
          ? "text/css; charset=utf-8"
          : "text/javascript; charset=utf-8",
      content: readFileSync(join(directory, name), "utf8"),
    }));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
