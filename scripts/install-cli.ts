import { existsSync } from "node:fs";
import { delimiter, resolve } from "node:path";

import { defaultInstallDirectory, installVaultBinary } from "../src/cli-install.ts";

const packageRoot = resolve(import.meta.dir, "..");
const sourcePath = resolve(packageRoot, "dist", "vault");

if (!existsSync(sourcePath)) {
  throw new Error("compiled vault CLI is missing; run bun run build:cli first");
}

const result = installVaultBinary(sourcePath, defaultInstallDirectory());
console.log(`installed vault CLI at ${result.installedPath}`);
if (!commandDirectoryIsOnPath(result.installedPath)) {
  console.log(
    `add this directory to PATH before using vault: ${defaultInstallDirectory()}`,
  );
}

function commandDirectoryIsOnPath(installedPath: string): boolean {
  const directory = resolve(installedPath, "..");
  return (process.env.PATH ?? "")
    .split(delimiter)
    .some((candidate) => candidate !== "" && resolve(candidate) === directory);
}
