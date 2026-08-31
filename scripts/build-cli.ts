import { randomUUID } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const packageRoot = resolve(import.meta.dir, "..");
const outputDirectory = resolve(packageRoot, "dist");
const outputPath = resolve(outputDirectory, "vault");
const buildDirectory = mkdtempSync(join(tmpdir(), "bwf-vault-build-"));
const buildOutputPath = resolve(buildDirectory, "vault");
const destinationTemporaryPath = resolve(
  outputDirectory,
  `.vault.build-${process.pid}-${randomUUID()}`,
);

mkdirSync(outputDirectory, { recursive: true });
try {
  const child = Bun.spawn(
    [
      process.execPath,
      "build",
      resolve(packageRoot, "src", "cli.ts"),
      "--compile",
      "--outfile",
      buildOutputPath,
    ],
    { cwd: buildDirectory, stdout: "inherit", stderr: "inherit" },
  );
  const exitCode = await child.exited;
  if (exitCode !== 0) throw new Error("standalone vault CLI build failed");
  copyFileSync(buildOutputPath, destinationTemporaryPath);
  chmodSync(destinationTemporaryPath, 0o755);
  renameSync(destinationTemporaryPath, outputPath);
} finally {
  rmSync(destinationTemporaryPath, { force: true });
  rmSync(buildDirectory, { force: true, recursive: true });
}
console.log(`built standalone vault CLI at ${outputPath}`);
