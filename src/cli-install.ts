import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import * as v from "valibot";

const RECEIPT_VERSION = 1;

const installReceiptSchema = v.looseObject({
  version: v.literal(RECEIPT_VERSION),
  installedPath: v.string(),
  sha256: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/u)),
});
type InstallReceipt = v.InferOutput<typeof installReceiptSchema>;

export type InstallResult = {
  installedPath: string;
  receiptPath: string;
};

export function defaultInstallDirectory(
  environment: Readonly<Record<string, string | undefined>> = process.env,
  homeDirectory = homedir(),
): string {
  const override = environment.BWF_VAULT_INSTALL_DIR?.trim();
  return resolve(
    override == null || override === "" ? join(homeDirectory, ".local", "bin") : override,
  );
}

export function receiptPathFor(installedPath: string): string {
  return join(dirname(installedPath), `.${basename(installedPath)}.bwf-install.json`);
}

export function installVaultBinary(
  sourcePath: string,
  installDirectory: string,
): InstallResult {
  const source = resolve(sourcePath);
  const directory = resolve(installDirectory);
  const installedPath = join(directory, "vault");
  const receiptPath = receiptPathFor(installedPath);

  assertRegularFile(source, "compiled vault binary");
  mkdirSync(directory, { recursive: true, mode: 0o755 });
  assertOwnedOrAbsent(installedPath, receiptPath);

  const binaryTemporaryPath = join(
    directory,
    `.vault.bwf-install-${process.pid}-${randomUUID()}`,
  );
  const receiptTemporaryPath = `${receiptPath}.${process.pid}-${randomUUID()}`;
  try {
    copyFileSync(source, binaryTemporaryPath);
    chmodSync(binaryTemporaryPath, 0o755);
    const receipt: InstallReceipt = {
      version: RECEIPT_VERSION,
      installedPath,
      sha256: sha256File(binaryTemporaryPath),
    };
    writeFileSync(receiptTemporaryPath, `${JSON.stringify(receipt, null, 2)}\n`, {
      mode: 0o644,
    });
    renameSync(binaryTemporaryPath, installedPath);
    renameSync(receiptTemporaryPath, receiptPath);
  } finally {
    rmSync(binaryTemporaryPath, { force: true });
    rmSync(receiptTemporaryPath, { force: true });
  }

  return { installedPath, receiptPath };
}

export function uninstallVaultBinary(installDirectory: string): boolean {
  const installedPath = join(resolve(installDirectory), "vault");
  const receiptPath = receiptPathFor(installedPath);

  if (!existsSync(installedPath)) {
    rmSync(receiptPath, { force: true });
    return false;
  }

  assertOwnedOrAbsent(installedPath, receiptPath, true);
  rmSync(installedPath);
  rmSync(receiptPath);
  return true;
}

function assertOwnedOrAbsent(
  installedPath: string,
  receiptPath: string,
  requirePresent = false,
): void {
  if (!existsSync(installedPath)) {
    if (requirePresent) throw new Error(`vault is not installed at ${installedPath}`);
    return;
  }

  assertRegularFile(installedPath, "installed vault command");
  if (!existsSync(receiptPath)) {
    throw new Error(`refusing to replace or remove unowned command at ${installedPath}`);
  }
  const receipt = readReceipt(receiptPath);
  if (receipt.installedPath !== installedPath) {
    throw new Error(`vault install receipt does not own ${installedPath}`);
  }
  if (receipt.sha256 !== sha256File(installedPath)) {
    throw new Error(`refusing to replace or remove modified command at ${installedPath}`);
  }
}

function assertRegularFile(path: string, label: string): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file: ${path}`);
  }
}

function readReceipt(path: string): InstallReceipt {
  let source: unknown;
  try {
    source = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`vault install receipt is unreadable: ${path}`);
  }
  const parsed = v.safeParse(installReceiptSchema, source);
  if (!parsed.success) {
    throw new Error(`vault install receipt is invalid: ${path}`);
  }
  return parsed.output;
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
