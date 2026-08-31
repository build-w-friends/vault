import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "bun:test";

import {
  defaultInstallDirectory,
  installVaultBinary,
  receiptPathFor,
  uninstallVaultBinary,
} from "./cli-install.ts";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true });
  }
});

describe("vault CLI installation", () => {
  test("defaults to ~/.local/bin and accepts an isolated override", () => {
    expect(defaultInstallDirectory({}, "/Users/operator")).toBe(
      "/Users/operator/.local/bin",
    );
    expect(
      defaultInstallDirectory(
        { BWF_VAULT_INSTALL_DIR: "/opt/bwf/bin" },
        "/Users/operator",
      ),
    ).toBe("/opt/bwf/bin");
  });

  test("installs, upgrades, and uninstalls an owned executable", () => {
    const root = temporaryDirectory();
    const source = join(root, "compiled-vault");
    const installDirectory = join(root, "bin");
    writeFileSync(source, "first build");
    chmodSync(source, 0o755);

    const first = installVaultBinary(source, installDirectory);
    expect(readFileSync(first.installedPath, "utf8")).toBe("first build");
    expect(statSync(first.installedPath).mode & 0o111).toBe(0o111);
    expect(existsSync(first.receiptPath)).toBe(true);

    writeFileSync(source, "second build");
    const second = installVaultBinary(source, installDirectory);
    expect(second).toEqual(first);
    expect(readFileSync(second.installedPath, "utf8")).toBe("second build");

    expect(uninstallVaultBinary(installDirectory)).toBe(true);
    expect(existsSync(second.installedPath)).toBe(false);
    expect(existsSync(second.receiptPath)).toBe(false);
    expect(uninstallVaultBinary(installDirectory)).toBe(false);
  });

  test("refuses to overwrite an unrelated vault command", () => {
    const root = temporaryDirectory();
    const source = join(root, "compiled-vault");
    const installDirectory = join(root, "bin");
    const destination = join(installDirectory, "vault");
    writeFileSync(source, "new command");
    mkdirSync(installDirectory);
    writeFileSync(destination, "existing command");

    expect(() => installVaultBinary(source, installDirectory)).toThrow(
      "refusing to replace or remove unowned command",
    );
    expect(readFileSync(destination, "utf8")).toBe("existing command");
  });

  test("refuses to replace or uninstall a modified managed command", () => {
    const root = temporaryDirectory();
    const source = join(root, "compiled-vault");
    const installDirectory = join(root, "bin");
    writeFileSync(source, "managed command");
    const result = installVaultBinary(source, installDirectory);
    writeFileSync(result.installedPath, "locally modified command");

    expect(() => installVaultBinary(source, installDirectory)).toThrow(
      "refusing to replace or remove modified command",
    );
    expect(() => uninstallVaultBinary(installDirectory)).toThrow(
      "refusing to replace or remove modified command",
    );
    expect(existsSync(receiptPathFor(result.installedPath))).toBe(true);
  });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "bwf-vault-install-"));
  temporaryDirectories.push(directory);
  return directory;
}
