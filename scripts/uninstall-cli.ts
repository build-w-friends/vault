import { defaultInstallDirectory, uninstallVaultBinary } from "../src/cli-install.ts";

const installDirectory = defaultInstallDirectory();
if (uninstallVaultBinary(installDirectory)) {
  console.log(`uninstalled vault CLI from ${installDirectory}/vault`);
} else {
  console.log(`vault CLI was not installed at ${installDirectory}/vault`);
}
