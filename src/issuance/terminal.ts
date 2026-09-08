import * as prompts from "@clack/prompts";
import { spawn } from "node:child_process";
import type { ConnectPrompts } from "./connect-cloudflare.ts";

export class PromptCancelled extends Error {
  constructor() {
    super("Setup cancelled. Credentials already created at the provider still exist.");
  }
}

function answer<T>(value: T | symbol): T {
  if (prompts.isCancel(value)) throw new PromptCancelled();
  return value;
}

export function terminalPrompts(): ConnectPrompts {
  if (!process.stdin.isTTY)
    throw new Error(
      "Guided setup needs an interactive terminal. Run vault issuance setup or vault issuance connect cloudflare there, or use vault issuance admin for scripted JSON input.",
    );
  const streams = { input: process.stdin, output: process.stderr };
  const say = (message: string) => {
    prompts.log.info(message, streams);
  };
  return {
    say,
    intro: (message) => {
      prompts.intro(message, streams);
    },
    outro: (message) => {
      prompts.outro(message, streams);
    },
    cancel: (message) => {
      prompts.cancel(message, streams);
    },
    async ask(message, validate) {
      return answer(
        await prompts.text({
          ...streams,
          message: message.trim().replace(/:$/u, ""),
          validate: (value) => validate?.(value ?? ""),
        }),
      );
    },
    async secret(message) {
      return answer(
        await prompts.password({
          ...streams,
          message: message.trim().replace(/:$/u, ""),
          validate: (value) => (value?.trim() ? undefined : "Enter a credential."),
        }),
      );
    },
    async select(message, entries, label) {
      const selected = answer(
        await prompts.select({
          ...streams,
          message,
          options: entries.map((entry) => ({ value: { entry }, label: label(entry) })),
        }),
      );
      return selected.entry;
    },
    async multiselect(message, entries, label) {
      const selected = answer(
        await prompts.multiselect({
          ...streams,
          message,
          options: entries.map((entry) => ({ value: { entry }, label: label(entry) })),
          required: false,
        }),
      );
      return selected.map(({ entry }) => entry);
    },
    async confirm(message) {
      return answer(await prompts.confirm({ ...streams, message, initialValue: false }));
    },
    async open(url) {
      const command =
        process.platform === "darwin"
          ? "open"
          : process.platform === "win32"
            ? "explorer.exe"
            : "xdg-open";
      const opened = await new Promise<boolean>((resolve) => {
        const child = spawn(command, [url], { stdio: "ignore" });
        child.on("error", () => {
          resolve(false);
        });
        child.on("exit", (code) => {
          resolve(code === 0);
        });
      });
      if (!opened) say("The browser could not be opened. Open the printed URL manually.");
    },
  };
}
