import * as prompts from "@clack/prompts";
import type { ConnectPrompts } from "./connect-cloudflare.ts";

export class PromptCancelledError extends Error {
  override readonly name = "PromptCancelledError";

  constructor() {
    super("Setup cancelled. Credentials already created at the provider still exist.");
  }
}

function answer<T>(value: T | symbol): T {
  if (prompts.isCancel(value)) throw new PromptCancelledError();
  // SAFETY: a clack prompt returns its answer or the cancel symbol, excluded above;
  // isCancel narrows only that unique symbol, not the `symbol` in the prompt types.
  return value as T;
}

/** How each platform opens a URL; everything else uses the freedesktop tool. */
const BROWSER_OPENERS: Partial<Record<NodeJS.Platform, string>> = {
  darwin: "open",
  win32: "explorer.exe",
};

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
      return answer<string>(
        await prompts.text({
          ...streams,
          message: message.trim().replace(/:$/u, ""),
          validate: (value) => validate?.(value ?? ""),
        }),
      );
    },
    async secret(message) {
      return answer<string>(
        await prompts.password({
          ...streams,
          message: message.trim().replace(/:$/u, ""),
          validate: (value) => (value?.trim() ? undefined : "Enter a credential."),
        }),
      );
    },
    async select(message, entries, label) {
      const selected = answer<{ entry: (typeof entries)[number] }>(
        await prompts.select({
          ...streams,
          message,
          options: entries.map((entry) => ({ value: { entry }, label: label(entry) })),
        }),
      );
      return selected.entry;
    },
    async multiselect(message, entries, label) {
      const selected = answer<{ entry: (typeof entries)[number] }[]>(
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
      return answer<boolean>(
        await prompts.confirm({ ...streams, message, initialValue: false }),
      );
    },
    async open(url) {
      const command = BROWSER_OPENERS[process.platform] ?? "xdg-open";
      let opened: boolean;
      try {
        // Bun.spawn throws synchronously when the opener is not installed.
        opened =
          (await Bun.spawn([command, url], { stdio: ["ignore", "ignore", "ignore"] })
            .exited) === 0;
      } catch {
        opened = false;
      }
      if (!opened) say("The browser could not be opened. Open the printed URL manually.");
    },
  };
}
