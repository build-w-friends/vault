import * as v from "valibot";
export async function readSecretValue(
  inline: string | undefined,
  stdin: NodeJS.ReadableStream & { isTTY?: boolean } = process.stdin,
  stdout: NodeJS.WritableStream = process.stdout,
  prompt = "value: ",
): Promise<string> {
  if (inline != null && inline.length > 0) return inline;
  if (stdin.isTTY !== true) {
    const chunks: Buffer[] = [];
    for await (const chunk of stdin) chunks.push(Buffer.from(chunk));
    const text = Buffer.concat(chunks).toString("utf8").replace(/\n$/u, "");
    if (text.length === 0) throw new Error("secret value must not be empty");
    return text;
  }
  stdout.write(prompt);
  const value = await readHidden(stdin, stdout);
  if (value.length === 0) throw new Error("secret value must not be empty");
  return value;
}

function readHidden(
  stdin: NodeJS.ReadableStream & {
    isTTY?: boolean;
    setRawMode?: (mode: boolean) => void;
    setEncoding?: (encoding: BufferEncoding) => void;
  },
  stdout: NodeJS.WritableStream,
): Promise<string> {
  return new Promise((resolve, reject) => {
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding?.("utf8");
    let value = "";
    const onData = (chunk: string | Buffer) => {
      const text = v.is(v.string(), chunk) ? chunk : chunk.toString("utf8");
      for (const character of text) {
        if (character === "\n" || character === "\r") {
          cleanup();
          stdout.write("\n");
          resolve(value);
          return;
        }
        if (character === "\u0003" || character === "\u0004") {
          cleanup();
          reject(new Error("cancelled"));
          return;
        }
        if (character === "\u007f" || character === "\b") {
          value = value.slice(0, -1);
        } else value += character;
      }
    };
    const cleanup = () => {
      stdin.setRawMode?.(false);
      stdin.pause();
      stdin.off("data", onData);
    };
    stdin.on("data", onData);
  });
}
