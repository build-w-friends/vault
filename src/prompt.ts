export async function readSecretValue(
  inline: string | undefined,
  stdin: NodeJS.ReadableStream & { isTTY?: boolean } = process.stdin,
  stdout: NodeJS.WritableStream = process.stdout,
): Promise<string> {
  if (inline != null && inline.length > 0) return inline;
  if (stdin.isTTY !== true) {
    const chunks: Buffer[] = [];
    for await (const chunk of stdin) chunks.push(Buffer.from(chunk));
    const text = Buffer.concat(chunks).toString("utf8").replace(/\n$/u, "");
    if (text.length === 0) throw new Error("secret value must not be empty");
    return text;
  }
  stdout.write("value: ");
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
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (text === "\n" || text === "\r" || text === "\r\n") {
        cleanup();
        stdout.write("\n");
        resolve(value);
        return;
      }
      if (text === "\u0003") {
        cleanup();
        reject(new Error("cancelled"));
        return;
      }
      if (text === "\u007f" || text === "\b") {
        value = value.slice(0, -1);
        return;
      }
      value += text;
    };
    const cleanup = () => {
      stdin.setRawMode?.(false);
      stdin.pause();
      stdin.off("data", onData);
    };
    stdin.on("data", onData);
  });
}
