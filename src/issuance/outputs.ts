/* oxlint-disable anti-slop/no-runtime-typeof -- Provider JSON is parsed at the boundary; recursive JSON traversal must distinguish its scalar, array, and object variants. */
import { z } from "zod";
import { PolicyError } from "../policy.ts";
import { secretReferenceSchema } from "./contracts.ts";
import type { Auth } from "./contracts.ts";
import type { IssuanceStore } from "./store.ts";

type Json = z.infer<ReturnType<typeof z.json>>;
const outputSchema = z.object({
  status: z.number().int(),
  body: z.json(),
  redactions: z.array(z.string()).default([]),
});
// Cloudflare credential responses use these names. Values remain encrypted;
// references can be injected into a later approved JSON request inside Vault.
const secretField =
  /(?:secret|password|token|credential|authorization|private.?key|access.?key|api.?key|jwt)|^(?:value|key)$/i;
const pointerPart = (key: string) => key.replaceAll("~", "~0").replaceAll("/", "~1");
function publicValue(
  value: Json,
  outputId: string,
  pointer = "",
  field = "",
  redactions: string[] = [],
): Json {
  if (secretField.test(field) && value !== null)
    return { $vaultSecret: { outputId, pointer } };
  if (Array.isArray(value))
    return value.map((entry, index) =>
      publicValue(entry, outputId, `${pointer}/${index}`, "", redactions),
    );
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        publicValue(entry, outputId, `${pointer}/${pointerPart(key)}`, key, redactions),
      ]),
    );
  // Non-JSON/text responses may themselves be a token or private key.
  if ((pointer === "" || field === "result") && typeof value === "string")
    return { $vaultSecret: { outputId, pointer } };
  return typeof value === "string"
    ? redactions.reduce((text, secret) => text.split(secret).join("[REDACTED]"), value)
    : value;
}
export async function saveOutput(
  store: IssuanceStore,
  requestId: string,
  result: { status: number; body: Json },
  redactions: string[] = [],
) {
  const outputId = crypto.randomUUID();
  const encrypted = await store.crypto.encrypt(JSON.stringify({ ...result, redactions }));
  if (encrypted.length > 1500000)
    throw new PolicyError(
      413,
      "output storage limit exceeded; inspect request status and the resource before repeating a mutation",
    );
  const saved = await store.db
    .prepare(
      "INSERT INTO issuance_outputs SELECT ?, ?, ?, ? WHERE (SELECT coalesce(sum(length(encrypted)), 0) FROM issuance_outputs) + ? <= 67108864 RETURNING id",
    )
    .bind(outputId, requestId, encrypted, store.now(), encrypted.length)
    .first();
  if (!saved)
    throw new PolicyError(
      503,
      "output storage limit reached; inspect request status and the resource before repeating a mutation",
    );
  return outputId;
}
async function readOutput(store: IssuanceStore, outputId: string) {
  const row = await store.db
    .prepare(
      "SELECT encrypted, request_id, created_at FROM issuance_outputs WHERE id = ?",
    )
    .bind(outputId)
    .first<{ encrypted: string; request_id: string; created_at: number }>();
  if (!row) throw new PolicyError(404, "provider output not found");
  return {
    ...outputSchema.parse(JSON.parse(await store.crypto.decrypt(row.encrypted))),
    requestId: row.request_id,
    createdAt: row.created_at,
  };
}
export async function showOutput(store: IssuanceStore, outputId: string) {
  const output = await readOutput(store, outputId);
  return {
    status: output.status,
    outputId,
    body: publicValue(output.body, outputId, "", "", output.redactions),
  };
}
export async function resolveSecrets(
  store: IssuanceStore,
  auth: Auth,
  value: Json,
  secrets = new Set<string>(),
): Promise<Json> {
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    "$vaultSecret" in value
  ) {
    const { $vaultSecret: ref } = secretReferenceSchema.parse(value);
    const output = await readOutput(store, ref.outputId);
    const request = await store.request(output.requestId, auth);
    if (
      output.createdAt <= store.now() - 86400000 ||
      !(await store.eligibleRequest(request))
    )
      throw new PolicyError(
        403,
        "referenced output is no longer available to this session",
      );
    let resolved: Json = output.body;
    if (ref.pointer !== "" && !ref.pointer.startsWith("/"))
      throw new PolicyError(400, "invalid JSON pointer");
    for (const segment of ref.pointer === "" ? [] : ref.pointer.slice(1).split("/")) {
      const key = segment.replaceAll("~1", "/").replaceAll("~0", "~");
      if (
        resolved === null ||
        typeof resolved !== "object" ||
        !Object.hasOwn(resolved, key)
      )
        throw new PolicyError(400, "secret reference does not exist");
      const object = z
        .record(z.string(), z.json())
        .parse(
          Array.isArray(resolved)
            ? Object.fromEntries(resolved.map((entry, index) => [String(index), entry]))
            : resolved,
        );
      resolved = object[key] ?? null;
    }
    function remember(entry: Json) {
      if (typeof entry === "string" && entry.length > 0) secrets.add(entry);
      else if (entry !== null && typeof entry === "object")
        for (const child of Object.values(entry)) remember(child);
    }
    remember(resolved);
    return resolved;
  }
  if (Array.isArray(value))
    return Promise.all(value.map((entry) => resolveSecrets(store, auth, entry, secrets)));
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      await Promise.all(
        Object.entries(value).map(async ([key, entry]) => [
          key,
          await resolveSecrets(store, auth, entry, secrets),
        ]),
      ),
    );
  return value;
}
