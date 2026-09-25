import { z } from "zod";
import { PolicyError } from "../policy.ts";
import {
  apiRequestSchema,
  policySchema,
  tokenPolicySchema,
  type ApiRequest,
} from "./contracts.ts";

/** The part of `fetch` issuance uses, so tests can pass a plain function. */
export type Send = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export function assertApiScope(
  request: ApiRequest,
  policy: z.infer<typeof policySchema>,
) {
  const [, kind, resourceId] = request.path.split("/");
  if (
    (request.host === "api.cloudflare.com" && kind !== "accounts" && kind !== "zones") ||
    (request.host === "gateway.ai.cloudflare.com" &&
      (kind !== "v1" || resourceId !== policy.accountId)) ||
    (kind === "accounts" && resourceId !== policy.accountId) ||
    (kind === "zones" && !policy.zoneIds.includes(resourceId ?? ""))
  ) {
    throw new PolicyError(403, "request exceeds the issuer's account and zones");
  }
}

export function assertTokenScope(
  policies: z.infer<typeof tokenPolicySchema>[],
  policy: z.infer<typeof policySchema>,
) {
  const account = `com.cloudflare.api.account.${policy.accountId}`;
  const zones = new Set(
    policy.zoneIds.map((zone) => `com.cloudflare.api.account.zone.${zone}`),
  );
  for (const grant of policies) {
    if (Object.keys(grant.resources).length === 0)
      throw new PolicyError(400, "token policy requires resources");
    for (const [resource, scope] of Object.entries(grant.resources)) {
      if (
        resource === account &&
        (scope === "*" || Object.keys(scope).every((key) => zones.has(key)))
      )
        continue;
      if (zones.has(resource) && scope === "*") continue;
      throw new PolicyError(403, "token policy exceeds the issuer's account and zones");
    }
  }
}

export function isTokenManagement(request: ApiRequest) {
  return /^\/accounts\/[a-f0-9]{32}\/tokens(?:\/|$)/u.test(request.path);
}

export async function providerRequest(send: Send, token: string, input: ApiRequest) {
  const request = apiRequestSchema.parse(input);
  const url = new URL(
    `https://${request.host}${request.host === "api.cloudflare.com" ? "/client/v4" : ""}${request.path}`,
  );
  for (const [key, value] of Object.entries(request.query))
    url.searchParams.set(key, value);
  const headers = new Headers({
    [request.host === "api.cloudflare.com" ? "Authorization" : "cf-aig-authorization"]:
      `Bearer ${token}`,
  });
  let body: BodyInit | undefined;
  if (request.body.kind === "json") {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(request.body.value);
  } else if (request.body.kind === "multipart") {
    const form = new FormData();
    for (const part of request.body.parts) {
      form.append(
        part.name,
        new Blob([part.content], { type: part.contentType }),
        part.filename,
      );
    }
    body = form;
  }
  const response = await send(url, {
    method: request.method,
    headers,
    body,
    redirect: "manual",
    signal: AbortSignal.timeout(60000),
  });
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new Error("Provider redirects are not allowed");
  }
  return readProviderResponse(response, token);
}

export async function readProviderResponse(response: Response, token: string) {
  const reader = response.body?.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  if (reader)
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > 2000000) {
        await reader.cancel();
        throw new Error("provider response exceeds 2 MB; outcome requires inspection");
      }
      parts.push(part.value);
    }
  const collected = await new Blob(parts).text();
  const text = collected.replaceAll(token, "[REDACTED]");
  let value: z.infer<ReturnType<typeof z.json>>;
  try {
    value = JSON.parse(text);
  } catch {
    value = text;
  }
  return { status: response.status, body: value };
}
