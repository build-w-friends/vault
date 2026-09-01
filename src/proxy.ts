/**
 * The brokering proxy behind `vault proxy`.
 *
 * `vault run` answers "this process needs a secret". This answers the harder
 * case: the process needs to make an authenticated request and should not hold
 * the credential — the shape of an agent running somebody else's code.
 *
 * A per-run CA signs short-lived leaf certificates for routed hosts only. The
 * child is spawned trusting that CA (five separate CA environment variables,
 * because the tools that need to trust it are written in different languages),
 * with placeholder values in place of real secrets and with `VAULT_API_KEY`
 * and `VAULT_API_URL` deleted so it cannot ask the vault for anything.
 *
 * `CONNECT` to an unrouted host is refused with 403. This is an allowlist, not
 * an interceptor. On a routed host the proxy strips the headers the route
 * declares (including the dummy the child just sent), injects the real value,
 * and forwards.
 *
 * What it is not: a sandbox. A process that ignores `HTTPS_PROXY` is not
 * intercepted — it simply fails to authenticate, holding only a dummy. And
 * whatever the routed API returns is visible to the child; this protects the
 * credential, not the data it unlocks.
 *
 * @see {@link https://vault.buildwithfriends.com/concepts/brokering/}
 */
import { generateKeyPairSync } from "node:crypto";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isIP } from "node:net";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import tls from "node:tls";

import forge from "node-forge";

import { applyInject } from "./presets.ts";
import type { ProcessEnvironment, RouteRecord, SecretRecord } from "./types.ts";
import { dummyForProxy } from "./policy.ts";

type ProxyCa = {
  certPem: string;
  keyPem: string;
  ca: forge.pki.Certificate;
  keys: forge.pki.rsa.KeyPair;
};

export type ProxyHandle = {
  port: number;
  caPem: string;
  caPath: string;
  dummyEnv: Record<string, string>;
  stop: () => Promise<void>;
};

function opensslRsaPair(): forge.pki.rsa.KeyPair {
  const generated = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });
  return {
    publicKey: forge.pki.publicKeyFromPem(generated.publicKey),
    privateKey: forge.pki.privateKeyFromPem(generated.privateKey),
  };
}

function generateProxyCa(): ProxyCa {
  const keys = opensslRsaPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  const attrs = [{ name: "commonName", value: "poc-vault-proxy" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    ca: cert,
    keys,
  };
}

function leafForHost(ca: ProxyCa, host: string): { certPem: string; keyPem: string } {
  const keys = opensslRsaPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setDate(cert.validity.notAfter.getDate() + 7);
  cert.setSubject([{ name: "commonName", value: host }]);
  cert.setIssuer(ca.ca.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "subjectAltName", altNames: [{ type: 2, value: host }] },
  ]);
  cert.sign(ca.keys.privateKey, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

export function dummyEnvFor(
  secrets: SecretRecord[],
  routes: RouteRecord[],
): Record<string, string> {
  const byName = new Map(routes.map((route) => [route.secretName, route]));
  const env: Record<string, string> = {};
  for (const secret of secrets) {
    if (!dummyForProxy(secret.kind)) {
      env[secret.name] = secret.value;
      continue;
    }
    const route = byName.get(secret.name);
    if (route != null) env[route.dummyEnvName] = route.dummyValue;
  }
  return env;
}

export async function startProxy(input: {
  secrets: SecretRecord[];
  routes: RouteRecord[];
  forward?: Record<string, string>;
  port?: number;
}): Promise<ProxyHandle> {
  const ca = generateProxyCa();
  const leafCache = new Map<string, { certPem: string; keyPem: string }>();
  const secretByName = new Map(input.secrets.map((secret) => [secret.name, secret]));
  const routesByHost = new Map<string, RouteRecord>();
  for (const route of input.routes) {
    const host = route.host.toLowerCase();
    if (!isPublicRouteHost(host)) {
      throw new Error(`proxy route host must be a public DNS name: ${route.host}`);
    }
    routesByHost.set(host, route);
  }

  const decryptedHttp = createHttpServer();
  decryptedHttp.on("request", (req, res) => {
    void handleMitmRequest(req, res, {
      routes: input.routes,
      routesByHost,
      secretByName,
      forward: input.forward ?? {},
    });
  });

  const proxy = createHttpServer();
  proxy.on("request", (req, res) => {
    void handleMitmRequest(req, res, {
      routes: input.routes,
      routesByHost,
      secretByName,
      forward: input.forward ?? {},
    });
  });
  proxy.on("connect", (req, socket, head) => {
    const host = hostFromAuthority(req.url ?? "");
    if (host == null || !routesByHost.has(host)) {
      socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }
    let leaf = leafCache.get(host);
    if (leaf == null) {
      leaf = leafForHost(ca, host);
      leafCache.set(host, leaf);
    }
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length > 0) socket.unshift(head);
    const tlsSocket = new tls.TLSSocket(socket, {
      isServer: true,
      key: leaf.keyPem,
      cert: leaf.certPem,
    });
    decryptedHttp.emit("connection", tlsSocket);
  });

  const port = await new Promise<number>((resolve, reject) => {
    proxy.listen(input.port ?? 0, "127.0.0.1", () => {
      const address = proxy.address();
      if (address == null || typeof address === "string") {
        reject(new Error("proxy failed to bind"));
        return;
      }
      resolve(address.port);
    });
  });

  const caDirectory = mkdtempSync(join(tmpdir(), "poc-vault-ca-"));
  chmodSync(caDirectory, 0o700);
  const caPath = join(caDirectory, "ca.pem");
  writeFileSync(caPath, ca.certPem, { mode: 0o600 });
  chmodSync(caPath, 0o600);

  return {
    port,
    caPem: ca.certPem,
    caPath,
    dummyEnv: dummyEnvFor(input.secrets, input.routes),
    stop: async () => {
      await new Promise<void>((resolve, reject) => {
        proxy.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
      decryptedHttp.close();
      rmSync(caDirectory, { force: true, recursive: true });
    },
  };
}

async function handleMitmRequest(
  req: IncomingMessage,
  res: ServerResponse,
  input: {
    routes: RouteRecord[];
    routesByHost: Map<string, RouteRecord>;
    secretByName: Map<string, SecretRecord>;
    forward: Record<string, string>;
  },
): Promise<void> {
  try {
    const incomingUrl =
      req.url != null && (req.url.startsWith("http://") || req.url.startsWith("https://"))
        ? new URL(req.url)
        : null;
    if (incomingUrl?.protocol === "http:") throw new Error("proxy routes require HTTPS");
    const host =
      incomingUrl?.hostname.toLowerCase() ?? hostFromAuthority(req.headers.host ?? "");
    if (host == null) throw new Error("proxy request is missing a host");
    const route = input.routesByHost.get(host);
    if (route == null) throw new Error(`proxy destination is not configured: ${host}`);
    if (incomingUrl != null && hostFromAuthority(req.headers.host ?? "") !== host) {
      throw new Error("proxy host header does not match request URL");
    }
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks);
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value == null || name === "host") continue;
      headers.set(name, Array.isArray(value) ? value.join(",") : value);
    }
    for (const name of route.stripHeaders) headers.delete(name);
    const secret = input.secretByName.get(route.secretName);
    if (secret != null) applyInject(headers, route.inject, secret.value);
    const originBase = proxyOrigin(route, input.forward);
    const path =
      incomingUrl != null
        ? `${incomingUrl.pathname}${incomingUrl.search}`
        : (req.url ?? "/");
    if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) {
      throw new Error("proxy request path is invalid");
    }
    const origin = new URL(originBase);
    const url = new URL(path, origin);
    if (url.origin !== origin.origin)
      throw new Error("proxy request escaped its configured origin");
    const upstream = await fetch(url, {
      method: req.method,
      headers,
      body:
        body.length > 0 && req.method !== "GET" && req.method !== "HEAD"
          ? body
          : undefined,
    });
    const responseHeaders: Record<string, string> = {};
    upstream.headers.forEach((value, name) => {
      if (name === "transfer-encoding") return;
      responseHeaders[name] = value;
    });
    const payload = Buffer.from(await upstream.arrayBuffer());
    res.writeHead(upstream.status, responseHeaders);
    res.end(payload);
  } catch (error) {
    res.writeHead(502, { "content-type": "text/plain" });
    res.end(error instanceof Error ? error.message : "proxy error");
  }
}

function hostFromAuthority(authority: string): string | null {
  try {
    return new URL(`https://${authority}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function isPublicRouteHost(host: string): boolean {
  return host !== "localhost" && !host.endsWith(".localhost") && isIP(host) === 0;
}

function proxyOrigin(route: RouteRecord, forward: Record<string, string>): string {
  const configured = forward[route.host];
  if (configured == null) return `https://${route.host}`;
  const url = new URL(configured);
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("proxy forwarding is limited to HTTPS or loopback HTTP");
  }
  return url.origin;
}

export function proxyChildEnv(
  handle: ProxyHandle,
  extra: Record<string, string | undefined>,
): ProcessEnvironment {
  const child: Record<string, string | undefined> = { ...extra };
  delete child.VAULT_API_KEY;
  delete child.VAULT_API_URL;
  return {
    ...child,
    ...handle.dummyEnv,
    HTTPS_PROXY: `http://127.0.0.1:${handle.port}`,
    HTTP_PROXY: `http://127.0.0.1:${handle.port}`,
    NO_PROXY: "localhost,127.0.0.1",
    NODE_USE_ENV_PROXY: "1",
    SSL_CERT_FILE: handle.caPath,
    NODE_EXTRA_CA_CERTS: handle.caPath,
    REQUESTS_CA_BUNDLE: handle.caPath,
    CURL_CA_BUNDLE: handle.caPath,
    GIT_SSL_CAINFO: handle.caPath,
    NODE_TLS_REJECT_UNAUTHORIZED: extra.NODE_TLS_REJECT_UNAUTHORIZED,
  };
}
