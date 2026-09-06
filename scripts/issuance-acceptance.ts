import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import forge from "node-forge";
import { chromium } from "playwright";
import { z } from "zod";
import { issuanceFixture, fixtureIds, fixturePlan } from "../src/issuance/fixture.ts";

const output = resolve(import.meta.dir, "../.wrangler/issuance-acceptance");
mkdirSync(output, { recursive: true });
const keys = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const cert = forge.pki.createCertificate();
cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKey);
cert.serialNumber = "01";
cert.validity.notBefore = new Date(Date.now() - 60000);
cert.validity.notAfter = new Date(Date.now() + 3600000);
cert.setSubject([{ name: "commonName", value: "localhost" }]);
cert.setIssuer(cert.subject.attributes);
cert.setExtensions([
  {
    name: "subjectAltName",
    altNames: [
      { type: 2, value: "localhost" },
      { type: 7, ip: "127.0.0.1" },
    ],
  },
]);
cert.sign(forge.pki.privateKeyFromPem(keys.privateKey), forge.md.sha256.create());
const fixture = await issuanceFixture();
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  tls: { key: keys.privateKey, cert: forge.pki.certificateToPem(cert) },
  fetch: async (request) => {
    const response = await fixture.app.fetch(request, fixture.env);
    const location = response.headers.get("Location");
    if (location?.startsWith("https://github.com/login/oauth/authorize?")) {
      const authorization = new URL(location);
      const callback = new URL(authorization.searchParams.get("redirect_uri") ?? "");
      callback.searchParams.set("state", authorization.searchParams.get("state") ?? "");
      callback.searchParams.set("code", "101");
      const headers = new Headers(response.headers);
      headers.set("Location", callback.href);
      return new Response(null, { status: 302, headers });
    }
    return response;
  },
});
const origin = `https://127.0.0.1:${server.port}`;
await fixture.admin({
  action: "identity",
  config: { origin, clientId: "synthetic-client", clientSecret: "synthetic-secret" },
});
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1000, height: 1000 },
  });
  // The server substitutes the synthetic identity provider's redirect. All Vault requests use HTTPS.
  await context.route("**/*", async (route) => {
    if (new URL(route.request().url()).origin === origin) await route.continue();
    else await route.abort();
  });
  const request = context.request;
  const verifier = "d".repeat(64);
  const started = await request.post(`${origin}/issuance/devices`, {
    data: { challenge: await fixture.crypto.sha256(verifier), label: "Acceptance MCP" },
  });
  const device = z
    .object({ deviceId: z.string(), verificationUrl: z.string() })
    .parse(await started.json());
  const page = await context.newPage();
  await page.goto(device.verificationUrl);
  await page.getByRole("link", { name: "Continue with GitHub" }).click();
  await page.waitForLoadState("networkidle");
  await page.getByRole("combobox").selectOption(fixtureIds.tenant);
  await page.screenshot({ path: `${output}/connection.png`, fullPage: true });
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await page.waitForLoadState("networkidle");
  await page.getByRole("heading", { name: "Connection approved" }).waitFor();
  const polled = await request.post(`${origin}/issuance/devices/poll`, {
    data: { deviceId: device.deviceId, verifier },
  });
  const { token } = z.object({ token: z.string() }).parse(await polled.json());
  const headers = { Authorization: `Bearer ${token}` };
  const plan = fixturePlan();
  const prepared = await request.post(`${origin}/issuance/requests`, {
    headers,
    data: plan,
  });
  assert.equal(prepared.status(), 201);
  const premature = await request.post(
    `${origin}/issuance/requests/${plan.requestId}/execute`,
    { headers },
  );
  assert.equal(premature.status(), 409);
  await page.goto(`${origin}/issuance/approve/${plan.requestId}`);
  await page.getByRole("button", { name: "Approve once" }).waitFor();
  assert.match((await page.textContent("main")) ?? "", new RegExp(fixtureIds.zone));
  await page.screenshot({ path: `${output}/approval.png`, fullPage: true });
  await page.getByRole("button", { name: "Approve once" }).click();
  await page.getByText("Return to your AI to continue.").waitFor();
  const issued = await request.post(
    `${origin}/issuance/requests/${plan.requestId}/execute`,
    { headers },
  );
  assert.equal(issued.status(), 200);
  assert.doesNotMatch(await issued.text(), /synthetic-(?:child|parent)/);
  const used = await request.post(`${origin}/issuance/requests/${plan.requestId}/use`, {
    headers,
    data: { method: "GET", path: `/zones/${"b".repeat(32)}/dns_records` },
  });
  assert.equal(used.status(), 200);
  assert.match(await used.text(), /example.test/);
  const provision = {
    ...fixturePlan(),
    purpose: "Create the app-data database",
    operation: {
      kind: "api-request",
      request: {
        method: "POST",
        path: `/accounts/${fixtureIds.account}/d1/database`,
        body: { kind: "json", value: { name: "app-data" } },
      },
    },
  };
  assert.equal(
    (
      await request.post(`${origin}/issuance/requests`, { headers, data: provision })
    ).status(),
    201,
  );
  await page.goto(`${origin}/issuance/approve/${provision.requestId}`);
  assert.match((await page.textContent("main")) ?? "", /d1\/database/);
  assert.match((await page.textContent("main")) ?? "", /app-data/);
  await page.screenshot({ path: `${output}/provisioning.png`, fullPage: true });
  await page.getByRole("button", { name: "Approve once" }).click();
  await page.getByText("Return to your AI to continue.").waitFor();
  const provisioned = await request.post(
    `${origin}/issuance/requests/${provision.requestId}/execute`,
    { headers },
  );
  assert.equal(provisioned.status(), 200);
  assert.match(await provisioned.text(), /synthetic-database-id/);
  const revoked = await request.post(
    `${origin}/issuance/requests/${plan.requestId}/revoke`,
    { headers },
  );
  assert.equal(revoked.status(), 200);
  assert.equal(fixture.tokens.size, 0);
  const denied = await request.post(`${origin}/issuance/requests/${plan.requestId}/use`, {
    headers,
    data: { method: "GET", path: `/zones/${"b".repeat(32)}/dns_records` },
  });
  assert.equal(denied.status(), 403);
  const receipt = {
    passed: true,
    provider: "synthetic Cloudflare and GitHub",
    browser: "Chromium",
    transport: "real local HTTPS",
    proof: [
      "browser sign-in",
      "tenant connection approval",
      "issuance denied before approval",
      "exact-scope human approval",
      "provisioning body shown and approved in browser",
      "one child token",
      "brokered use",
      "revocation stops use",
    ],
    ...fixture.counts(),
  };
  writeFileSync(`${output}/receipt.json`, JSON.stringify(receipt, null, 2) + "\n");
  console.log(JSON.stringify(receipt));
  console.log(`Acceptance screenshots and receipt: ${output}`);
} finally {
  await browser.close();
  await server.stop(true);
}
