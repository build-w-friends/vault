import { z } from "zod";
import { adminSchema, cfId, id, subject } from "./contracts.ts";

const namedCloudflareResource = z.object({ id: cfId, name: z.string().min(1) });
export const setupSchema = z.object({
  identityConfigured: z.boolean(),
  tenants: z.array(z.object({ id, label: z.string(), members: z.array(subject) })),
});
type Tenant = z.infer<typeof setupSchema>["tenants"][number];
type Admin = z.infer<typeof adminSchema>;
export type ConnectPrompts = {
  say: (message: string) => void;
  ask: (
    message: string,
    validate?: (value: string) => string | undefined,
  ) => Promise<string>;
  select: <T>(message: string, entries: T[], label: (entry: T) => string) => Promise<T>;
  multiselect: <T>(
    message: string,
    entries: T[],
    label: (entry: T) => string,
  ) => Promise<T[]>;
  confirm: (message: string) => Promise<boolean>;
  intro: (message: string) => void;
  outro: (message: string) => void;
  cancel: (message: string) => void;
  secret: (message: string) => Promise<string>;
  open: (url: string) => Promise<void>;
};

export function cloudflareTokenTemplate() {
  const url = new URL("https://dash.cloudflare.com/");
  url.searchParams.set("to", "/:account/api-tokens");
  url.searchParams.set("name", "Vault shared Cloudflare");
  url.searchParams.set(
    "permissionGroupKeys",
    JSON.stringify([
      { key: "account_api_tokens", type: "edit" },
      { key: "account_settings", type: "read" },
      { key: "zone", type: "read" },
      { key: "workers_scripts", type: "edit" },
      { key: "workers_kv_storage", type: "edit" },
      { key: "workers_r2", type: "edit" },
      { key: "d1", type: "edit" },
    ]),
  );
  return url.href;
}

export class CloudflareDiscovery {
  constructor(
    private readonly token: string,
    private readonly send: typeof fetch = fetch,
  ) {}

  private async request(path: string) {
    let response: Response;
    try {
      response = await this.send(`https://api.cloudflare.com/client/v4${path}`, {
        headers: { Authorization: `Bearer ${this.token}` },
        redirect: "error",
        signal: AbortSignal.timeout(30000),
      });
    } catch {
      throw new Error(
        "Could not reach Cloudflare. Nothing has been registered in Vault.",
      );
    }
    if (!response.ok)
      throw new Error(
        `Cloudflare discovery failed (HTTP ${response.status}). Check Account Settings Read, Zone Read, and Account API Tokens Edit on the token.`,
      );
    const envelope = z
      .object({
        success: z.literal(true),
        result: z.unknown(),
        result_info: z.object({ total_pages: z.number().int().nonnegative() }).optional(),
      })
      .safeParse(await response.json().catch(() => null));
    if (!envelope.success)
      throw new Error("Cloudflare did not return a successful discovery response.");
    return envelope.data;
  }

  private async list(path: string) {
    const found: z.infer<typeof namedCloudflareResource>[] = [];
    for (let page = 1; page <= 100; page++) {
      const envelope = await this.request(
        `${path}${path.includes("?") ? "&" : "?"}page=${page}&per_page=50`,
      );
      const parsed = z.array(namedCloudflareResource).safeParse(envelope.result);
      if (!parsed.success)
        throw new Error("Cloudflare returned invalid account or zone metadata.");
      found.push(...parsed.data);
      if (
        envelope.result_info
          ? page >= envelope.result_info.total_pages
          : parsed.data.length < 50
      )
        return found;
    }
    throw new Error(
      "Cloudflare discovery exceeded 100 pages. Narrow the token's account or zone scope and reconnect.",
    );
  }
  accounts() {
    return this.list("/accounts");
  }
  zones(accountId: string) {
    return this.list(`/zones?account.id=${cfId.parse(accountId)}`);
  }

  async verify(accountId: string) {
    const account = cfId.parse(accountId);
    const envelope = await this.request(`/accounts/${account}/tokens/verify`);
    const verified = z
      .object({ id: cfId, status: z.literal("active") })
      .safeParse(envelope.result);
    if (!verified.success) throw new Error("The Cloudflare account token is not active.");
    const details = await this.request(`/accounts/${account}/tokens/${verified.data.id}`);
    const parsed = z
      .object({
        policies: z.array(
          z.object({
            effect: z.enum(["allow", "deny"]),
            permission_groups: z.array(z.object({ name: z.string() })),
          }),
        ),
      })
      .safeParse(details.result);
    if (!parsed.success)
      throw new Error("Could not inspect the account-owned token's permissions.");
    const names = parsed.data.policies
      .filter((p) => p.effect === "allow")
      .flatMap((p) => p.permission_groups.map((g) => g.name));
    if (!names.some((name) => /^Account API Tokens (Write|Edit)$/.test(name)))
      throw new Error(
        "This token needs Account API Tokens Edit to create managed tokens.",
      );
    return [...new Set(names)];
  }
}

async function choose<T>(
  ui: ConnectPrompts,
  label: string,
  entries: T[],
  name: (entry: T) => string,
): Promise<T> {
  if (entries.length === 0) throw new Error(`No choices available for ${label}.`);
  if (entries.length === 1) {
    const [entry] = entries;
    if (entry !== undefined) {
      ui.say(`${label}: ${name(entry)}`);
      return entry;
    }
  }
  return ui.select(label, entries, name);
}
async function required(ui: ConnectPrompts, label: string) {
  return (
    await ui.ask(label, (value) => {
      const length = value.trim().length;
      return length > 0 && length <= 120
        ? undefined
        : "Enter between 1 and 120 characters.";
    })
  ).trim();
}
async function githubMember(login: string, send: typeof fetch) {
  if (!/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(login))
    throw new Error("Enter a GitHub username, not a URL or ID.");
  const response = await send(`https://api.github.com/users/${login}`, {
    headers: { Accept: "application/vnd.github+json", "User-Agent": "Vault-CLI" },
    redirect: "error",
    signal: AbortSignal.timeout(30000),
  });
  const user = z
    .object({
      id: z.number().int().positive().safe(),
      login: z.string(),
      type: z.literal("User"),
    })
    .safeParse(await response.json());
  if (!response.ok || !user.success)
    throw new Error(`Could not find the GitHub user ${login}.`);
  return { subject: subject.parse(String(user.data.id)), login: user.data.login };
}

export async function connectCloudflare(options: {
  ui: ConnectPrompts;
  setup: z.infer<typeof setupSchema>;
  save: (input: Admin) => Promise<void>;
  send?: typeof fetch;
}) {
  const { ui, setup, save, send = fetch } = options;
  if (!setup.identityConfigured)
    throw new Error(
      "Vault GitHub sign-in is not configured. Run vault issuance setup before connecting Cloudflare.",
    );
  const pending: Admin[] = [];
  const tenantChoice =
    setup.tenants.length === 0
      ? { kind: "new" as const }
      : await choose(
          ui,
          "Vault team",
          [
            ...setup.tenants.map((tenant) => ({ kind: "existing" as const, tenant })),
            { kind: "new" as const },
          ],
          (entry) => (entry.kind === "new" ? "Create a team" : entry.tenant.label),
        );
  let tenant: Tenant;
  if (tenantChoice.kind === "new") {
    const label = await required(ui, "Name your team");
    const member = await githubMember(await required(ui, "Your GitHub username: "), send);
    tenant = { id: crypto.randomUUID(), label, members: [member.subject] };
    pending.push(
      { action: "tenant", id: tenant.id, label },
      {
        action: "member",
        tenantId: tenant.id,
        subject: member.subject,
        operation: "add",
      },
    );
    ui.say(`Create ${label} with member ${member.login}.`);
  } else tenant = tenantChoice.tenant;

  ui.say(
    "Create an account-owned token in Cloudflare. The template includes token management, account/zone discovery, Workers, KV, R2, and D1. Review the permissions there; add other services if needed.",
  );
  const url = cloudflareTokenTemplate();
  ui.say(url);
  if (await ui.confirm("Open Cloudflare in your browser?")) await ui.open(url);
  const parentToken = (await ui.secret("Cloudflare token (hidden): ")).trim();
  if (!parentToken || /\s/.test(parentToken))
    throw new Error("Enter only the Cloudflare token in the hidden prompt.");
  const provider = new CloudflareDiscovery(parentToken, send);
  const account = await choose(
    ui,
    "Cloudflare account",
    await provider.accounts(),
    (a) => `${a.name} (${a.id.slice(0, 8)}…)`,
  );
  const permissions = await provider.verify(account.id);
  ui.say(
    `Token verified. Granted permissions: ${permissions.join(", ")}. Cloudflare enforces the full resource policy on each operation.`,
  );
  const zones = await provider.zones(account.id);
  let zoneIds: string[] = [];
  if (zones.length) {
    ui.say(
      "Account services remain available. Choose which discovered domains may also be used through zone API paths.",
    );
    zoneIds = (
      await ui.multiselect("Allow access to these domains", zones, (zone) => zone.name)
    ).map((zone) => zone.id);
  } else ui.say("No zones are visible to this token. Account services remain available.");

  const sharing = await choose(
    ui,
    "Share with",
    ["Everyone in this team", "Selected current members"],
    (value) => value,
  );
  let audience: "tenant" | string[] = "tenant";
  if (sharing === "Selected current members") {
    const logins = (await required(ui, "GitHub usernames, separated by commas: "))
      .split(",")
      .map((value) => value.trim());
    audience = [];
    for (const login of logins) {
      const user = await githubMember(login, send);
      if (!tenant.members.includes(user.subject))
        throw new Error(
          `${user.login} is not a member of ${tenant.label}. Add them with vault issuance setup first.`,
        );
      audience.push(user.subject);
    }
  }
  const hours = await choose(
    ui,
    "Maximum child-token lifetime",
    [1, 4, 8, 24],
    (value) => `${value} hour${value === 1 ? "" : "s"}`,
  );
  const label = await required(
    ui,
    "Connection name (for example Cloudflare production): ",
  );
  const issuer = adminSchema.parse({
    action: "issuer",
    id: crypto.randomUUID(),
    tenantId: tenant.id,
    label,
    parentToken,
    audience,
    policy: { accountId: account.id, zoneIds, maxTtlSeconds: hours * 3600 },
  });
  ui.say(
    `\nReview connection\n  Name: ${label}\n  Vault team: ${tenant.label}\n  Cloudflare account: ${account.name}\n  Domains: ${
      zones
        .filter((zone) => zoneIds.includes(zone.id))
        .map((zone) => zone.name)
        .join(", ") || "none"
    }\n  Sharing: ${sharing}${audience === "tenant" ? "" : ` (${audience.length} members)`}\n  Child-token lifetime: ${hours} hour${hours === 1 ? "" : "s"}\n  Parent use: approval required every time`,
  );
  if (!(await ui.confirm("Save this connection?"))) {
    ui.cancel(
      "Cancelled. Nothing was saved to Vault. The token you created in Cloudflare still exists.",
    );
    return;
  }
  for (const record of pending) await save(record);
  await save(issuer);
  ui.outro(
    `Connected ${label}. Members can discover it after vault issuance login. No services or child tokens were created.`,
  );
}

export async function setupIssuance(options: {
  ui: ConnectPrompts;
  setup: z.infer<typeof setupSchema>;
  origin: string;
  save: (input: Admin) => Promise<void>;
  send?: typeof fetch;
}) {
  const { ui, setup, origin, save, send = fetch } = options;
  const action = setup.identityConfigured
    ? await choose(
        ui,
        "Vault setup",
        ["Add a team member", "Replace GitHub sign-in configuration"],
        (value) => value,
      )
    : "Replace GitHub sign-in configuration";
  if (action === "Add a team member") {
    const tenant = await choose(ui, "Vault team", setup.tenants, (value) => value.label);
    const member = await githubMember(
      await required(ui, "GitHub username to add: "),
      send,
    );
    if (await ui.confirm(`Add ${member.login} to ${tenant.label}?`)) {
      await save({
        action: "member",
        tenantId: tenant.id,
        subject: member.subject,
        operation: "add",
      });
      ui.outro(`Added ${member.login} to ${tenant.label}.`);
    } else ui.cancel("Cancelled. No membership changes were saved.");
    return;
  }
  if (!origin.startsWith("https://"))
    throw new Error("Browser sign-in requires a Vault HTTPS origin.");
  const url = new URL("https://github.com/settings/applications/new");
  url.searchParams.set("oauth_application[name]", "Vault");
  url.searchParams.set("oauth_application[url]", origin);
  url.searchParams.set(
    "oauth_application[callback_url]",
    `${origin}/issuance/auth/callback`,
  );
  ui.say(
    `Register a GitHub OAuth app for Vault. Homepage: ${origin}\nCallback: ${origin}/issuance/auth/callback\n${url.href}`,
  );
  if (await ui.confirm("Open GitHub in your browser?")) await ui.open(url.href);
  const clientId = await required(ui, "GitHub OAuth Client ID: ");
  const clientSecret = await ui.secret("GitHub OAuth client secret (hidden): ");
  const record = adminSchema.parse({
    action: "identity",
    config: { origin, clientId, clientSecret },
  });
  if (await ui.confirm(`Save GitHub sign-in for ${origin}?`)) {
    await save(record);
    ui.outro(
      "GitHub sign-in configured. Run vault issuance connect cloudflare to create or choose a team and connect its credential.",
    );
  } else ui.cancel("Cancelled. GitHub sign-in was not changed.");
}
