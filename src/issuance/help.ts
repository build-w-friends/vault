const docs = "https://vault.buildwithfriends.dev";

const commands = {
  connect: `vault issuance connect cloudflare [--api-url URL]

Connect a Cloudflare account without entering JSON or resource IDs.
Uses the existing Vault operator login. Run vault issuance setup first if GitHub
sign-in is not configured. An interactive terminal is required.

Choose or create a Vault tenant. Open a prefilled Cloudflare account-token page,
review its permissions, create the token, and paste it once into a hidden prompt.
Vault discovers accounts and zones, verifies the token and token-management grant,
then asks you to choose sharing, a child-token lifetime, and a connection name.
Nothing is saved until you confirm the review. No provider services are created.

The template includes Account API Tokens Edit, Account Settings Read, Zone Read,
Workers Scripts, KV, R2, and D1 Edit. Adjust service permissions in Cloudflare.
For selected-member sharing, enter GitHub usernames; Vault resolves their IDs and
requires existing membership. Add members with vault issuance setup.

This flow creates an account-owned API token in Cloudflare's dashboard. It is not
Cloudflare OAuth; a registered OAuth client and verified token-management scopes
are prerequisites for a future direct browser authorization flow.

Guide: ${docs}/start/connect-cloudflare/`,
  setup: `vault issuance setup [--api-url URL]

Guide an operator through GitHub sign-in configuration or adding tenant members.
Uses vault login credentials and requires an interactive terminal.
For initial sign-in, open GitHub's OAuth app page, use the displayed callback,
and supply its Client ID and hidden client secret. Review before saving.
For members, choose a tenant and enter a GitHub username; Vault resolves the ID.

Next: vault issuance connect cloudflare`,
  login: `vault issuance login --api-url URL

Connect this operating system account to a Vault tenant through GitHub.
Open the printed URL, verify the connection ID, sign in, and select your tenant.
The CLI waits up to ten minutes and retries temporary connection failures.
Membership must already exist in Vault.

The member session lasts up to eight hours and is saved with mode 0600 at
~/.config/poc-vault/issuance.json. It is separate from the operator login.
Connecting permits discovery and requests; each parent operation still needs
approval in the signed-in browser. No vault.json or provider token is needed.

Next: configure your AI client to run vault issuance mcp.`,
  mcp: `vault issuance mcp [--api-url URL]

Serve the AI tools over stdio using the saved member session. Run issuance login
first. An optional --api-url must match the saved session's origin.
Configure your MCP client with:

{
  "mcpServers": {
    "vault": { "command": "vault", "args": ["issuance", "mcp"] }
  }
}

Use an absolute executable path if your client cannot find vault on PATH.
The client starts this process; stdout is reserved for MCP messages.
No operator or provider credential belongs in the client configuration.

Tools:
  list_issuers       Discover eligible parent credentials without their values.
  prepare_request   Save an exact api-request or create-token operation.
  request_approval  Ask the person to review the returned Vault browser URL.
  request_status    Read approval, execution, result, and credential state.
  execute_request   Run the exact operation after browser approval.
  use_credential    Send an API request using a managed child reference.
  cancel_request    Cancel a pending request or revoke a managed child token.

API requests support Cloudflare account/zone paths, query parameters, JSON,
multipart Worker uploads, and non-streaming AI requests. Token creation uses
Cloudflare's native permission groups and resource policies. Available scopes
also depend on the issuer and provider permissions.

A chat reply or MCP confirmation cannot approve parent use. Never retry an
uncertain mutation automatically; inspect request_status and provider state.
Cancellation cannot undo an API call already admitted.
Credential use allows 60 calls per minute per tenant. Outputs and references last
at most 24 hours, ending earlier when session or issuer access is revoked.

Tool inputs and examples: ${docs}/reference/mcp/`,
  admin: `vault issuance admin [--api-url URL]

Configure shared issuers using the existing operator login or VAULT_API_KEY.
Read one JSON record from hidden terminal input or stdin. Never place credentials
in shell arguments, history, or workspace files.

Actions and required fields:
  identity        config: { origin, clientId, clientSecret }
  tenant          id (UUID), label
  member          tenantId, subject (numeric GitHub ID), operation: add|remove
  issuer          id, tenantId, label, parentToken, audience, policy
  revoke-issuer   issuerId
  revoke-session  sessionId

Issuer audience is "tenant" or an array of GitHub ID strings. Policy contains
accountId, zoneIds, and maxTtlSeconds (60-86400). Selected people must also be
current tenant members. Parent tokens need the service permissions they will use;
managed token creation also needs Cloudflare Account API Tokens Edit.

Issuer records are immutable. Revoke and register a new issuer to change its
parent, audience, or policy. Revocation blocks subsequent Vault use; provider
cleanup follows. These administrative actions apply immediately, without a
browser approval or --yes flag. Only member-requested parent use uses that form.

Configuration records: ${docs}/concepts/approved-issuance/#configure-as-an-operator`,
  inspect: `vault issuance inspect REQUEST_ID [--api-url URL]

Use the operator login to print a request and its audit events as JSON.
REQUEST_ID is the UUID used by prepare_request. Provider credential values are
not returned. This does not approve, execute, retry, or cancel the request.

For unknown outcomes, inspect provider state before preparing another mutation.
An AI session uses request_status for its own requests. Stored outputs are removed
after 24 hours or loss of access; request state and audit events remain.`,
  logout: `vault issuance logout

Revoke the saved member session on its Vault server, then remove
~/.config/poc-vault/issuance.json. Subsequent child use through Vault is blocked;
provider token cleanup follows. Already admitted API calls cannot be undone.

The operator login is separate and remains available. If the server cannot be
reached, logout fails and keeps the local file so revocation can be retried.
An operator can revoke a session using vault issuance admin.`,
} satisfies Record<string, string>;

export function issuanceHelp(topic?: string): string {
  if (topic !== undefined) {
    const text = new Map(Object.entries(commands)).get(topic);
    if (text === undefined)
      throw new Error(`unknown issuance command: ${topic}; run vault issuance --help`);
    return text;
  }
  return `vault issuance <command>

Let AI provision services and create scoped tokens using shared credentials.
Vault discovers what is available to the signed-in tenant member, records the
exact request, and requires browser approval before using a parent token.
Provider credentials stay in Vault; AI receives results and secret references.

  setup                Configure GitHub sign-in or add tenant members.
  connect cloudflare   Guided Cloudflare registration without JSON.
  login --api-url URL   Connect through GitHub and select a tenant.
  mcp                  Start the stdio tools for your AI client.
  logout               Revoke the member session and remove its local file.
  admin                Read an operator configuration record from hidden input/stdin.
  inspect REQUEST_ID   Read operator request and audit evidence without values.

Run vault issuance COMMAND --help for command details.
Works from any directory without vault.json. This is separate from project-secret
management through vault run, vault proxy, and the HTTP /mcp endpoint.

Start here: ${docs}/start/provision-services/
MCP reference: ${docs}/reference/mcp/`;
}
