import * as v from "valibot";
export type GitHubAuthorizationExpectation = {
  readonly callbackUrl: string;
  readonly clientId: string;
  readonly pkce: boolean;
  readonly scopes?: readonly string[];
};

/** Validate the public half of a GitHub authorization request without retaining credentials. */
export function assertGitHubAuthorizationUrl(
  value: string,
  expectation: GitHubAuthorizationExpectation,
): URL {
  const url = new URL(value);
  if (url.origin !== "https://github.com" || url.pathname !== "/login/oauth/authorize") {
    throw new Error("authorization did not use GitHub's web application endpoint");
  }
  if (url.searchParams.get("client_id") !== expectation.clientId) {
    throw new Error("authorization used the wrong GitHub client id");
  }
  if (url.searchParams.get("redirect_uri") !== expectation.callbackUrl) {
    throw new Error("authorization used the wrong callback URL");
  }
  if ((url.searchParams.get("state")?.length ?? 0) < 16) {
    throw new Error("authorization did not carry an opaque state value");
  }
  if (url.searchParams.has("client_secret") || url.searchParams.has("code")) {
    throw new Error("authorization URL contained a credential");
  }
  if (expectation.pkce) {
    if (
      url.searchParams.get("code_challenge_method") !== "S256" ||
      (url.searchParams.get("code_challenge")?.length ?? 0) < 32
    ) {
      throw new Error("authorization did not use PKCE S256");
    }
  }
  if (expectation.scopes !== undefined) {
    const actual = new Set(
      (url.searchParams.get("scope") ?? "").split(" ").filter(Boolean),
    );
    const expected = new Set(expectation.scopes);
    if (
      actual.size !== expected.size ||
      [...expected].some((scope) => !actual.has(scope))
    ) {
      throw new Error("authorization requested unexpected GitHub scopes");
    }
  }
  return url;
}

/** Reject GitHub's HTTP-200 OAuth error pages as well as transport errors. */
export function assertGitHubAuthorizationPage(input: {
  readonly body: string;
  readonly status: number;
}): void {
  if (
    input.status >= 400 ||
    /incorrect_client_credentials|invalid redirect uri|redirect_uri[^<\n]*(?:not associated|mismatch)|application[^<\n]*not found/iu.test(
      input.body,
    )
  ) {
    throw new Error("GitHub rejected the OAuth application configuration");
  }
}

export function d1DatabaseIdFromListOutput(output: string, name: string): string {
  const databases = v.parse(
    v.array(
      v.looseObject({
        name: v.optional(v.string()),
        uuid: v.optional(v.string()),
      }),
    ),
    JSON.parse(output),
  );
  const match = databases.find((database) => database.name === name)?.uuid;
  if (!v.is(v.string(), match) || !/^[0-9a-f-]{36}$/iu.test(match)) {
    throw new Error("Wrangler did not list the disposable D1 database id");
  }
  return match;
}

export function deployedWorkersDevUrl(output: string): URL {
  const match = /https:\/\/[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev\/?/iu.exec(output)?.[0];
  if (match === undefined) {
    throw new Error("Wrangler did not report the disposable Worker URL");
  }
  return new URL(match);
}

export function secretsStoreSecretId(output: string, name: string): string {
  for (const line of output.split("\n")) {
    if (!line.includes(name)) continue;
    const id = /\b[0-9a-f]{32}\b/iu.exec(line)?.[0];
    if (id !== undefined) return id;
  }
  throw new Error(`Secrets Store did not list ${name}`);
}
