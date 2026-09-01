/**
 * Route templates for the brokering proxy.
 *
 * A route says three things: which host it covers, which headers to strip from
 * the child's request, and how to attach the real value. The strip list matters
 * as much as the inject template — without it the dummy the child sent would
 * survive alongside the injected credential, and the upstream would see two
 * conflicting values for the same header.
 *
 * @see {@link https://vault.buildwithfriends.com/concepts/brokering/}
 */
export type RoutePreset = {
  host: string;
  inject: string;
  stripHeaders: string[];
  dummyEnvName: string;
  dummyValue: string;
};

const PRESETS: Record<string, RoutePreset> = {
  github: {
    host: "api.github.com",
    inject: "header:Authorization:Bearer",
    stripHeaders: ["authorization"],
    dummyEnvName: "GITHUB_TOKEN",
    dummyValue: "ghp_dummy_vault_placeholder",
  },
  anthropic: {
    host: "api.anthropic.com",
    inject: "header:x-api-key",
    stripHeaders: ["x-api-key"],
    dummyEnvName: "ANTHROPIC_API_KEY",
    dummyValue: "__anthropic_api_key__",
  },
};

export function routePreset(name: string): RoutePreset | null {
  return PRESETS[name] ?? null;
}

export function genericRoute(input: {
  host: string;
  header: string;
  dummyEnvName: string;
  dummyValue?: string;
}): RoutePreset {
  return {
    host: input.host,
    inject: `header:${input.header}`,
    stripHeaders: [input.header.toLowerCase()],
    dummyEnvName: input.dummyEnvName,
    dummyValue: input.dummyValue ?? `__${input.dummyEnvName.toLowerCase()}__`,
  };
}

export function applyInject(headers: Headers, inject: string, value: string): void {
  const parts = inject.split(":");
  const kind = parts[0];
  if (kind !== "header" || parts[1] == null) {
    throw new Error(`unsupported inject template: ${inject}`);
  }
  const headerName = parts[1];
  const scheme = parts[2];
  headers.set(headerName, scheme != null ? `${scheme} ${value}` : value);
}
