import { createRemoteJWKSet, type JWTVerifyGetKey } from 'jose';

import { requireEnv, requireUrlEnv } from '../utils/require-env.js';

/**
 * The Tunda issuers this console will accept a token from.
 *
 * ## A closed set, configured, never discovered
 *
 * An issuer is added here by configuration and by nothing else. No request
 * parameter, no host header, no claim inside a token can introduce one — because
 * a provider that learned which issuer to trust from the token it was verifying
 * would trust every token.
 *
 * ## Why it is a set when there is one member
 *
 * Because the alternative — a single `TUNDA_ISSUER` string — is the decision that
 * turns per-tenant consoles into a rewrite instead of a registration. Tunda issues
 * per tenant; a customer-facing console is the same code with more entries here
 * (ADR 0036, and §7.4 of the console specification).
 *
 * Every session is bound to exactly one issuer at creation and is never re-bound.
 */

export type TundaIssuer = {
	/** The tenant whose issuer this is, as it appears in the issuer URL. */
	readonly tenantId: string;

	/**
	 * The exact issuer string, compared byte for byte against the `iss` claim.
	 *
	 * Tunda's issuer never ends in a slash, and its contract says strict validators
	 * compare exactly. This console is a strict validator: no normalisation, no
	 * trailing-slash tolerance.
	 */
	readonly issuer: string;

	/**
	 * Where this console reaches Tunda for server-to-server calls — the token
	 * endpoint and the JWKS.
	 *
	 * Defaults to {@link issuer} and is usually the same string. It exists because
	 * an issuer is an *identifier* and an endpoint is a *location*, and in a real
	 * deployment they differ: the public issuer is `https://id.example.com/t/…`
	 * while the console reaches the node inside a mesh at
	 * `http://tunda-node.identity.svc`. Forcing the back channel through the public
	 * name puts egress, TLS termination and a public DNS lookup on the path that
	 * verifies every token.
	 *
	 * It changes where bytes are fetched from and never what `iss` must equal. The
	 * browser-facing URLs — authorize, and RP-initiated logout — always use
	 * {@link issuer}, because those are addresses a person's browser resolves.
	 */
	readonly internalIssuer: string;

	readonly clientId: string;
	/**
	 * The `kid` of the key this console signs client assertions with.
	 *
	 * Sent in the assertion header so Tunda knows which registered key to check
	 * against. That is what makes rotation possible without a flag day: register
	 * the new key, switch this, remove the old one — three deployments, none of
	 * which has to happen at the same instant as another.
	 */
	readonly keyId: string;

	/**
	 * The audience this console's tokens are minted for.
	 *
	 * Its own, never Tunda's management API audience. That separation is what stops
	 * a token stolen from here being usable against the platform, and a token stolen
	 * from the platform being usable here.
	 */
	readonly audience: string;

	readonly scopes: readonly string[];

	/** Where the browser is sent back to. Registered in Tunda by exact string match. */
	readonly redirectUri: string;

	/**
	 * The verification keys, fetched and cached by `jose`.
	 *
	 * Cached with a hard TTL matching the JWKS endpoint's own `Cache-Control`, and
	 * rate-limited on a cache miss so an unknown `kid` cannot be used to make this
	 * console hammer Tunda on demand.
	 */
	readonly jwks: JWTVerifyGetKey;
};

/** How long a fetched key set is reused. Tunda serves JWKS with `max-age=300`. */
const JWKS_CACHE_MS = 5 * 60 * 1000;

/**
 * The shortest interval between two fetches prompted by an unknown `kid`.
 *
 * Without it, a caller presenting tokens with random `kid` values turns this
 * console into a request amplifier pointed at the identity platform.
 */
const JWKS_COOLDOWN_MS = 60 * 1000;

/**
 * The one value that has to be right.
 *
 * `TUNDA_ISSUER` is the **complete** issuer, exactly as it appears in a token's
 * `iss` claim — `https://id.example.com/t/tnt_01K3ST…`, not the origin.
 *
 * It used to be the origin, with `/t/{TUNDA_TENANT_ID}` appended here. Two
 * variables composed into the string that actually gets compared, which meant
 * the value nobody configured directly was the only one that mattered, and
 * setting `TUNDA_ISSUER` to the thing it is named after produced a doubled path
 * and a flat "issuer is not configured" on every token. Nothing consumed the
 * tenant id separately, so the composition bought nothing and cost that.
 *
 * Now there is one source of truth, compared verbatim, and the tenant is read
 * back out of it.
 */
function buildIssuer(): TundaIssuer {
	const issuer = requireUrlEnv('TUNDA_ISSUER').replace(/\/+$/, '');

	// `/t/{tenantId}` is the tenant-issuer shape every Tunda issuer has. Refused
	// rather than defaulted: an issuer without it is either a misconfiguration or
	// a different product, and guessing at the tenant would mean this console
	// silently believed it was serving one it was not.
	const tenantId = /\/t\/([^/]+)$/.exec(issuer)?.[1];
	if (tenantId === undefined) {
		throw new Error(
			`TUNDA_ISSUER must be a full tenant issuer ending in /t/{tenantId}, e.g.` +
				` https://id.example.com/t/tnt_01K3ST0000E008000000000081 — got '${issuer}'.`
		);
	}

	// Same shape as `issuer`, so a mesh address that forgot the tenant path fails
	// here rather than 404ing at the first token exchange.
	const internalIssuer = (process.env['TUNDA_INTERNAL_ISSUER'] ?? issuer).replace(/\/+$/, '');

	return {
		tenantId,
		internalIssuer,
		issuer,
		clientId: requireEnv('TUNDA_CLIENT_ID'),
		keyId: requireEnv('TUNDA_CLIENT_KEY_ID'),
		audience: requireEnv('TUNDA_AUDIENCE'),
		scopes: ['openid', 'profile', 'offline_access', 'observability.read'],
		redirectUri: requireEnv('TUNDA_REDIRECT_URI'),
		// Fetched from the internal address. See `internalIssuer` above — and note
		// that in this repository's own development stack the two genuinely differ:
		// the issuer is `id.tunda.localhost`, and `.localhost` is loopback by
		// RFC 6761, so Bun's `fetch` short-circuits it before DNS is consulted and
		// a container that resolves the name correctly still connects to itself.
		// The symptom was a bare `TypeError` on every token.
		jwks: createRemoteJWKSet(new URL(`${internalIssuer}/oauth2/jwks`), {
			cacheMaxAge: JWKS_CACHE_MS,
			cooldownDuration: JWKS_COOLDOWN_MS
		})
	};
}

let registry: ReadonlyMap<string, TundaIssuer> | null = null;

/**
 * Builds the registry once, at boot.
 *
 * Deliberately eager: a console that started with an unreadable issuer
 * configuration and failed on the first sign-in would report healthy while being
 * unusable. Missing configuration is a process that does not start.
 */
export function initIssuers(): void {
	if (registry !== null) {
		throw new Error('initIssuers has already been called');
	}
	const issuer = buildIssuer();
	registry = new Map([[issuer.issuer, issuer]]);
}

/** Every configured issuer. Used by the sign-in route, which has exactly one to offer. */
export function issuers(): readonly TundaIssuer[] {
	if (registry === null) {
		throw new Error('issuers() called before initIssuers(); ensure the boot sequence ran');
	}
	return [...registry.values()];
}

/**
 * The issuer a token claims to come from, if this console trusts it.
 *
 * `undefined` for anything else — including a well-formed Tunda issuer for a
 * tenant this console was not configured for. There is no fallback and no "the
 * only one" shortcut: a lookup that returned the sole configured issuer whatever
 * was asked would accept a token minted for a different tenant.
 */
export function issuerFor(claimedIssuer: string | undefined): TundaIssuer | undefined {
	if (registry === null) {
		throw new Error('issuerFor() called before initIssuers(); ensure the boot sequence ran');
	}
	if (claimedIssuer === undefined) {
		return undefined;
	}
	return registry.get(claimedIssuer);
}

/** The single issuer, for the sign-in route. Throws if the set is not exactly one. */
export function theIssuer(): TundaIssuer {
	const all = issuers();
	if (all.length !== 1) {
		throw new Error(
			`Expected exactly one configured issuer for this deployment, found ${all.length}.` +
				' A multi-issuer console must choose one per request rather than assuming.'
		);
	}
	return all[0]!;
}
