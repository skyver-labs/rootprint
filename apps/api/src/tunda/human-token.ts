import { jwtVerify, type JWTPayload } from 'jose';

import { issuerFor, type TundaIssuer } from './issuers.js';

/**
 * Verifying an access token Tunda issued for a person.
 *
 * ## Seven checks, and none of them is optional
 *
 * Each one exists because skipping it admits a specific token this console must
 * not accept. They are listed in the order they run, because the order matters:
 * nothing reads a claim before the signature over it has been checked.
 *
 * 1. **The algorithm is pinned here, not read from the token.** A verifier that
 *    takes `alg` from the header it is verifying accepts `none`, and accepts an
 *    HMAC forged with the public key it was given.
 * 2. **The signature verifies** against a key from the issuer's JWKS.
 * 3. **The issuer matches exactly** — no normalisation, no trailing-slash
 *    tolerance. Tunda's issuer never ends in a slash and its contract says strict
 *    validators compare exactly.
 * 4. **The audience is this console's own.** Without it, a token minted for
 *    Tunda's management API is a token for this console, and vice versa.
 * 5. **`exp` and `iat` hold**, with at most a minute of clock skew.
 * 6. **The scope is present.**
 * 7. **`sub`, `sid`, `acr`, `amr` and `auth_time` are present.** A missing claim
 *    is a refusal, never a default — Tunda's own policy engine holds that absence
 *    never satisfies a condition, and this console applies the same rule at its
 *    boundary. A token that cannot say what was proven cannot be evaluated
 *    against any rule that asks.
 */

/** The only algorithm accepted. A constant here, never a value from the token. */
const PERMITTED_ALGORITHMS = ['ES256'] as const;

/** Tolerance for clock drift between Tunda and this console. */
const CLOCK_SKEW_SECONDS = 60;

/** The scope a human session must carry to be of any use here. */
const REQUIRED_SCOPE = 'observability.read';

export type VerifiedHumanToken = {
	readonly issuer: TundaIssuer;
	readonly subject: string;
	readonly sessionId: string;
	readonly scopes: readonly string[];

	/**
	 * The canonical assurance value, as Tunda emitted it — `urn:tunda:aal:2`.
	 *
	 * Carried through untouched. It is passed back to Tunda's policy decision point
	 * on every authorization call, and a console that reinterpreted it would be
	 * asserting an assurance rather than relaying one.
	 */
	readonly acr: string;
	readonly amr: readonly string[];
	readonly authTime: Date;
	readonly expiresAt: Date;
};

export class TokenRejected extends Error {
	constructor(readonly reason: string) {
		// The reason is for this console's own logs. It never reaches a browser: an
		// expired token and a forged one produce the same response, because telling
		// them apart is a forgery oracle.
		super(`token rejected: ${reason}`);
		this.name = 'TokenRejected';
	}
}

/**
 * Verifies an access token, or throws {@link TokenRejected}.
 *
 * The issuer is resolved from the token's own `iss` claim *and then looked up in
 * the configured set* — a token naming an issuer this console does not trust
 * finds nothing, which is the only way an unknown issuer is handled.
 */
export async function verifyHumanToken(token: string): Promise<VerifiedHumanToken> {
	const claimedIssuer = readIssuerClaim(token);
	const issuer = issuerFor(claimedIssuer);
	if (issuer === undefined) {
		throw new TokenRejected('issuer is not configured');
	}

	let payload: JWTPayload;
	try {
		({ payload } = await jwtVerify(token, issuer.jwks, {
			algorithms: [...PERMITTED_ALGORITHMS],
			issuer: issuer.issuer,
			audience: issuer.audience,
			clockTolerance: CLOCK_SKEW_SECONDS
		}));
	} catch (err) {
		throw new TokenRejected(err instanceof Error ? err.name : 'verification failed');
	}

	const scopes = readScopes(payload);
	if (!scopes.includes(REQUIRED_SCOPE)) {
		throw new TokenRejected('scope');
	}

	return {
		issuer,
		subject: requireString(payload, 'sub'),
		sessionId: requireString(payload, 'sid'),
		scopes,
		acr: requireString(payload, 'acr'),
		amr: readAmr(payload),
		authTime: new Date(requireNumber(payload, 'auth_time') * 1000),
		expiresAt: new Date(requireNumber(payload, 'exp') * 1000)
	};
}

/**
 * The `iss` claim, read without verifying anything.
 *
 * This is the one place an unverified claim is read, and it is safe for exactly
 * one reason: the value is used only as a *lookup key* into a configured set. It
 * selects which trusted key set to verify against; it never establishes trust
 * itself. A token naming an unconfigured issuer resolves to nothing and is
 * refused before a signature is checked.
 *
 * This mirrors how Tunda treats the tenant in a request path: naming a tenant
 * selects a trusted placement record, it does not reach a schema.
 */
function readIssuerClaim(token: string): string | undefined {
	const segments = token.split('.');
	if (segments.length !== 3) {
		return undefined;
	}
	try {
		const payload: unknown = JSON.parse(Buffer.from(segments[1]!, 'base64url').toString('utf8'));
		if (typeof payload === 'object' && payload !== null && 'iss' in payload) {
			const iss = (payload as { iss: unknown }).iss;
			return typeof iss === 'string' ? iss : undefined;
		}
		return undefined;
	} catch {
		return undefined;
	}
}

function readScopes(payload: JWTPayload): string[] {
	const scope = payload['scope'];
	if (typeof scope !== 'string' || scope.trim() === '') {
		return [];
	}
	return scope.trim().split(/\s+/);
}

function readAmr(payload: JWTPayload): string[] {
	const amr = payload['amr'];
	if (!Array.isArray(amr)) {
		// Present but not a list, or absent. Either way this token cannot say how the
		// user authenticated, and a rule asking for a hardware key has nothing to
		// read. Refused rather than defaulted to empty, which would read as "no
		// methods" — indistinguishable from a genuine AAL0.
		throw new TokenRejected('amr');
	}
	return amr.filter((method): method is string => typeof method === 'string');
}

function requireString(payload: JWTPayload, claim: string): string {
	const value = payload[claim];
	if (typeof value !== 'string' || value === '') {
		throw new TokenRejected(claim);
	}
	return value;
}

function requireNumber(payload: JWTPayload, claim: string): number {
	const value = payload[claim];
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new TokenRejected(claim);
	}
	return value;
}
