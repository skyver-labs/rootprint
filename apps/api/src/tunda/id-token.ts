import { createHash } from 'node:crypto';

import { jwtVerify, type JWTPayload } from 'jose';

import { constantTimeEquals, digest } from './crypto.js';
import type { TundaIssuer } from './issuers.js';

/**
 * Verifying the ID token, which this console did not do at all.
 *
 * ## What was missing
 *
 * The flow requested `openid profile`, stored a hash of the `nonce` it sent, and
 * then read nothing out of the `id_token` that came back — not the nonce, not the
 * `at_hash`, not the subject. The token was passed to `createSession` as an opaque
 * string to be handed back at logout.
 *
 * That is not a cosmetic omission. OIDC Core §3.1.3.7 makes the nonce comparison
 * the relying party's replay defence, and a relying party that stores the nonce
 * and never compares it has the cost of the defence and none of it. The column was
 * there. The digest was computed. Nothing read it.
 *
 * ## Six checks
 *
 * 1. **ES256 pinned here**, never read from the token's own header.
 * 2. **The signature verifies** against the issuer's JWKS — the same key set the
 *    access token is checked against, so a forged ID token needs Tunda's key.
 * 3. **`iss` matches exactly and `aud` is this console's `client_id`.** Not the
 *    API audience: an ID token names the client it was issued to, and one naming
 *    a resource server would be a bearer credential at that resource server.
 * 4. **`nonce` matches the transaction**, compared as a digest in constant time —
 *    the plaintext was never stored, and this is why it was hashed.
 * 5. **`at_hash` binds the access token** presented alongside. Without it, an ID
 *    token from one authentication can be paired with an access token from
 *    another, and every claim read here would describe the wrong person.
 * 6. **`sub` and `sid` agree with the access token.** Belt and braces over the
 *    `at_hash`, and the check that makes the profile claims safe to attribute:
 *    the name written against a principal row comes from this token, and the
 *    principal row is keyed by the access token's subject.
 *
 * ## Why the profile claims are read from here and not from the access token
 *
 * Because that is where they are. Tunda emits `name`, `email` and `email_verified`
 * into the ID token when `profile` or `email` was granted — an access token is a
 * capability presented to a resource server, and putting a person's name in one
 * would send it to every API the token reaches.
 */

/** The only algorithm accepted. A constant, never a value from the token. */
const PERMITTED_ALGORITHMS = ['ES256'] as const;

/** Tolerance for clock drift between Tunda and this console. */
const CLOCK_SKEW_SECONDS = 60;

/**
 * What the granted scopes actually yielded.
 *
 * Every field optional, and absence is meaningful rather than a default: an
 * account with no display name produces no `name` claim, and this console shows
 * the subject identifier instead of inventing something to put on screen.
 */
export type SubjectProfile = {
	readonly name?: string;
	readonly email?: string;
	readonly emailVerified?: boolean;
};

export class IdTokenRejected extends Error {
	constructor(readonly reason: string) {
		super(`id token rejected: ${reason}`);
		this.name = 'IdTokenRejected';
	}
}

export type IdTokenExpectations = {
	/**
	 * The digest of the nonce this console sent, as stored on the transaction.
	 *
	 * Absent on a refresh: OIDC Core §12.2 says an ID token from a refresh carries
	 * the nonce of the original authentication or none, and there is no transaction
	 * row to compare against by then. The other five checks still run.
	 */
	readonly nonceHash?: Buffer;

	/** The access token issued alongside, hashed into `at_hash`. */
	readonly accessToken: string;

	/** The `sub` the access token asserted. */
	readonly subject: string;

	/** The `sid` the access token asserted. */
	readonly sessionId: string;
};

/**
 * Verifies an ID token and returns the profile claims it carries.
 *
 * Throws {@link IdTokenRejected} on any failure. The caller treats that as a
 * failed sign-in rather than as a sign-in without a name: a token that cannot be
 * verified says nothing about who authenticated, and proceeding on the access
 * token alone would mean the ID token's checks are optional in practice.
 */
export async function verifyIdToken(
	idToken: string,
	issuer: TundaIssuer,
	expected: IdTokenExpectations
): Promise<SubjectProfile> {
	let payload: JWTPayload;
	try {
		({ payload } = await jwtVerify(idToken, issuer.jwks, {
			algorithms: [...PERMITTED_ALGORITHMS],
			issuer: issuer.issuer,
			// The client, not `issuer.audience`. See check 3.
			audience: issuer.clientId,
			clockTolerance: CLOCK_SKEW_SECONDS
		}));
	} catch (err) {
		throw new IdTokenRejected(err instanceof Error ? err.name : 'verification failed');
	}

	if (expected.nonceHash !== undefined) {
		const nonce = payload['nonce'];
		if (typeof nonce !== 'string' || nonce === '') {
			throw new IdTokenRejected('nonce');
		}
		if (!constantTimeEquals(expected.nonceHash, await digest(nonce))) {
			throw new IdTokenRejected('nonce mismatch');
		}
	}

	const atHash = payload['at_hash'];
	if (typeof atHash !== 'string' || atHash !== accessTokenHash(expected.accessToken)) {
		// Tunda emits `at_hash` on every ID token, so a missing one is as wrong as a
		// mismatched one. Required rather than checked-when-present: "verify it if
		// they sent it" is a check an attacker turns off by not sending it.
		throw new IdTokenRejected('at_hash');
	}

	if (payload.sub !== expected.subject) {
		throw new IdTokenRejected('subject mismatch');
	}
	if (payload['sid'] !== expected.sessionId) {
		throw new IdTokenRejected('session mismatch');
	}

	return {
		name: optionalString(payload, 'name'),
		email: optionalString(payload, 'email'),
		// Only ever read beside an address, and only as a real boolean. A string
		// "false" is not false, and OIDC Core §5.1 warns that some providers send
		// one — treated as absent here, which makes the address unverified.
		emailVerified:
			typeof payload['email_verified'] === 'boolean'
				? (payload['email_verified'] as boolean)
				: undefined
	};
}

/**
 * OIDC Core §3.1.3.6: base64url of the left-most half of the SHA-256 of the
 * access token's ASCII octets.
 *
 * Half of the *digest*, not of the encoded form. Halving the base64 would produce
 * a value that decodes to nothing and compares equal to nothing — which is a bug
 * that fails closed and therefore looks like Tunda sending a wrong `at_hash`.
 */
function accessTokenHash(accessToken: string): string {
	const digested = createHash('sha256').update(accessToken, 'ascii').digest();
	return digested.subarray(0, digested.length / 2).toString('base64url');
}

function optionalString(payload: JWTPayload, claim: string): string | undefined {
	const value = payload[claim];
	return typeof value === 'string' && value !== '' ? value : undefined;
}
