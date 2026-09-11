import { SignJWT, importPKCS8 } from 'jose';
import { randomUUID } from 'node:crypto';

import { requireEnv } from '../utils/require-env.js';
import type { TundaIssuer } from './issuers.js';

/**
 * Authenticating to Tunda with a signed assertion instead of a shared secret
 * (RFC 7523 §3, and ADR 0036's preferred method).
 *
 * ## What this replaced, and why it is better
 *
 * A `client_secret` is a bearer credential. It has to be transmitted on every
 * back-channel call, it sits in the environment of every replica, rotating it is a
 * coordinated deployment, and anything that can read it — a log, a heap dump, an
 * environment listing — becomes this console.
 *
 * A signing key is none of those. The private half never leaves this process;
 * Tunda holds only the public half, which is worthless to somebody who steals its
 * database. Each assertion is single-use and expires in a minute, so capturing one
 * off the wire buys nothing.
 *
 * ## Why the key is a file and not generated
 *
 * The same reason `CONSOLE_SESSION_KEY` is not generated. A key this process made
 * for itself would differ per replica, so half the token exchanges would be
 * refused; and it would change on restart, so a registration would have to be
 * updated every deploy. The private key is configuration, and Tunda is told the
 * public half once.
 */

/** The only assertion type Tunda accepts (RFC 7523 §2.2). */
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/**
 * How long an assertion is valid.
 *
 * Sixty seconds. Long enough to survive clock skew and a slow network, short
 * enough that a captured one is worth almost nothing even before Tunda's replay
 * check sees it. Tunda refuses anything valid for more than five minutes.
 */
const LIFETIME_SECONDS = 60;

let cachedKey: CryptoKey | null = null;

async function signingKey(): Promise<CryptoKey> {
	if (cachedKey !== null) {
		return cachedKey;
	}
	// PKCS#8 PEM, which is what `openssl pkcs8` produces and what every key
	// management system exports. Read once: parsing on every token exchange would
	// put a key derivation on the sign-in path for no benefit.
	cachedKey = (await importPKCS8(requireEnv('TUNDA_CLIENT_PRIVATE_KEY'), 'ES256')) as CryptoKey;
	return cachedKey;
}

/**
 * Proves the key is present and parseable, at boot.
 *
 * Without this the first failure is a sign-in that gets all the way to the token
 * exchange and dies there — after the person has already authenticated with
 * Tunda, which is the worst possible moment to discover a configuration error.
 */
export async function verifySigningKey(): Promise<void> {
	await signingKey();
}

/**
 * The form parameters that authenticate this console for one request.
 *
 * `aud` is the token endpoint as Tunda advertises it — built from the **public**
 * issuer, not from `internalIssuer`. That distinction is the point of the
 * audience check: Tunda compares this against its own configured identity, and an
 * assertion naming the address we happen to reach it on would be an assertion for
 * a server that does not exist by that name.
 */
export async function clientAssertion(issuer: TundaIssuer): Promise<Record<string, string>> {
	const assertion = await new SignJWT({})
		.setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: issuer.keyId })
		.setIssuer(issuer.clientId)
		.setSubject(issuer.clientId)
		.setAudience(`${issuer.issuer}/oauth2/token`)
		// Fresh per assertion, and the thing Tunda's replay check keys on. A reused
		// one is refused — which is the property that makes a captured assertion
		// useless rather than merely short-lived.
		.setJti(randomUUID())
		.setIssuedAt()
		.setExpirationTime(`${LIFETIME_SECONDS}s`)
		.sign(await signingKey());

	return { client_assertion_type: ASSERTION_TYPE, client_assertion: assertion };
}
