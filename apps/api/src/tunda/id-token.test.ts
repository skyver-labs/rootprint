import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';

import { exportJWK, generateKeyPair, SignJWT, type JWK, type JWTVerifyGetKey } from 'jose';

import { digest } from './crypto.js';
import { IdTokenRejected, verifyIdToken } from './id-token.js';
import type { TundaIssuer } from './issuers.js';

/**
 * The checks the console was not doing.
 *
 * Every case here is a token that was, before `id-token.ts` existed, accepted
 * without being looked at: the `id_token` from a code exchange went straight into
 * encrypted storage to be replayed at logout, and nothing read a claim out of it.
 * The `nonce` in particular was generated, hashed, written to
 * `console_auth_transaction`, and never compared — the whole cost of the defence
 * and none of the defence.
 *
 * So these are not regression tests for a bug that was fixed. They are the first
 * assertions that the checks happen at all, which is why each one is stated as the
 * token it refuses rather than as a method call.
 */

const ISSUER = 'https://id.tunda.localhost/t/tnt_01K3ST0000E008000000000081';
const CLIENT_ID = 'observability-console';
const SUBJECT = 'usr_01K3ST0000E008000000000051';
const SESSION_ID = 'ses_01K3ST0000E008000000000061';
const ACCESS_TOKEN = 'an.access.token';
const NONCE = 'a-nonce-nobody-guessed';

const keys = await generateKeyPair('ES256', { extractable: true });
const publicJwk: JWK = await exportJWK(keys.publicKey);

/** Resolves to the one key these tests sign with, whatever `kid` a token names. */
const jwks: JWTVerifyGetKey = (async () => keys.publicKey) as unknown as JWTVerifyGetKey;

const issuer: TundaIssuer = {
	tenantId: 'tnt_01K3ST0000E008000000000081',
	internalIssuer: ISSUER,
	issuer: ISSUER,
	clientId: CLIENT_ID,
	keyId: 'test-key',
	audience: 'https://observability.tunda.localhost',
	scopes: ['openid', 'profile'],
	redirectUri: 'http://localhost:8290/api/auth/callback',
	jwks
};

function accessTokenHash(token: string): string {
	const digested = createHash('sha256').update(token, 'ascii').digest();
	return digested.subarray(0, digested.length / 2).toString('base64url');
}

async function idToken(
	claims: Record<string, unknown> = {},
	overrides: { aud?: string; iss?: string } = {}
) {
	return new SignJWT({
		sid: SESSION_ID,
		nonce: NONCE,
		at_hash: accessTokenHash(ACCESS_TOKEN),
		...claims
	})
		.setProtectedHeader({ alg: 'ES256', kid: 'test-key' })
		.setIssuer(overrides.iss ?? ISSUER)
		.setAudience(overrides.aud ?? CLIENT_ID)
		.setSubject(SUBJECT)
		.setIssuedAt()
		.setExpirationTime('5m')
		.sign(keys.privateKey);
}

async function expectations(overrides: Partial<{ nonce: string | undefined }> = {}) {
	const nonce = 'nonce' in overrides ? overrides.nonce : NONCE;
	return {
		nonceHash: nonce === undefined ? undefined : await digest(nonce),
		accessToken: ACCESS_TOKEN,
		subject: SUBJECT,
		sessionId: SESSION_ID
	};
}

describe('the ID token verifier', () => {
	test('returns the name claim that the profile scope grants', async () => {
		const profile = await verifyIdToken(
			await idToken({ name: 'Tunda Platform Operator' }),
			issuer,
			await expectations()
		);

		expect(profile.name).toBe('Tunda Platform Operator');
	});

	test('returns an email only with its verification flag', async () => {
		const profile = await verifyIdToken(
			await idToken({ email: 'operator@example.test', email_verified: true }),
			issuer,
			await expectations()
		);

		expect(profile.email).toBe('operator@example.test');
		expect(profile.emailVerified).toBe(true);
	});

	test('treats a string "false" as no flag at all, never as a verified address', async () => {
		// OIDC Core §5.1 warns that some providers send the flag as a string. A
		// truthiness check on it would read "false" as verified, which is the exact
		// inversion that matters.
		const profile = await verifyIdToken(
			await idToken({ email: 'operator@example.test', email_verified: 'false' }),
			issuer,
			await expectations()
		);

		expect(profile.emailVerified).toBeUndefined();
	});

	test('yields no name when the account has none, rather than inventing one', async () => {
		const profile = await verifyIdToken(await idToken(), issuer, await expectations());

		expect(profile.name).toBeUndefined();
	});

	test('refuses a token whose nonce is not the one this console sent', async () => {
		// The replay this console stored a nonce hash to stop, and did not.
		await expect(
			verifyIdToken(
				await idToken({ nonce: 'a-nonce-from-another-sign-in' }),
				issuer,
				await expectations()
			)
		).rejects.toThrow(IdTokenRejected);
	});

	test('refuses a token carrying no nonce when one was sent', async () => {
		await expect(
			verifyIdToken(await idToken({ nonce: undefined }), issuer, await expectations())
		).rejects.toThrow(IdTokenRejected);
	});

	test('refuses a token whose at_hash does not bind the access token beside it', async () => {
		// An ID token from one authentication paired with an access token from
		// another. Every claim read out of it would describe the wrong person.
		await expect(
			verifyIdToken(
				await idToken({ at_hash: accessTokenHash('a.different.token') }),
				issuer,
				await expectations()
			)
		).rejects.toThrow(IdTokenRejected);
	});

	test('refuses a token with no at_hash, rather than checking it only when present', async () => {
		await expect(
			verifyIdToken(await idToken({ at_hash: undefined }), issuer, await expectations())
		).rejects.toThrow(IdTokenRejected);
	});

	test('refuses a token whose audience is the API rather than this client', async () => {
		await expect(
			verifyIdToken(await idToken({}, { aud: issuer.audience }), issuer, await expectations())
		).rejects.toThrow(IdTokenRejected);
	});

	test('refuses a token from an issuer this console does not trust', async () => {
		await expect(
			verifyIdToken(
				await idToken({}, { iss: 'https://id.evil.test/t/tnt_01K3ST0000E008000000000081' }),
				issuer,
				await expectations()
			)
		).rejects.toThrow(IdTokenRejected);
	});

	test('refuses a token describing a different session', async () => {
		await expect(
			verifyIdToken(
				await idToken({ sid: 'ses_01K3ST0000E008000000000099' }),
				issuer,
				await expectations()
			)
		).rejects.toThrow(IdTokenRejected);
	});

	test('skips the nonce on a refresh, which carries none, and still checks the rest', async () => {
		// OIDC Core §12.2: an ID token from a refresh carries the original nonce or
		// none, and there is no transaction row left to compare against either way.
		const profile = await verifyIdToken(
			await idToken({ nonce: undefined, name: 'Tunda Platform Operator' }),
			issuer,
			await expectations({ nonce: undefined })
		);

		expect(profile.name).toBe('Tunda Platform Operator');

		await expect(
			verifyIdToken(
				await idToken({ nonce: undefined, at_hash: accessTokenHash('a.different.token') }),
				issuer,
				await expectations({ nonce: undefined })
			)
		).rejects.toThrow(IdTokenRejected);
	});

	test('refuses an unsigned token, whatever its header claims', async () => {
		// `alg` is pinned in the verifier and never read from the token. A verifier
		// that trusts the header accepts `none`.
		const unsigned =
			Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url') +
			'.' +
			Buffer.from(
				JSON.stringify({ iss: ISSUER, aud: CLIENT_ID, sub: SUBJECT, sid: SESSION_ID, nonce: NONCE })
			).toString('base64url') +
			'.';

		await expect(verifyIdToken(unsigned, issuer, await expectations())).rejects.toThrow(
			IdTokenRejected
		);
	});

	test('the key it verifies against is a public key, not a shared secret', () => {
		// Guards the shape of the fixture rather than the code: a test that signed
		// and verified with one symmetric secret would pass while proving nothing
		// about a token Tunda actually issued.
		expect(publicJwk.kty).toBe('EC');
		expect(publicJwk.d).toBeUndefined();
	});
});
