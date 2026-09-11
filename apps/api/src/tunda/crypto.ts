import { requireEnv } from '../utils/require-env.js';

/**
 * Hashing and envelope encryption for the two things this console holds on a
 * user's behalf: a session handle, and Tunda's own tokens.
 *
 * ## Why the session handle is hashed and the tokens are encrypted
 *
 * They need different properties. A session handle only ever has to be *compared*
 * — so it is stored hashed, and a database dump is not a set of live sessions.
 * Tunda's tokens have to be *presented back to Tunda*, so they have to be
 * recoverable, which means encryption and a key that lives somewhere other than
 * the database.
 */

/** AES-256-GCM. The nonce is prepended to the ciphertext. */
const ALGORITHM = 'AES-GCM';
const NONCE_BYTES = 12;

let cachedKey: CryptoKey | null = null;

/**
 * The envelope key, from the secret store.
 *
 * Read once and refused if absent. This console does not generate one: a
 * generated key would make every session on every other replica undecryptable,
 * and would silently rotate on each restart — which presents as "everybody is
 * randomly signed out" rather than as a missing secret.
 */
async function envelopeKey(): Promise<CryptoKey> {
	if (cachedKey !== null) {
		return cachedKey;
	}
	const raw = Uint8Array.from(Buffer.from(requireEnv('CONSOLE_SESSION_KEY'), 'base64'));
	if (raw.length !== 32) {
		throw new Error(
			`CONSOLE_SESSION_KEY must be 32 bytes of base64 for AES-256-GCM; got ${raw.length}`
		);
	}
	cachedKey = await crypto.subtle.importKey('raw', raw, ALGORITHM, false, ['encrypt', 'decrypt']);
	return cachedKey;
}

/**
 * Proves the key is present and usable, at boot.
 *
 * <p>Without this the key is read on the first {@link seal} — which is the first
 * sign-in. A deployment missing it therefore starts, reports healthy, serves the
 * login redirect, and fails at the callback with a stack trace, for every user.
 * That is a configuration error presenting as an outage an hour after the deploy
 * that caused it.
 *
 * Called before the database is touched, so a misconfigured console refuses to
 * start rather than migrating a schema it is not going to be able to use.
 */
export async function verifyEnvelopeKey(): Promise<void> {
	await envelopeKey();
}

/** Encrypts a token for storage. The nonce is fresh per call and never reused. */
export async function seal(plaintext: string): Promise<Buffer> {
	const key = await envelopeKey();
	const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
	const ciphertext = await crypto.subtle.encrypt(
		{ name: ALGORITHM, iv: nonce },
		key,
		new TextEncoder().encode(plaintext)
	);
	return Buffer.concat([Buffer.from(nonce), Buffer.from(ciphertext)]);
}

/**
 * Decrypts a stored token.
 *
 * Throws on a ciphertext that does not authenticate, which for GCM means it was
 * altered or encrypted under a different key. The caller treats that as a session
 * that cannot be used rather than as a recoverable error: a row whose tokens will
 * not decrypt is a row nothing can be done with.
 */
export async function open(sealed: Buffer): Promise<string> {
	const key = await envelopeKey();
	const nonce = Uint8Array.from(sealed.subarray(0, NONCE_BYTES));
	const ciphertext = Uint8Array.from(sealed.subarray(NONCE_BYTES));
	const plaintext = await crypto.subtle.decrypt({ name: ALGORITHM, iv: nonce }, key, ciphertext);
	return new TextDecoder().decode(plaintext);
}

/** SHA-256, for values that are only ever compared. */
export async function digest(value: string): Promise<Buffer> {
	const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
	return Buffer.from(hash);
}

/**
 * A fresh opaque value, 256 bits, base64url.
 *
 * Used for the session handle, the transaction handle, `state`, `nonce` and the
 * PKCE verifier. All five are values whose only property is being unguessable,
 * and one generator means none of them can be the one somebody made shorter.
 */
export function randomToken(): string {
	return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
}

/**
 * Constant-time comparison.
 *
 * For `state` and the CSRF token. A byte-by-byte comparison that returned early
 * leaks how much of the value matched, and a value is recoverable one character
 * at a time from that.
 */
export function constantTimeEquals(a: Buffer, b: Buffer): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let difference = 0;
	for (let i = 0; i < a.length; i++) {
		difference |= a[i]! ^ b[i]!;
	}
	return difference === 0;
}
