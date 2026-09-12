import { and, eq, isNull } from 'drizzle-orm';

import { db } from '../lib/db.js';
import { logger } from '../lib/logger.js';
import { clientAssertion } from './client-assertion.js';
import { constantTimeEquals, digest, open, randomToken, seal } from './crypto.js';
import { verifyIdToken, type SubjectProfile } from './id-token.js';
import { theIssuer, type TundaIssuer } from './issuers.js';
import { consoleAuthTransaction } from './schema.js';
import { verifyHumanToken, type VerifiedHumanToken } from './human-token.js';

/**
 * The authorization-code flow, from this console's side.
 *
 * ## The parts that are not optional
 *
 * **PKCE on every request.** Tunda requires it of confidential clients too, and is
 * right to: a client secret does nothing to protect a code intercepted before the
 * secret is ever used.
 *
 * **`state` compared in constant time, and spent before the exchange.** A replayed
 * callback finds no transaction. Spending it first rather than after means two
 * concurrent callbacks cannot both proceed.
 *
 * **`next` validated as a local path.** An unvalidated return path is an open
 * redirect on this console's own origin, reached immediately after a screen the
 * user trusted — which is precisely the credibility a phishing page is trying to
 * borrow.
 */

/** The cookie carrying the in-flight transaction. Same `__Host-` binding as the session. */
export const TRANSACTION_COOKIE = '__Host-rp_authtx';

/** A transaction is a screen somebody is looking at. One that outlives that is abandoned. */
const TRANSACTION_LIFETIME_MS = 10 * 60 * 1000;

export type StartedFlow = {
	readonly authorizeUrl: string;
	readonly transactionHandle: string;
};

export type TundaTokens = {
	readonly accessToken: string;
	readonly refreshToken?: string;
	readonly idToken?: string;
	readonly verified: VerifiedHumanToken;

	/**
	 * What the ID token said about the person, once it was verified.
	 *
	 * Empty when the grant carried no ID token — a refresh may or may not return
	 * one, and OIDC Core §12.2 leaves that to the server. Never partially trusted:
	 * either `verifyIdToken` passed every check and this is its result, or the
	 * whole exchange was refused.
	 */
	readonly profile: SubjectProfile;
};

export class FlowRejected extends Error {
	constructor(readonly reason: string) {
		super(`authorization flow rejected: ${reason}`);
		this.name = 'FlowRejected';
	}
}

/**
 * Begins a sign-in, or a step-up on one already established.
 *
 * @param requiredAcr when present, the assurance the PDP said was needed. Sent as
 *   `acr_values` with `prompt=login`, so Tunda authenticates again rather than
 *   returning whatever the existing device already satisfies.
 */
export async function startFlow(next: string, requiredAcr?: string): Promise<StartedFlow> {
	const issuer = theIssuer();

	const handle = randomToken();
	const state = randomToken();
	const nonce = randomToken();
	const verifier = randomToken();

	const challenge = Buffer.from(
		await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
	).toString('base64url');

	const now = new Date();
	await db.insert(consoleAuthTransaction).values({
		id: randomToken(),
		tokenHash: await digest(handle),
		tundaTenantId: issuer.tenantId,
		stateHash: await digest(state),
		nonceHash: await digest(nonce),
		pkceVerifierEnc: await seal(verifier),
		nextPath: safeNextPath(next),
		stepUp: requiredAcr !== undefined,
		createdAt: now,
		expiresAt: new Date(now.getTime() + TRANSACTION_LIFETIME_MS)
	});

	const parameters = new URLSearchParams({
		response_type: 'code',
		client_id: issuer.clientId,
		redirect_uri: issuer.redirectUri,
		scope: issuer.scopes.join(' '),
		state,
		nonce,
		code_challenge: challenge,
		code_challenge_method: 'S256'
	});

	if (requiredAcr !== undefined) {
		parameters.set('acr_values', requiredAcr);
		// `max_age=0` says the same thing as `prompt=login` and Tunda honours either.
		// Both are sent because a step-up that silently returned the existing
		// assurance would be a refusal the user can never clear.
		parameters.set('prompt', 'login');
		parameters.set('max_age', '0');
	}

	return {
		authorizeUrl: `${issuer.issuer}/oauth2/authorize?${parameters.toString()}`,
		transactionHandle: handle
	};
}

/**
 * Completes a callback: validates the transaction, exchanges the code, verifies
 * what came back.
 *
 * The transaction is consumed before the exchange. A code that fails to exchange
 * does not leave a reusable transaction behind.
 */
export async function completeFlow(
	transactionHandle: string | undefined,
	state: string | undefined,
	code: string | undefined
): Promise<{ tokens: TundaTokens; nextPath: string; stepUp: boolean }> {
	if (!transactionHandle || !state || !code) {
		throw new FlowRejected('incomplete callback');
	}

	const [transaction] = await db
		.select()
		.from(consoleAuthTransaction)
		.where(
			and(
				eq(consoleAuthTransaction.tokenHash, await digest(transactionHandle)),
				isNull(consoleAuthTransaction.usedAt)
			)
		)
		.limit(1);

	if (!transaction) {
		throw new FlowRejected('no such transaction');
	}
	if (transaction.expiresAt <= new Date()) {
		throw new FlowRejected('transaction expired');
	}
	if (!constantTimeEquals(transaction.stateHash, await digest(state))) {
		throw new FlowRejected('state mismatch');
	}

	// Spent before the exchange, and conditionally, so two concurrent callbacks
	// cannot both proceed on one transaction.
	const spent = await db
		.update(consoleAuthTransaction)
		.set({ usedAt: new Date() })
		.where(
			and(eq(consoleAuthTransaction.id, transaction.id), isNull(consoleAuthTransaction.usedAt))
		)
		.returning({ id: consoleAuthTransaction.id });

	if (spent.length === 0) {
		throw new FlowRejected('transaction already used');
	}

	const issuer = theIssuer();
	const verifier = await open(transaction.pkceVerifierEnc);

	const tokens = await verifyExchange(
		issuer,
		await post(issuer, {
			grant_type: 'authorization_code',
			code,
			code_verifier: verifier,
			redirect_uri: issuer.redirectUri
		}),
		// The reason the nonce was hashed and stored in the first place. Until this
		// argument existed the column was written on every sign-in and read by
		// nothing, which is the shape a replay defence takes when it is absent.
		transaction.nonceHash
	);

	return { tokens, nextPath: transaction.nextPath, stepUp: transaction.stepUp };
}

/**
 * What a refresh attempt produced.
 *
 * Three outcomes rather than a value and an exception, because the middle one has
 * no natural exception shape: Tunda answered, rotated the family, and returned
 * something this console cannot use. The rotation happened whether or not the
 * response verified, and the caller has to record it — a spent token left in the
 * row is presented again on the next request, and Tunda revokes the whole family
 * as reuse.
 */
export type RefreshResult =
	| { readonly status: 'rotated'; readonly tokens: TundaTokens }
	| {
			readonly status: 'unverifiable';
			/** The successor, if one came back. Must be stored even though the rest is unusable. */
			readonly refreshToken: string | undefined;
			readonly reason: string;
	  };

/**
 * Exchanges a refresh token for its successor.
 *
 * Tunda rotates refresh tokens and revokes the whole family on reuse, so the
 * caller must hold the session's refresh claim before calling this — two
 * concurrent presentations of one token is exactly the pattern that revokes it.
 * See `claimRefresh`.
 *
 * Throws {@link GrantRejected} when Tunda refused the grant, which is
 * authoritative: the family is revoked or the token is spent, and the session is
 * over. Throws {@link FlowRejected} when Tunda could not be reached, which is
 * not — the session survives on the token it already holds.
 */
export async function refresh(refreshToken: string): Promise<RefreshResult> {
	const issuer = theIssuer();
	const payload = await post(issuer, {
		grant_type: 'refresh_token',
		refresh_token: refreshToken
	});

	try {
		return { status: 'rotated', tokens: await verifyExchange(issuer, payload) };
	} catch (err) {
		// Deliberately not rethrown. The rotation already happened at Tunda, and the
		// caller's first job is to record the successor; deciding what an unusable
		// response means comes after that.
		return {
			status: 'unverifiable',
			refreshToken: payload.refresh_token,
			reason: err instanceof Error ? err.message : 'verification failed'
		};
	}
}

/** Whether a failure was Tunda refusing the grant, as opposed to being unreachable. */
export class GrantRejected extends Error {
	constructor() {
		super('the authorization server refused the grant');
		this.name = 'GrantRejected';
	}
}

/** The token endpoint's response, unverified. */
type TokenResponse = {
	access_token?: string;
	refresh_token?: string;
	id_token?: string;
};

/**
 * Posts to the token endpoint and returns what came back, verifying nothing.
 *
 * Split from the verification so a refresh can record the rotation that already
 * happened even when the response turns out to be unusable. Nothing downstream
 * may treat this as trusted: it is a parsed body, and every claim in it is
 * checked by `verifyExchange` before anything reads one.
 */
async function post(issuer: TundaIssuer, body: Record<string, string>): Promise<TokenResponse> {
	// The internal address, not the public issuer: this is a back-channel call.
	// `authorizeUrl` above deliberately uses the public one, because that is a URL
	// a person's browser has to resolve.
	// A freshly signed assertion per request, in the body — not a secret in a
	// Basic header. See `client-assertion.ts`: nothing reusable crosses the wire,
	// so capturing this exchange buys an attacker one expired, already-spent
	// credential.
	const response = await fetch(`${issuer.internalIssuer}/oauth2/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ ...body, ...(await clientAssertion(issuer)) }).toString()
	});

	if (!response.ok) {
		// `invalid_grant` is authoritative — the refresh family was revoked, or the
		// code is spent. Anything else is Tunda having a bad moment, and the caller
		// must not end a session over it.
		const text = await response.text();
		if (response.status === 400 && text.includes('invalid_grant')) {
			throw new GrantRejected();
		}
		logger.warn({ status: response.status }, 'tunda token endpoint did not return tokens');
		throw new FlowRejected(`token endpoint returned ${response.status}`);
	}

	return (await response.json()) as TokenResponse;
}

/**
 * Verifies a token response, or throws.
 *
 * Every check lives here so both grant types get the same ones. A sign-in that
 * cannot be verified must fail outright; a refresh that cannot be verified is
 * handled differently by its caller, but not by skipping anything.
 */
async function verifyExchange(
	issuer: TundaIssuer,
	payload: TokenResponse,
	nonceHash?: Buffer
): Promise<TundaTokens> {
	if (typeof payload.access_token !== 'string') {
		throw new FlowRejected('token response carried no access token');
	}

	const verified = await verifyHumanToken(payload.access_token);

	// Verified against the access token that arrived with it, not on its own. The
	// two are checked as a pair — `at_hash`, `sub` and `sid` — so an ID token
	// describing a different authentication cannot name the person this session is
	// about to be created for.
	//
	// A rejection fails the whole exchange rather than yielding a session without a
	// name. A check that is skipped when it fails is not a check.
	const profile =
		typeof payload.id_token === 'string'
			? await verifyIdToken(payload.id_token, issuer, {
					nonceHash,
					accessToken: payload.access_token,
					subject: verified.subject,
					sessionId: verified.sessionId
				})
			: {};

	return {
		accessToken: payload.access_token,
		refreshToken: payload.refresh_token,
		idToken: payload.id_token,
		verified,
		profile
	};
}

/**
 * A return path on this console's own origin, or `/`.
 *
 * Rejects a scheme, a protocol-relative `//host`, and the backslash form some
 * browsers normalise into one. Each of those is an absolute URL wearing the shape
 * of a path.
 *
 * And rejects `/auth/…`, which is not a security property but a correctness one:
 * those are the pages that exist for somebody with no session, and a completed
 * sign-in that returns to one has returned the user to being told to sign in. The
 * SPA collapses it too — this is the copy that holds when the parameter arrives
 * from somewhere the SPA did not write.
 */
export function safeNextPath(candidate: string | undefined): string {
	if (!candidate || !candidate.startsWith('/')) {
		return '/';
	}
	if (candidate.startsWith('//') || candidate.startsWith('/\\')) {
		return '/';
	}
	if (/^\/[a-z][a-z0-9+.-]*:/i.test(candidate)) {
		return '/';
	}
	if (candidate === '/auth' || candidate.startsWith('/auth/')) {
		return '/';
	}
	return candidate;
}
