import { and, eq, isNull } from 'drizzle-orm';

import { db } from '../lib/db.js';
import { logger } from '../lib/logger.js';
import { constantTimeEquals, digest, open, randomToken, seal } from './crypto.js';
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

	const tokens = await exchange(issuer, {
		grant_type: 'authorization_code',
		code,
		code_verifier: verifier,
		redirect_uri: issuer.redirectUri
	});

	return { tokens, nextPath: transaction.nextPath, stepUp: transaction.stepUp };
}

/**
 * Exchanges a refresh token for its successor.
 *
 * Tunda rotates refresh tokens and revokes the whole family on reuse, so the
 * caller must serialize refreshes per session — two concurrent presentations of
 * one token is exactly the pattern that revokes it.
 */
export async function refresh(refreshToken: string): Promise<TundaTokens> {
	const issuer = theIssuer();
	return exchange(issuer, { grant_type: 'refresh_token', refresh_token: refreshToken });
}

/** Whether a failure was Tunda refusing the grant, as opposed to being unreachable. */
export class GrantRejected extends Error {
	constructor() {
		super('the authorization server refused the grant');
		this.name = 'GrantRejected';
	}
}

async function exchange(issuer: TundaIssuer, body: Record<string, string>): Promise<TundaTokens> {
	const response = await fetch(`${issuer.issuer}/oauth2/token`, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
			// RFC 6749 §2.3.1 requires both halves form-urlencoded before base64.
			authorization: `Basic ${Buffer.from(
				`${encodeURIComponent(issuer.clientId)}:${encodeURIComponent(issuer.clientSecret)}`
			).toString('base64')}`
		},
		body: new URLSearchParams(body).toString()
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

	const payload = (await response.json()) as {
		access_token?: string;
		refresh_token?: string;
		id_token?: string;
	};

	if (typeof payload.access_token !== 'string') {
		throw new FlowRejected('token response carried no access token');
	}

	return {
		accessToken: payload.access_token,
		refreshToken: payload.refresh_token,
		idToken: payload.id_token,
		verified: await verifyHumanToken(payload.access_token)
	};
}

/**
 * A return path on this console's own origin, or `/`.
 *
 * Rejects a scheme, a protocol-relative `//host`, and the backslash form some
 * browsers normalise into one. Each of those is an absolute URL wearing the shape
 * of a path.
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
	return candidate;
}
