import { and, eq, isNull, lt, or } from 'drizzle-orm';

import { db } from '../lib/db.js';
import { logger } from '../lib/logger.js';
import { constantTimeEquals, digest, open, randomToken, seal } from './crypto.js';
import { consolePrincipal, consoleSession } from './schema.js';
import type { VerifiedHumanToken } from './human-token.js';

/**
 * The browser session, and custody of Tunda's tokens.
 *
 * ## Why the browser holds nothing but an opaque handle
 *
 * This console renders log lines. Log lines are written by services, and services
 * log what their users send them — so the page displays attacker-influenced
 * content by definition, and a cross-site scripting flaw here is the expected
 * class of bug rather than a hypothetical one.
 *
 * Any design that puts a bearer token where JavaScript can read it puts Tunda
 * credentials one rendering defect away from exfiltration. So the tokens stay on
 * this side, encrypted, and the browser gets 256 bits of nothing.
 */

/**
 * `__Host-` binds the cookie to this exact origin with no `Domain`, and requires
 * `Secure` and `Path=/`. A sibling subdomain cannot set it.
 */
export const SESSION_COOKIE = '__Host-rp_session';

/** Ends a session that has been untouched this long. */
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;

/**
 * The longest a session here may live, whatever anybody does with it.
 *
 * Never extended: an idle timeout that can be refreshed forever is not a bound.
 *
 * Eight, not the twelve this said before. Twelve was never reachable — Tunda's own
 * session is capped at eight by `AuthenticationParameters` on the node, and this
 * console's session cannot outlive the grant it depends on. A refresh past that
 * point is refused and the family revoked, so a twelve-hour row described four
 * hours that could not happen.
 *
 * It is a maximum rather than a floor, and worth naming that way round: the
 * platform's number is the ceiling, and a tenant may lower it and never raise it.
 */
const ABSOLUTE_LIFETIME_MS = 8 * 60 * 60 * 1000;

/**
 * Refresh once the access token has less than this left.
 *
 * The refresh is not a convenience. With no introspection call on the request
 * path, a *failed refresh* is the only signal this console gets that a Tunda
 * session ended — so the refresh interval is the revocation window. Tunda issues
 * five-minute access tokens; refreshing at one minute remaining means a suspended
 * operator loses the console within five.
 */
const REFRESH_WHEN_REMAINING_MS = 60 * 1000;

export type ConsoleSession = {
	readonly id: string;
	readonly principalId: string;
	readonly tundaTenantId: string;
	readonly tundaSid: string;
	readonly subject: string;
	readonly displayName: string | null;
	readonly acr: string;
	readonly amr: readonly string[];
	readonly authTime: Date;
	readonly accessToken: string;
	readonly accessExpiresAt: Date;
};

export type EndedReason = 'LOGOUT' | 'IDLE' | 'ABSOLUTE' | 'AUTHORITY_REJECTED' | 'UNDECRYPTABLE';

/**
 * Records a Tunda subject, and returns the console's own id for it.
 *
 * Upsert on `(tenant, subject)`, never on email: an address is a routing detail
 * people change, and using it as the join key means somebody who changes theirs
 * becomes a different principal.
 */
export async function rememberPrincipal(
	token: VerifiedHumanToken,
	displayName: string | null
): Promise<string> {
	const now = new Date();

	const [existing] = await db
		.select({ id: consolePrincipal.id })
		.from(consolePrincipal)
		.where(
			and(
				eq(consolePrincipal.tundaTenantId, token.issuer.tenantId),
				eq(consolePrincipal.tundaUserId, token.subject)
			)
		)
		.limit(1);

	if (existing) {
		await db
			.update(consolePrincipal)
			.set({ lastSeenAt: now, displayName })
			.where(eq(consolePrincipal.id, existing.id));
		return existing.id;
	}

	// There is no invitation and no provisioning step. A person who can complete a
	// Tunda authorization-code flow against this console's client is a user of this
	// console; onboarding one is a Tunda operation and nothing here.
	const id = randomToken();
	await db.insert(consolePrincipal).values({
		id,
		tundaTenantId: token.issuer.tenantId,
		tundaUserId: token.subject,
		displayName,
		firstSeenAt: now,
		lastSeenAt: now
	});
	return id;
}

/** Creates a session and returns the cookie value, which is never stored. */
export async function createSession(
	principalId: string,
	token: VerifiedHumanToken,
	tokens: { accessToken: string; refreshToken?: string; idToken?: string }
): Promise<string> {
	const handle = randomToken();
	const now = new Date();

	await db.insert(consoleSession).values({
		id: randomToken(),
		tokenHash: await digest(handle),
		principalId,
		tundaTenantId: token.issuer.tenantId,
		tundaSid: token.sessionId,
		acr: token.acr,
		amr: [...token.amr],
		authTime: token.authTime,
		accessTokenEnc: await seal(tokens.accessToken),
		accessExpiresAt: token.expiresAt,
		refreshTokenEnc: tokens.refreshToken ? await seal(tokens.refreshToken) : null,
		idTokenEnc: tokens.idToken ? await seal(tokens.idToken) : null,
		createdAt: now,
		lastUsedAt: now,
		absoluteExpiresAt: new Date(now.getTime() + ABSOLUTE_LIFETIME_MS)
	});

	return handle;
}

/**
 * Resolves a cookie to a usable session, refreshing the access token if needed.
 *
 * `null` for anything that is not usable — unknown, ended, idle, past its
 * absolute deadline, or holding tokens that will not decrypt. The caller sees one
 * answer because there is one correct response to all of them.
 */
export async function resolveSession(handle: string): Promise<ConsoleSession | null> {
	const [row] = await db
		.select()
		.from(consoleSession)
		.innerJoin(consolePrincipal, eq(consoleSession.principalId, consolePrincipal.id))
		.where(and(eq(consoleSession.tokenHash, await digest(handle)), isNull(consoleSession.endedAt)))
		.limit(1);

	if (!row) {
		return null;
	}

	const session = row.console_session;
	const principal = row.console_principal;
	const now = new Date();

	// Compared in constant time even though the lookup was by hash. The hash makes a
	// timing side channel unlikely rather than impossible, and the comparison is
	// free.
	if (!constantTimeEquals(session.tokenHash, await digest(handle))) {
		return null;
	}

	if (session.absoluteExpiresAt <= now) {
		await endSession(session.id, 'ABSOLUTE');
		return null;
	}
	if (now.getTime() - session.lastUsedAt.getTime() > IDLE_TIMEOUT_MS) {
		await endSession(session.id, 'IDLE');
		return null;
	}

	let accessToken: string;
	try {
		accessToken = await open(session.accessTokenEnc);
	} catch {
		// A row whose tokens will not decrypt is a row nothing can be done with —
		// the envelope key changed, or the ciphertext was altered. Ended rather than
		// left to fail on every subsequent request.
		await endSession(session.id, 'UNDECRYPTABLE');
		return null;
	}

	await db.update(consoleSession).set({ lastUsedAt: now }).where(eq(consoleSession.id, session.id));

	return {
		id: session.id,
		principalId: session.principalId,
		tundaTenantId: session.tundaTenantId,
		tundaSid: session.tundaSid,
		subject: principal.tundaUserId,
		displayName: principal.displayName,
		acr: session.acr,
		amr: session.amr,
		authTime: session.authTime,
		accessToken,
		accessExpiresAt: session.accessExpiresAt
	};
}

/** Whether this session's access token is close enough to expiry to refresh. */
export function needsRefresh(session: ConsoleSession, now = new Date()): boolean {
	return session.accessExpiresAt.getTime() - now.getTime() < REFRESH_WHEN_REMAINING_MS;
}

/** The stored refresh token, if this session has one. */
export async function refreshTokenOf(sessionId: string): Promise<string | null> {
	const [row] = await db
		.select({ refreshTokenEnc: consoleSession.refreshTokenEnc })
		.from(consoleSession)
		.where(eq(consoleSession.id, sessionId))
		.limit(1);

	if (!row?.refreshTokenEnc) {
		return null;
	}
	try {
		return await open(row.refreshTokenEnc);
	} catch {
		return null;
	}
}

/** The stored ID token, for `id_token_hint` at logout. */
export async function idTokenOf(sessionId: string): Promise<string | null> {
	const [row] = await db
		.select({ idTokenEnc: consoleSession.idTokenEnc })
		.from(consoleSession)
		.where(eq(consoleSession.id, sessionId))
		.limit(1);

	if (!row?.idTokenEnc) {
		return null;
	}
	try {
		return await open(row.idTokenEnc);
	} catch {
		return null;
	}
}

/** Replaces the stored tokens after a successful refresh or step-up. */
export async function storeRotatedTokens(
	sessionId: string,
	token: VerifiedHumanToken,
	tokens: { accessToken: string; refreshToken?: string; idToken?: string }
): Promise<void> {
	await db
		.update(consoleSession)
		.set({
			accessTokenEnc: await seal(tokens.accessToken),
			accessExpiresAt: token.expiresAt,
			...(tokens.refreshToken ? { refreshTokenEnc: await seal(tokens.refreshToken) } : {}),
			...(tokens.idToken ? { idTokenEnc: await seal(tokens.idToken) } : {}),
			acr: token.acr,
			amr: [...token.amr],
			authTime: token.authTime,
			tundaSid: token.sessionId
		})
		.where(eq(consoleSession.id, sessionId));
}

/**
 * How long a refresh claim stays valid before another request may take it.
 *
 * Longer than a healthy refresh (one HTTP round trip to Tunda) and far shorter
 * than a session. A process that dies holding a claim blocks this session's
 * refreshes until this elapses, and a session that can never refresh again is a
 * worse failure than the one the claim prevents.
 */
const REFRESH_CLAIM_TTL_MS = 30 * 1000;

/** How long a request that lost the claim waits for the winner before giving up. */
const REFRESH_WAIT_MS = 2000;

/** How often it looks. */
const REFRESH_POLL_MS = 50;

/**
 * Claims the exclusive right to refresh this session, or reports that somebody else has it.
 *
 * One conditional `UPDATE`, so the check and the claim cannot be separated by
 * another request doing the same thing. The alternative — read, decide, write —
 * has a window between the read and the write in which two requests both decide
 * they may refresh, which is exactly the concurrency this exists to remove.
 */
export async function claimRefresh(sessionId: string, now = new Date()): Promise<boolean> {
	const stale = new Date(now.getTime() - REFRESH_CLAIM_TTL_MS);

	const claimed = await db
		.update(consoleSession)
		.set({ refreshingAt: now })
		.where(
			and(
				eq(consoleSession.id, sessionId),
				isNull(consoleSession.endedAt),
				or(isNull(consoleSession.refreshingAt), lt(consoleSession.refreshingAt, stale))
			)
		)
		.returning({ id: consoleSession.id });

	return claimed.length > 0;
}

/** Releases the claim, whatever the outcome. */
export async function releaseRefreshClaim(sessionId: string): Promise<void> {
	await db
		.update(consoleSession)
		.set({ refreshingAt: null })
		.where(eq(consoleSession.id, sessionId));
}

/**
 * Waits for whoever holds the claim to finish, and reports what they achieved.
 *
 * Returns the session once its access token has moved on — which is the only
 * observable difference between "the winner is still working" and "the winner
 * succeeded". Returns `null` if the session ended while waiting, which is what a
 * failed refresh looks like from here.
 *
 * Bounded, and the bound is short. A caller that waits too long turns one slow
 * refresh into a slow page; a caller that does not wait at all sends a request
 * onward with a token that may already have expired.
 */
export async function awaitRefresh(
	sessionId: string,
	previousExpiry: Date,
	deadlineMs = REFRESH_WAIT_MS
): Promise<'refreshed' | 'ended' | 'timeout'> {
	const until = Date.now() + deadlineMs;

	while (Date.now() < until) {
		await new Promise((resolve) => setTimeout(resolve, REFRESH_POLL_MS));

		const [row] = await db
			.select({
				endedAt: consoleSession.endedAt,
				accessExpiresAt: consoleSession.accessExpiresAt
			})
			.from(consoleSession)
			.where(eq(consoleSession.id, sessionId))
			.limit(1);

		if (!row || row.endedAt !== null) {
			return 'ended';
		}
		if (row.accessExpiresAt.getTime() > previousExpiry.getTime()) {
			return 'refreshed';
		}
	}

	return 'timeout';
}

/**
 * Stores a rotated refresh token on its own, without the rest of a successful refresh.
 *
 * ## Why this exists separately from `storeRotatedTokens`
 *
 * Because Tunda rotates the family the moment it answers, and it answers before
 * this console has verified anything. If verification then fails — a missing
 * claim, clock skew past the tolerance — the old code threw, stored nothing, and
 * left the spent token in the row. The next request presented that spent token,
 * Tunda saw a consumed token presented twice, and revoked the whole family as
 * reuse.
 *
 * So the rotation is recorded even when the response is unusable. Nothing about
 * the session is extended: the access token, its expiry and the assurance are all
 * left alone, because none of them was verified. This writes down one fact that
 * is true regardless — the token in the row is spent and this is its successor.
 */
export async function storeRotatedRefreshToken(
	sessionId: string,
	refreshToken: string
): Promise<void> {
	await db
		.update(consoleSession)
		.set({ refreshTokenEnc: await seal(refreshToken) })
		.where(eq(consoleSession.id, sessionId));
}

/** Ends a session, recording why. */
export async function endSession(sessionId: string, reason: EndedReason): Promise<void> {
	await db
		.update(consoleSession)
		.set({ endedAt: new Date(), endedReason: reason })
		.where(and(eq(consoleSession.id, sessionId), isNull(consoleSession.endedAt)));

	logger.info({ sessionId, reason }, 'console session ended');
}
