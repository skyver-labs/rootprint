import { and, eq, isNull } from 'drizzle-orm';

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

/** Never extended. An idle timeout that can be refreshed forever is not a bound. */
const ABSOLUTE_LIFETIME_MS = 12 * 60 * 60 * 1000;

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

/** Ends a session, recording why. */
export async function endSession(sessionId: string, reason: EndedReason): Promise<void> {
	await db
		.update(consoleSession)
		.set({ endedAt: new Date(), endedReason: reason })
		.where(and(eq(consoleSession.id, sessionId), isNull(consoleSession.endedAt)));

	logger.info({ sessionId, reason }, 'console session ended');
}
