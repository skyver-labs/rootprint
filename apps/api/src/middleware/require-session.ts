import type { MiddlewareHandler } from 'hono';

import type { AppEnv, AuthedEnv } from '../env.js';
import { logger } from '../lib/logger.js';
import { passesCsrfChecks } from '../tunda/csrf.js';
import { GrantRejected, refresh } from '../tunda/oidc.js';
import {
	awaitRefresh,
	claimRefresh,
	endSession,
	needsRefresh,
	refreshTokenOf,
	releaseRefreshClaim,
	resolveSession,
	SESSION_COOKIE,
	storeRotatedRefreshToken,
	storeRotatedTokens,
	type ConsoleSession
} from '../tunda/sessions.js';
import { forbidden, unauthorized } from '../utils/http-error.js';

/**
 * Turns the session cookie into a principal, refreshing Tunda's token when it is
 * close to expiring.
 *
 * ## The refresh is a security mechanism, not housekeeping
 *
 * This console does not call Tunda's introspection endpoint on the request path —
 * that would be a round trip per request, or a cache with a staleness window. So
 * a **failed refresh is the only signal it gets that a Tunda session ended.**
 *
 * The refresh interval is therefore the revocation window. Tunda issues
 * five-minute access tokens and this refreshes at one minute remaining, so an
 * operator suspended in Tunda loses this console within five minutes without any
 * event having to arrive.
 *
 * ## Refusal and unavailability are not the same thing
 *
 * `invalid_grant` is Tunda saying no — the family was revoked. The session ends.
 *
 * A timeout or a 5xx is Tunda having a bad moment, and must not end anything: a
 * five-minute blip would otherwise sign out every operator at once, which is an
 * outage caused by the mechanism meant to detect one. Requests continue on the
 * token already held until it expires.
 */
export const requireSession: MiddlewareHandler<AppEnv> = async (c, next) => {
	const handle = readSessionCookie(c.req.header('cookie'));
	if (handle === null) {
		throw unauthorized('Unauthorized');
	}

	let session = await resolveSession(handle);
	if (session === null) {
		throw unauthorized('Unauthorized');
	}

	if (!passesCsrfChecks(c)) {
		// Deliberately distinguished from "not signed in". The caller *is* signed in;
		// what failed is the proof that they meant to send this particular request.
		throw forbidden('Request origin is not permitted', 'CSRF_CHECK_FAILED');
	}

	if (needsRefresh(session)) {
		session = await refreshSession(session, handle);
		if (session === null) {
			throw unauthorized('Unauthorized');
		}
	}

	c.set('session', { user: { id: session.principalId } });
	c.set('tunda', session);
	await next();
};

/**
 * Exchanges the refresh token, or decides what its failure meant.
 *
 * ## Exactly one request per session refreshes
 *
 * Tunda rotates refresh tokens and revokes the whole family when a consumed one is
 * presented again — correctly, because it cannot tell the legitimate client from
 * the thief. So two concurrent refreshes of one session sign the user out.
 *
 * This was documented as a narrow window worth accepting. It is not narrow: the
 * access token lives five minutes, this fires at T−60s, and a browser loading a
 * page issues several requests at once. Every page load near the boundary was a
 * coin toss, and the losing side of it ended the session.
 *
 * So a request claims the refresh with one conditional `UPDATE` and only the
 * winner talks to Tunda. The losers wait for the row to change rather than for a
 * lock, which is why no database connection is held across an HTTP call.
 */
async function refreshSession(
	session: ConsoleSession,
	handle: string
): Promise<ConsoleSession | null> {
	if (!(await claimRefresh(session.id))) {
		return waitForRefresh(session, handle);
	}

	try {
		return await performRefresh(session);
	} finally {
		// Released whatever happened, including on an exception. A claim left behind
		// blocks this session's refreshes until it goes stale, and a session that
		// cannot refresh is a worse outcome than the reuse the claim prevents.
		await releaseRefreshClaim(session.id);
	}
}

/** The winner's path: it is the only request in this session talking to Tunda. */
async function performRefresh(session: ConsoleSession): Promise<ConsoleSession | null> {
	const refreshToken = await refreshTokenOf(session.id);
	if (refreshToken === null) {
		// No refresh token and an access token about to expire. Nothing can extend
		// this session, so it ends now rather than at the next request.
		await endSession(session.id, 'AUTHORITY_REJECTED');
		return null;
	}

	let result;
	try {
		result = await refresh(refreshToken);
	} catch (err) {
		if (err instanceof GrantRejected) {
			// Authoritative: the family is revoked or the token is spent. Nothing
			// this console does will make it work again.
			logger.info({ sessionId: session.id }, 'tunda refused the refresh; ending the session');
			await endSession(session.id, 'AUTHORITY_REJECTED');
			return null;
		}

		// Tunda is unreachable or erroring. Not a refusal, so the session survives on
		// the token it already holds — the alternative signs everybody out over a
		// blip, and the token is still valid for up to another minute.
		logger.warn({ sessionId: session.id, err }, 'could not reach tunda; keeping the session');
		return session;
	}

	if (result.status === 'unverifiable') {
		// Tunda answered and rotated the family; this console cannot use what came
		// back. The successor is recorded first and unconditionally, because the
		// token in the row is now spent: leaving it there means the next request
		// presents a consumed token, Tunda reads that as reuse, and revokes the
		// entire family. That is how one unusable response used to become a
		// security event.
		if (result.refreshToken !== undefined) {
			await storeRotatedRefreshToken(session.id, result.refreshToken);
		}

		logger.warn(
			{ sessionId: session.id, reason: result.reason },
			'tunda returned a token this console cannot verify; ending the session'
		);
		await endSession(session.id, 'AUTHORITY_REJECTED');
		return null;
	}

	const { tokens } = result;
	await storeRotatedTokens(session.id, tokens.verified, tokens);

	return {
		...session,
		accessToken: tokens.accessToken,
		accessExpiresAt: tokens.verified.expiresAt,
		acr: tokens.verified.acr,
		amr: tokens.verified.amr,
		authTime: tokens.verified.authTime
	};
}

/**
 * The losing path: somebody else is refreshing this session right now.
 *
 * Waits for the row to show a later access-token expiry, which is the only
 * observable difference between "still working" and "succeeded". Bounded and
 * short — waiting too long turns one slow refresh into a slow page.
 *
 * On timeout the session continues on the token it holds. That is safe by
 * construction rather than by luck: the refresh fires at T−60s, so a token that
 * triggered this still has up to a minute of life, and the next request will find
 * either a refreshed row or an unclaimed one.
 */
async function waitForRefresh(
	session: ConsoleSession,
	handle: string
): Promise<ConsoleSession | null> {
	const outcome = await awaitRefresh(session.id, session.accessExpiresAt);

	if (outcome === 'ended') {
		return null;
	}
	if (outcome === 'refreshed') {
		// Re-read rather than reconstruct: the winner wrote the whole row, including
		// an assurance this request never saw.
		return resolveSession(handle);
	}

	logger.debug(
		{ sessionId: session.id },
		'another request is refreshing this session; continuing on the current token'
	);
	return session;
}

/**
 * The session cookie, parsed without a library.
 *
 * Only this one name, and only an exact match — a prefix comparison would also
 * accept `__Host-rp_session_evil`, which a sibling application could set.
 */
export function readSessionCookie(header: string | undefined): string | null {
	if (header === undefined) {
		return null;
	}
	for (const part of header.split(';')) {
		const separator = part.indexOf('=');
		if (separator < 0) {
			continue;
		}
		if (part.slice(0, separator).trim() === SESSION_COOKIE) {
			return decodeURIComponent(part.slice(separator + 1).trim());
		}
	}
	return null;
}

/** The verified Tunda session behind this request, for a handler that needs the token. */
export function tundaSession(c: { get: (key: 'tunda') => ConsoleSession }): ConsoleSession {
	return c.get('tunda');
}

export type { AuthedEnv };
