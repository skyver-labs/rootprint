import type { MiddlewareHandler } from 'hono';

import type { AppEnv, AuthedEnv } from '../env.js';
import { logger } from '../lib/logger.js';
import { passesCsrfChecks } from '../tunda/csrf.js';
import { GrantRejected, refresh } from '../tunda/oidc.js';
import {
	endSession,
	needsRefresh,
	refreshTokenOf,
	resolveSession,
	SESSION_COOKIE,
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
		session = await refreshSession(session);
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
 * Not serialized across processes. Tunda revokes a refresh family on reuse, so two
 * concurrent refreshes of one session would sign the user out — the window is
 * narrow and the consequence is one re-authentication, which is the right trade
 * against a distributed lock on every request. A deployment that sees it happen
 * should take a row lock here.
 */
async function refreshSession(session: ConsoleSession): Promise<ConsoleSession | null> {
	const refreshToken = await refreshTokenOf(session.id);
	if (refreshToken === null) {
		// No refresh token and an access token about to expire. Nothing can extend
		// this session, so it ends now rather than at the next request.
		await endSession(session.id, 'AUTHORITY_REJECTED');
		return null;
	}

	try {
		const rotated = await refresh(refreshToken);
		await storeRotatedTokens(session.id, rotated.verified, rotated);

		return {
			...session,
			accessToken: rotated.accessToken,
			accessExpiresAt: rotated.verified.expiresAt,
			acr: rotated.verified.acr,
			amr: rotated.verified.amr,
			authTime: rotated.verified.authTime
		};
	} catch (err) {
		if (err instanceof GrantRejected) {
			logger.info({ sessionId: session.id }, 'tunda refused the refresh; ending the session');
			await endSession(session.id, 'AUTHORITY_REJECTED');
			return null;
		}

		// Tunda is unreachable or erroring. The session survives on the token it
		// already holds; see the note above.
		logger.warn({ sessionId: session.id, err }, 'could not refresh; keeping the session');
		return session;
	}
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
