import { Hono } from 'hono';

import type { AppEnv } from '../env.js';
import { logger } from '../lib/logger.js';
import { publicAuthLimiter } from '../middleware/rate-limit.js';
import { readSessionCookie } from '../middleware/require-session.js';
import {
	completeFlow,
	FlowRejected,
	safeNextPath,
	startFlow,
	TRANSACTION_COOKIE
} from '../tunda/oidc.js';
import { theIssuer } from '../tunda/issuers.js';
import {
	createSession,
	endSession,
	idTokenOf,
	rememberPrincipal,
	resolveSession,
	SESSION_COOKIE
} from '../tunda/sessions.js';

/**
 * The whole of this console's authentication surface.
 *
 * Four routes, and none of them verifies a credential. There is no sign-in form,
 * no password endpoint, no invite redemption and no first-admin bootstrap —
 * upstream had all five and each was a way to obtain a session without Tunda.
 *
 * What remains is: start a flow, finish one, end one, and describe the current
 * one.
 */

/** `__Host-` requires Secure and Path=/, and forbids Domain. A sibling host cannot set it. */
const COOKIE_ATTRIBUTES = 'Path=/; HttpOnly; Secure; SameSite=Lax';

export const authRouter = new Hono<AppEnv>()
	/**
	 * Begins a sign-in.
	 *
	 * A `GET`, because it starts an authentication rather than changing anything —
	 * the session cookie is set on the callback, not here.
	 */
	.get('/login', publicAuthLimiter, async (c) => {
		const next = safeNextPath(c.req.query('next'));
		const flow = await startFlow(next);

		c.header(
			'set-cookie',
			`${TRANSACTION_COOKIE}=${flow.transactionHandle}; ${COOKIE_ATTRIBUTES}; Max-Age=600`,
			{ append: true }
		);
		return c.redirect(flow.authorizeUrl, 302);
	})

	/**
	 * Begins a step-up, in response to a `STEP_UP_REQUIRED` refusal.
	 *
	 * The requested assurance is carried to Tunda as `acr_values` with
	 * `prompt=login`, so it authenticates again rather than returning whatever the
	 * current device already satisfies. What comes back is verified against what was
	 * asked for: a relying party that requests AAL3 and proceeds on whatever arrives
	 * has requested nothing.
	 */
	.get('/step-up', publicAuthLimiter, async (c) => {
		const acr = c.req.query('acr');
		if (acr === undefined || acr === '') {
			return c.json({ error: { code: 'ACR_REQUIRED', message: 'acr is required' } }, 400);
		}

		const flow = await startFlow(safeNextPath(c.req.query('next')), acr);
		c.header(
			'set-cookie',
			`${TRANSACTION_COOKIE}=${flow.transactionHandle}; ${COOKIE_ATTRIBUTES}; Max-Age=600`,
			{ append: true }
		);
		return c.redirect(flow.authorizeUrl, 302);
	})

	/** Finishes a flow. */
	.get('/callback', publicAuthLimiter, async (c) => {
		const transactionHandle = readCookie(c.req.header('cookie'), TRANSACTION_COOKIE);

		try {
			const { tokens, nextPath } = await completeFlow(
				transactionHandle ?? undefined,
				c.req.query('state'),
				c.req.query('code')
			);

			// The display name comes from the verified ID token's `name` claim, which
			// is what `profile` grants. It was `null` here for as long as this route
			// has existed — partly because nobody had wired it, and partly because
			// Tunda did not emit the claim at all despite advertising the scope. Both
			// halves are now real, and an account with no display name still yields
			// `undefined`, which stores as null and renders as the subject id.
			const principalId = await rememberPrincipal(tokens.verified, tokens.profile.name ?? null);
			const handle = await createSession(principalId, tokens.verified, tokens);

			// The transaction cookie is cleared explicitly. Leaving it to expire would
			// leave a spent handle in the browser for ten minutes.
			c.header('set-cookie', `${TRANSACTION_COOKIE}=; ${COOKIE_ATTRIBUTES}; Max-Age=0`, {
				append: true
			});
			c.header('set-cookie', `${SESSION_COOKIE}=${handle}; ${COOKIE_ATTRIBUTES}`, {
				append: true
			});

			return c.redirect(nextPath, 302);
		} catch (err) {
			// One response for every failure. A replayed callback, a mismatched state
			// and an expired transaction are the same answer to whoever sent it; the
			// distinction is in the log.
			logger.warn(
				{ reason: err instanceof FlowRejected ? err.reason : 'unknown' },
				'authorization callback rejected'
			);
			c.header('set-cookie', `${TRANSACTION_COOKIE}=; ${COOKIE_ATTRIBUTES}; Max-Age=0`, {
				append: true
			});
			return c.json(
				{ error: { code: 'SIGN_IN_FAILED', message: 'Sign-in could not be completed.' } },
				400
			);
		}
	})

	/**
	 * Ends the session here, and at Tunda when it can.
	 *
	 * A `POST`: it changes state, so it carries the CSRF protections every other
	 * write does.
	 */
	.post('/logout', async (c) => {
		const handle = readSessionCookie(c.req.header('cookie'));
		let redirectTo: string | null = null;

		if (handle !== null) {
			const session = await resolveSession(handle);
			if (session !== null) {
				const idToken = await idTokenOf(session.id);
				await endSession(session.id, 'LOGOUT');

				// RP-initiated logout, so signing out here signs out of Tunda rather
				// than leaving a session that a fresh sign-in would silently resume.
				if (idToken !== null) {
					const issuer = theIssuer();
					const parameters = new URLSearchParams({
						id_token_hint: idToken,
						client_id: issuer.clientId,
						// `/auth/signed-out`, which is where the SPA actually serves the page.
						// Derived from the redirect URI rather than configured separately, so
						// the two cannot disagree — but the path has to be the real one, and
						// `/signed-out` merely fell through the catch-all to index.html and
						// then bounced the browser back into a sign-in.
						post_logout_redirect_uri: `${issuer.redirectUri.replace(/\/api\/auth\/callback$/, '')}/auth/signed-out`
					});
					redirectTo = `${issuer.issuer}/connect/logout?${parameters.toString()}`;
				}
			}
		}

		c.header('set-cookie', `${SESSION_COOKIE}=; ${COOKIE_ATTRIBUTES}; Max-Age=0`, {
			append: true
		});

		return c.json({ signedOut: true as const, redirectTo });
	})

	/**
	 * Who is signed in.
	 *
	 * Returns `401` with a `loginUrl` when nobody is. The browser navigates the
	 * top-level window there — never a fetch, an iframe or a popup, none of which
	 * can complete a flow that may need a WebAuthn ceremony.
	 */
	.get('/session', async (c) => {
		const handle = readSessionCookie(c.req.header('cookie'));
		const session = handle === null ? null : await resolveSession(handle);

		if (session === null) {
			return c.json(
				{
					error: {
						code: 'UNAUTHENTICATED',
						message: 'Sign in to continue.',
						loginUrl: '/api/auth/login'
					}
				},
				401
			);
		}

		return c.json({
			principalId: session.principalId,
			displayName: session.displayName,
			// The tenant, so the console can say whose plane this is. Rendering
			// only, like displayName: it grants nothing and is re-derived from a
			// verified token on every request.
			tenantId: session.tundaTenantId,
			// What Tunda proved, relayed unchanged. The browser renders from it and
			// decides nothing: every server call is authorized again.
			acr: session.acr,
			amr: session.amr,
			authenticatedAt: session.authTime.toISOString()
		});
	});

function readCookie(header: string | undefined, name: string): string | null {
	if (header === undefined) {
		return null;
	}
	for (const part of header.split(';')) {
		const separator = part.indexOf('=');
		if (separator >= 0 && part.slice(0, separator).trim() === name) {
			return decodeURIComponent(part.slice(separator + 1).trim());
		}
	}
	return null;
}
