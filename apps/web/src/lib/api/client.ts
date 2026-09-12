import { hc } from 'hono/client';
import type { AppType } from 'api';

import { isPublicPath, signInPath } from '$lib/auth/paths';

/**
 * The API client, and the one thing it does beyond calling fetch.
 *
 * ## A 401 in the middle of a page used to do nothing at all
 *
 * The root layout checks for a session when a route loads, and that was the only
 * place anything noticed. A session that expired while somebody was reading a page
 * — which happens often here, because the access token lives five minutes and the
 * idle timeout is thirty — produced a 401 on the next request and nothing else.
 * The explorer's fetch rejected, the spinner kept spinning, and the page looked
 * like it was loading slowly rather than like it was signed out.
 *
 * Every symptom of that reads as a performance problem. It is not: every endpoint
 * this console calls answers in well under a tenth of a second.
 *
 * So a 401 navigates to the sign-in page, carrying where they were so they come
 * back to it. That is the same answer the layout gives on a cold load, given at
 * the other moment it can happen.
 */

/** Where the session probe lives. The one endpoint whose 401 is an answer, not a failure. */
const SESSION_PROBE = '/api/auth/session';

/**
 * Guards against a page-load's worth of requests each starting a navigation.
 *
 * The explorer issues config, fields, histogram and logs together. If the session
 * has gone, all four come back 401 at once, and four navigations to the same place
 * is a visible flicker and a mangled history stack.
 */
let redirecting = false;

async function fetchWithSessionHandling(
	input: RequestInfo | URL,
	init?: RequestInit
): Promise<Response> {
	const response = await fetch(input, init);

	if (response.status !== 401) {
		return response;
	}

	const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

	// `getSession` asks precisely so that it can be told "nobody". Answering that
	// with a navigation would make the sign-in page redirect to itself.
	if (url.includes(SESSION_PROBE)) {
		return response;
	}

	// No window during a server-side render or a test, and already where a
	// signed-out person belongs, or already on the way.
	//
	// `isPublicPath` rather than a second `startsWith('/auth/')`: the page this is
	// about to navigate to is under `/auth`, so the check that stops it navigating
	// away from there has to be the same check, not a copy of it that can drift.
	if (typeof window === 'undefined' || redirecting || isPublicPath(window.location.pathname)) {
		return response;
	}

	redirecting = true;

	// `location.assign`, not the client router. The session is gone, so every
	// route's load would fail on its way through; a full load starts from a clean
	// state with no stale data behind it.
	window.location.assign(signInPath(window.location.pathname + window.location.search));

	return response;
}

export const client = hc<AppType>('', { fetch: fetchWithSessionHandling });
