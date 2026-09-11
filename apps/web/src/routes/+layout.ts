import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';
import { getSession } from '$lib/api/session';
import { DEP } from '$lib/api/deps';

export const ssr = false;
export const prerender = false;

/** Pages that render without a session: the only ones an anonymous visitor may see. */
const PUBLIC_PATHS = ['/auth/signed-out', '/share/'];

export const load: LayoutLoad = async ({ url, depends }) => {
	depends(DEP.session);

	const session = await getSession();

	// The bootstrap call this replaced asked whether a first administrator still
	// needed creating — a question that only exists when the console owns accounts.
	// It does not, so there is nothing to bootstrap: an operator either exists in
	// Tunda or is created there.
	if (session === null && !PUBLIC_PATHS.some((prefix) => url.pathname.startsWith(prefix))) {
		// To a page, not to `/api/auth/login`.
		//
		// Redirecting straight at the authorization endpoint sent somebody whose
		// session had just expired into an OAuth flow with no explanation — a blank
		// screen, a bounce through Tunda, and, when anything went wrong in between,
		// a layout rendering with no session. "Cannot read properties of null
		// (reading 'session')" was that, every time.
		//
		// `/auth/sign-in` is an ordinary route this router can reach, so the
		// navigation is a navigation rather than a full-page load into an endpoint
		// that answers with a 302. The flow still leaves this origin — from a link
		// on that page, in a top-level window, which is what a WebAuthn ceremony
		// needs.
		redirect(303, `/auth/sign-in?next=${encodeURIComponent(url.pathname + url.search)}`);
	}

	return { session };
};
