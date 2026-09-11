import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';
import { getSession, loginUrl } from '$lib/api/session';
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
		// A full navigation, not a SvelteKit redirect to an internal route: the flow
		// leaves this origin, and may need a WebAuthn ceremony that only a top-level
		// window can perform.
		redirect(303, loginUrl(url.pathname + url.search));
	}

	return { session };
};
