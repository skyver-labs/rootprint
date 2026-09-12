import type { LayoutLoad } from './$types';
import { getSession } from '$lib/api/session';
import { DEP } from '$lib/api/deps';

export const ssr = false;
export const prerender = false;

/**
 * Who is signed in, asked once, for every page to read.
 *
 * ## This used to be the gate, and that is what made it loop
 *
 * It answered "no session" with a redirect to `/auth/sign-in`, and its list of
 * pages that render without a session did not contain `/auth/sign-in`. So the
 * redirect landed back here, which redirected again, ten times, until SvelteKit
 * refused with "Redirect loop" — four session probes, four 401s, and a blank
 * screen for somebody whose session had merely expired.
 *
 * The list was the bug, but a longer list is not the fix: it is a second
 * description of the route tree, kept by hand, and it will disagree again the
 * next time a page moves. The gate now lives on `(app)`, the group that actually
 * requires a session, so the sign-in page is not behind it — not because it is
 * listed as an exception, but because it is somewhere else.
 *
 * The bootstrap call this replaced asked whether a first administrator still
 * needed creating — a question that only exists when the console owns accounts.
 * It does not: an operator either exists in Tunda or is created there.
 */
export const load: LayoutLoad = async ({ depends }) => {
	depends(DEP.session);

	// No try/catch: `getSession` already distinguishes the two answers. A 401 is
	// `null`, which is an ordinary answer; a 5xx throws, and bubbling it to
	// `+error.svelte` is right. Signing somebody out because the probe blipped
	// would send them through an authentication they did not need.
	return { session: await getSession() };
};
