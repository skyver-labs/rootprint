import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';
import { signInPath } from '$lib/auth/paths';

/**
 * The gate, on the boundary of the group that needs one.
 *
 * ## Why here and not the root layout
 *
 * Because a gate in the root layout guards the sign-in page too, and a sign-in
 * page that redirects to itself is the redirect loop this console shipped. Every
 * route is either under `(app)` or under `/auth`; putting the check on `(app)`
 * means the page it redirects to is structurally outside the check rather than
 * exempted from it by a list somebody has to maintain.
 *
 * ## And why the redirect is to a page
 *
 * Not to `/api/auth/login`. That is not a page, it is the start of an OAuth flow —
 * so an expired session produced a blank screen, a bounce through Tunda, and,
 * when anything went wrong in between, a layout rendering with no session.
 * "Cannot read properties of null (reading 'session')" was that, every time.
 *
 * `/auth/sign-in` is an ordinary route this router can reach, so this is a
 * navigation rather than a full-page load into an endpoint answering with a 302.
 * The flow still leaves this origin — from a link on that page, in a top-level
 * window, which is what a WebAuthn ceremony needs.
 */
export const load: LayoutLoad = async ({ parent, url }) => {
	const { session } = await parent();

	if (session === null) {
		redirect(303, signInPath(url.pathname + url.search));
	}
};
