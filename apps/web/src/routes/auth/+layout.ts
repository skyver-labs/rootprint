import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';
import { afterSignIn } from '$lib/auth/paths';

/**
 * `/auth/*` is two pages: sign in, and the signed-out confirmation.
 *
 * Upstream had sign-in, first-admin setup and invite redemption under here, and
 * this layout decided which to show. Two of those are gone and the third collects
 * nothing — the sign-in page is a sentence and a link to Tunda's authorization
 * endpoint, with no field on it. The rule left is the one that always applied:
 * somebody with a live session has no business on either page.
 *
 * Where they go is their `next` rather than always `/`, which matters on the one
 * path that reaches here with a live session: a browser that still had the
 * sign-in page open when the flow completed in another tab. `afterSignIn`
 * collapses an `/auth` destination to `/`, so this cannot bounce back into here.
 */
export const load: LayoutLoad = async ({ parent, url }) => {
	const { session } = await parent();

	if (session !== null) {
		redirect(303, afterSignIn(url.searchParams.get('next')));
	}

	return {};
};
