import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';

/**
 * `/auth/*` is two pages: sign in, and the signed-out confirmation.
 *
 * Upstream had sign-in, first-admin setup and invite redemption under here, and
 * this layout decided which to show. Two of those are gone and the third collects
 * nothing — the sign-in page is a sentence and a link to Tunda's authorization
 * endpoint, with no field on it. The rule left is the one that always applied:
 * somebody with a live session has no business on either page.
 */
export const load: LayoutLoad = async ({ parent }) => {
	const { session } = await parent();

	if (session !== null) {
		redirect(303, '/');
	}

	return {};
};
