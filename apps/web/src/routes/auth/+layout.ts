import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';

/**
 * `/auth/*` is one page now: the signed-out confirmation.
 *
 * Upstream had sign-in, first-admin setup and invite redemption under here, and
 * this layout decided which to show. All three are gone — nothing in this console
 * collects a credential — so the only rule left is that somebody with a live
 * session has no business on the signed-out page.
 */
export const load: LayoutLoad = async ({ parent }) => {
	const { session } = await parent();

	if (session !== null) {
		redirect(303, '/');
	}

	return {};
};
