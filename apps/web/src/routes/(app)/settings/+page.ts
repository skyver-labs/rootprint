import { redirect } from '@sveltejs/kit';
import type { PageLoad } from './$types';

/**
 * Settings has one landing page now.
 *
 * Upstream branched here on `session.user.role`, sending an administrator to the
 * overview and everybody else to their profile. The profile page was account
 * management — password, personal API keys — and is gone with the rest of the
 * local identity; the role it branched on is gone too.
 */
export const load: PageLoad = async () => {
	redirect(307, '/settings/overview');
};
