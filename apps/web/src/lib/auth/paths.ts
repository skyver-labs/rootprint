import { safeReturnTo } from '$lib/return-to';

/**
 * Where a signed-out person goes, and where a signed-in one comes back to.
 *
 * ## Why this is a module rather than two string literals
 *
 * Because there were two string literals, and they disagreed. The root layout
 * sent people to `/auth/sign-in?next=…`, the app group sent them to
 * `/auth/sign-in?returnTo=…`, and the sign-in page read only `next` — so half the
 * redirects into it silently lost the destination they were carrying.
 *
 * Worse, the root layout's list of pages that render without a session did not
 * include the sign-in page it was redirecting to. So an expired session produced:
 * probe, 401, redirect to sign-in; probe, 401, redirect to sign-in; ten times,
 * and then SvelteKit gave up with "Redirect loop". Four `GET /api/auth/session
 * 401` lines in the console and no page at all — at the exact moment somebody
 * needed to be told to sign in again.
 *
 * One definition of "public", one definition of the sign-in URL, and the gate
 * moved to the boundary of the group it guards (see `(app)/+layout.ts`), so the
 * loop is not fixed but unavailable: the redirect target is outside the gate.
 */

/**
 * The one route group that renders without a session.
 *
 * It is a prefix rather than a list of pages because the rule is about the group,
 * not its contents — a page added under `/auth` is public by being there, and
 * cannot be forgotten on a list somewhere else.
 */
const PUBLIC_PREFIX = '/auth/';

export const SIGN_IN = '/auth/sign-in';

/** Whether a path renders without a session. */
export function isPublicPath(pathname: string): boolean {
	return pathname === '/auth' || pathname.startsWith(PUBLIC_PREFIX);
}

/**
 * A destination worth carrying through a sign-in, or `null`.
 *
 * `null` for offsite (`safeReturnTo` folds those to `/`), for `/` itself — which
 * is where somebody lands anyway, so saying it adds nothing — and for anything
 * under `/auth`, which is the case that matters: a `next` pointing back at the
 * sign-in page is how a returning visitor gets sent to sign in again after having
 * just done so.
 */
export function returnable(raw: string | null | undefined): string | null {
	const path = safeReturnTo(raw ?? null);
	if (path === '/' || isPublicPath(path)) {
		return null;
	}
	return path;
}

/** The sign-in page, carrying where they were headed when there is somewhere to carry. */
export function signInPath(from: string | null | undefined): string {
	const next = returnable(from);
	return next === null ? SIGN_IN : `${SIGN_IN}?next=${encodeURIComponent(next)}`;
}

/** Where a signed-in visitor on an `/auth` page belongs. */
export function afterSignIn(raw: string | null | undefined): string {
	return returnable(raw) ?? '/';
}
