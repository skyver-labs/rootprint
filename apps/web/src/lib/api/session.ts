import { client } from './client';

/**
 * What the browser knows about who is signed in.
 *
 * ## It is for rendering, and for nothing else
 *
 * Every field here came from a token the server verified, and none of it is
 * re-usable as evidence: the browser cannot prove any of it, and the server does
 * not accept it if offered. `acr` decides whether to *offer* a step-up link, never
 * whether an action is permitted — that answer comes from the server on every
 * call, and a client that hid a button would still have to be refused when it
 * called anyway.
 *
 * This replaced `authClient.getSession()`. The shape is deliberately smaller than
 * Better Auth's: no `role`, no `email`, no `banned`. A role here would be a second
 * answer to a question Tunda already answers, and the first thing to go stale.
 */
export type Session = {
	principalId: string;
	displayName: string | null;
	/** The Tunda tenant this session belongs to. For saying whose plane you are looking at. */
	tenantId: string;
	/** The assurance Tunda proved, canonically `urn:tunda:aal:N`. For offering a step-up. */
	acr: string;
	/** How it was proven — `pwd`, `otp`, `hwk`. For telling somebody what they used. */
	amr: string[];
	authenticatedAt: string;
};

/**
 * The current session, or `null`.
 *
 * `null` is an ordinary answer, not an error: an anonymous visitor is expected,
 * and the layout turns it into a sign-in redirect rather than an error page.
 */
export async function getSession(): Promise<Session | null> {
	const res = await client.api.auth.session.$get();
	if (res.status === 401) {
		return null;
	}
	if (!res.ok) {
		// A 5xx is not "signed out". Treating it as such would sign people out on
		// every blip and send them through an authentication they did not need.
		throw new Error(`session lookup failed with ${res.status}`);
	}
	return (await res.json()) as Session;
}

/** Where to send the top-level window to sign in, returning to `next` afterwards. */
export function loginUrl(next: string): string {
	return `/api/auth/login?next=${encodeURIComponent(next)}`;
}

/**
 * Where to send the top-level window to prove more, in response to a
 * `STEP_UP_REQUIRED` refusal.
 */
export function stepUpUrl(acr: string, next: string): string {
	return `/api/auth/step-up?acr=${encodeURIComponent(acr)}&next=${encodeURIComponent(next)}`;
}

/**
 * Ends the session.
 *
 * A `POST`, and the navigation that follows is a top-level one: Tunda's
 * `end_session_endpoint` clears its own cookie, which a fetch cannot do.
 */
export async function signOut(): Promise<void> {
	const res = await client.api.auth.logout.$post();
	const body = res.ok ? await res.json() : null;
	const redirectTo = body && 'redirectTo' in body ? body.redirectTo : null;

	// Falls back to the local signed-out page. A failed RP-initiated logout must
	// still end the session here — it already has, server-side — rather than leave
	// somebody on a page that looks signed in.
	window.location.assign(redirectTo ?? '/auth/signed-out');
}
