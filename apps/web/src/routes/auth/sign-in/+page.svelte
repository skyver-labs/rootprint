<script lang="ts">
	import { page } from '$app/state';
	import { loginUrl } from '$lib/api/session';
	import { returnable } from '$lib/auth/paths';

	/**
	 * The only screen this console has for somebody who is not signed in.
	 *
	 * ## Why it exists when there is nothing to fill in
	 *
	 * Because the alternative was a redirect straight to `/api/auth/login` from the
	 * root layout's `load`. That is not a page, it is the start of an OAuth flow —
	 * so an expired session produced a blank screen, then a bounce through Tunda,
	 * and if anything went wrong in between, a layout that rendered with no session
	 * and threw. "Cannot read properties of null (reading 'session')" was that,
	 * every time.
	 *
	 * A page is also the honest thing to show. Being sent somewhere else without
	 * being told why is disorienting at the best of times, and this console's
	 * sessions are short by design — five minutes of access token, thirty of idle.
	 * People will see this screen often, and it should say what happened.
	 *
	 * ## It still collects nothing
	 *
	 * No form, no field, no credential. The button is a link to the authorization
	 * endpoint, and everything after it happens at Tunda. That is the property this
	 * whole fork exists to hold, and a sign-in page is exactly where somebody would
	 * eventually add a password box "just for the admin account" — so there is one
	 * anchor tag here and nothing else.
	 */

	/**
	 * Where they were headed, or `null`.
	 *
	 * Through `returnable`, so this page agrees with whatever sent somebody here:
	 * offsite is dropped, and so is a `next` pointing back into `/auth` — which is
	 * what a returning visitor would otherwise be handed, to be sent straight back
	 * to this page after signing in successfully.
	 */
	const next = $derived(returnable(page.url.searchParams.get('next')));

	/**
	 * Whether this is an interruption rather than an arrival.
	 *
	 * Somebody opening the console cold lands on `/`; somebody whose session ended
	 * mid-task was somewhere else. The distinction is worth drawing because the two
	 * want different sentences — one is "sign in", the other is "you were signed
	 * out, and here is your way back".
	 */
	const interrupted = $derived(next !== null);

	/**
	 * Whether a flow came back rejected.
	 *
	 * `/api/auth/callback` sends somebody here rather than answering a top-level
	 * navigation with a JSON error body, which is what it used to do: a browser
	 * showing `{"error":{"code":"SIGN_IN_FAILED"}}` as a page, with no way back.
	 * The commonest cause is the least alarming one — the ten-minute auth
	 * transaction expired while the Tunda tab sat open — and a retry fixes it.
	 *
	 * One reason code for every rejection, deliberately. The server draws no
	 * distinction between a replayed callback, a mismatched state and an expired
	 * transaction in what it tells the browser; that distinction is in its log.
	 */
	const failed = $derived(page.url.searchParams.get('error') !== null);

	const heading = $derived(
		failed ? 'Sign-in could not be completed' : interrupted ? 'Your session ended' : 'Sign in'
	);
</script>

<svelte:head><title>Sign in</title></svelte:head>

<div class="flex flex-col items-center gap-6 px-4 py-12 text-center">
	<div class="flex flex-col gap-2">
		<h1 class="text-h1">{heading}</h1>
		<p class="text-base-content/60 max-w-sm text-sm">
			{#if failed}
				The sign-in did not finish — most often because it was left open too long. Starting again
				usually works.
			{:else if interrupted}
				Sessions here are deliberately short. Signing in again takes you back to where you were.
			{:else}
				This console has no accounts of its own. Everyone signs in through Tunda.
			{/if}
		</p>
	</div>

	<!--
		A plain anchor, and a full navigation rather than a client-side one.

		The flow leaves this origin and may need a WebAuthn ceremony, which only a
		top-level window can perform — a fetch or an iframe gets as far as the
		security-key prompt and then fails in a way that reads like a broken key.
		`data-sveltekit-reload` is what stops the router from treating this as an
		internal link.
	-->
	<a class="btn btn-primary" href={loginUrl(next ?? '/')} data-sveltekit-reload>
		{failed ? 'Try again' : 'Sign in with Tunda'}
	</a>

	{#if interrupted}
		<p class="text-base-content/40 max-w-sm text-xs">
			You were on <span class="font-mono">{next}</span>
		</p>
	{/if}
</div>
