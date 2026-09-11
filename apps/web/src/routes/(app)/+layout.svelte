<script lang="ts">
	import AppSidebar from '$lib/components/shell/AppSidebar.svelte';

	let { data, children } = $props();

	/**
	 * No `!`.
	 *
	 * The root layout redirects when there is no session, so by the time this
	 * renders there is one — except during the moment the redirect is being
	 * performed, when Svelte flushes effects against data that is on its way out.
	 * The non-null assertion silenced the type error and left the runtime one: the
	 * sidebar read `user.displayName` off nothing and threw, which surfaced as an
	 * unhandled rejection with no obvious connection to an expired session.
	 *
	 * Rendering nothing for one frame is the correct behaviour anyway. There is no
	 * shell to draw for somebody who is leaving.
	 */
	const session = $derived(data.session);
</script>

{#if session}
	<div class="flex min-h-0 w-full flex-1">
		<AppSidebar user={session} />

		<div class="flex min-h-0 min-w-0 flex-1 flex-col">
			{@render children()}
		</div>
	</div>
{/if}
