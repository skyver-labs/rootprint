<script lang="ts">
	import { ChevronsUpDown, LogOut } from 'lucide-svelte';
	import { toast } from 'svelte-sonner';
	import { signOut as endSession, type Session } from '$lib/api/session';
	import { avatarColor, avatarInitials } from '$lib/utils/avatar';

	let { user, collapsed = false }: { user: Session; collapsed?: boolean } = $props();

	// The principal id, not an email. This console holds no address — it is Tunda's
	// attribute — so somebody whose last sign-in carried no display name is
	// identified here by the same id Tunda knows them by.
	const label = $derived(user.displayName ?? user.principalId);
	const initials = $derived(avatarInitials(user.displayName));
	const color = $derived(avatarColor(user.principalId));

	const dd = $props.id();

	let signingOut = $state(false);

	async function signOut() {
		signingOut = true;
		try {
			// Navigates away on success — to Tunda's end-session endpoint when there is
			// one — so there is no invalidate() to run afterwards.
			await endSession();
		} catch {
			toast.error('Failed to sign out');
			signingOut = false;
		}
	}
</script>

<button
	type="button"
	popovertarget={dd}
	style="anchor-name:--{dd}"
	aria-label="User menu"
	class="hover:bg-base-200/60 flex w-full items-center rounded transition-colors {collapsed
		? 'justify-center p-1'
		: 'gap-2.5 px-2 py-1.5'}"
>
	<span
		class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs text-white"
		style="background: {color}"
	>
		{initials}
	</span>
	{#if !collapsed}
		<span class="min-w-0 flex-1 text-left">
			<span class="block truncate text-sm">{label}</span>
			<span class="text-subtle block truncate text-xs">Signed in with Tunda</span>
		</span>
		<ChevronsUpDown class="text-base-content/40 h-3.5 w-3.5 shrink-0" />
	{/if}
</button>

<div
	popover
	id={dd}
	style="position-anchor:--{dd}"
	class="dropdown dropdown-right dropdown-end border-line rounded-box bg-base-100 ml-2 w-64 border p-0"
>
	<div class="border-line border-b px-4 py-3">
		<p class="text-sm">{label}</p>
		<p class="text-base-content/60 mt-0.5 font-mono text-xs">{user.acr}</p>
	</div>
	<div class="p-2">
		<button
			type="button"
			class="btn btn-ghost btn-sm w-full justify-start"
			onclick={signOut}
			disabled={signingOut}
		>
			<LogOut class="h-3.5 w-3.5 opacity-70" />
			{signingOut ? 'Signing out…' : 'Sign out'}
		</button>
	</div>
</div>
