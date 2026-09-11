<script lang="ts">
	import AppSidebar from '$lib/components/shell/AppSidebar.svelte';

	let { data, children } = $props();

	const session = $derived(data.session!);
</script>

<div class="flex min-h-0 w-full flex-1">
	<AppSidebar user={session} />

	<div class="flex min-h-0 min-w-0 flex-1 flex-col">
		{@render children()}
	</div>
</div>
