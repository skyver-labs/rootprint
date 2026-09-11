<script lang="ts">
	import { page } from '$app/state';
	import { ExternalLink } from 'lucide-svelte';
	import Breadcrumb from '$lib/components/ui/Breadcrumb.svelte';
	import { resolveBreadcrumbs } from '$lib/settings-nav';
	import type { Integration, Signal } from '$lib/send-telemetry/types';
	import type { IndexSummary } from 'api/types';

	let {
		integration,
		signal,
		indexes,
		traceIndexId,
		selectedIndexId = $bindable<string>('')
	}: {
		integration: Integration;
		signal: Signal;
		indexes: IndexSummary[];
		/** Null when the span store does not exist in Quickwit. */
		traceIndexId: string | null;
		selectedIndexId?: string;
	} = $props();

	const segments = $derived([
		...resolveBreadcrumbs(page.route.id, page.params).slice(0, -1),
		{ label: integration.label }
	]);
</script>

<header class="flex flex-col gap-4">
	<Breadcrumb {segments} />
	<div class="flex items-center justify-between gap-4">
		<h1 class="text-h1">{integration.label}</h1>
		<a
			href={integration.docs}
			target="_blank"
			rel="noreferrer"
			class="link link-hover text-base-content/60 hover:text-base-content flex items-center gap-1.5 text-xs"
		>
			Documentation
			<ExternalLink class="h-3 w-3" />
		</a>
	</div>

	{#if signal === 'traces'}
		{#if traceIndexId}
			<p class="text-base-content/60 text-xs">
				Spans go to <span class="text-base-content font-mono">{traceIndexId}</span> — the span store,
				wherever the token's other destinations point.
			</p>
		{:else}
			<p class="text-warning-ink text-xs">
				No span store exists in Quickwit yet, so spans sent here have nowhere to land.
			</p>
		{/if}
	{:else}
		<label class="flex items-center gap-2 text-xs">
			<span class="text-base-content/60">Sending to</span>
			<select class="select select-sm w-64 font-mono" bind:value={selectedIndexId}>
				{#each indexes as index (index.indexId)}
					<option value={index.indexId}>{index.indexId}</option>
				{/each}
			</select>
		</label>
	{/if}

	<!--
		This is where a freshly minted ingest key used to sit, one click away. It is a
		note instead because the console no longer issues credentials: a producer
		authenticates to Tunda as a registered client, and the destinations it may
		write to are signed into the token it gets back. So there is nothing here to
		mint, nothing to copy, and nothing for this page to have a copy of.
	-->
	<aside class="border-line bg-base-200/40 rounded-box border p-3 text-xs">
		<p class="text-base-content">This console does not issue ingest credentials.</p>
		<p class="text-base-content/60 mt-1">
			Register the producer as a Tunda client with the
			<span class="font-mono">observability.{signal}.ingest</span> scope and the destinations it may
			write to. It exchanges its own credentials for an access token; the snippets below read that
			token from <span class="font-mono">$TUNDA_ACCESS_TOKEN</span>.
		</p>
	</aside>
</header>
