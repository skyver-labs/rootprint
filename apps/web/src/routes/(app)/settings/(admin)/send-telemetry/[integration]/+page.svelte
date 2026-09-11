<script lang="ts">
	import { untrack } from 'svelte';
	import { page } from '$app/state';
	import { DEFAULT_OTEL_LOGS_INDEX_ID } from '$lib/send-telemetry/constants';
	import { integrationById } from '$lib/send-telemetry/integrations';
	import { SIGNAL_TABS, signalFromUrl } from '$lib/send-telemetry/signal';
	import WizardHeader from '$lib/components/send-telemetry/WizardHeader.svelte';
	import WizardSteps from '$lib/components/send-telemetry/WizardSteps.svelte';
	import TabLinks from '$lib/components/send-telemetry/TabLinks.svelte';

	let { data } = $props();

	const integration = $derived(integrationById.get(data.integrationId)!);

	// A traces link can only be produced for an integration that has a traces block, so an
	// out-of-band ?signal=traces falls back to logs rather than erroring.
	const signal = $derived(integration.traces ? signalFromUrl(page.url) : 'logs');
	const setup = $derived(integration[signal] ?? integration.logs);

	const flavor = $derived.by(() => {
		const raw = page.url.searchParams.get('flavor');
		if (setup.flavors?.some((f) => f.id === raw)) return raw!;
		return setup.defaultFlavor;
	});

	let selectedIndexId = $state<string>(
		untrack(() => {
			const preferred = data.indexes.find((i) => i.indexId === DEFAULT_OTEL_LOGS_INDEX_ID);
			return preferred?.indexId ?? data.indexes[0]?.indexId ?? DEFAULT_OTEL_LOGS_INDEX_ID;
		})
	);

	// Always a placeholder. The wizard used to paste a freshly minted key straight
	// into these snippets; the credential is now a Tunda access token the producer
	// fetches for itself, and a console that could print one would be a console
	// that had a copy.
	const ctx = $derived({
		origin: page.url.origin,
		apiKey: '$TUNDA_ACCESS_TOKEN',
		hasRealApiKey: false,
		indexId: selectedIndexId,
		flavor
	});

	const steps = $derived(setup.buildSteps(ctx));
</script>

<div class="settings-page flex flex-col gap-2">
	<WizardHeader
		{integration}
		{signal}
		indexes={data.indexes}
		traceIndexId={data.traceIndexId}
		bind:selectedIndexId
	/>

	{#if integration.traces}
		<TabLinks items={SIGNAL_TABS} active={signal} param="signal" ariaLabel="Telemetry signal" />
	{/if}

	{#if setup.flavors && flavor}
		<TabLinks items={setup.flavors} active={flavor} param="flavor" ariaLabel="Integration flavor" />
	{/if}

	<WizardSteps {steps} />
</div>
