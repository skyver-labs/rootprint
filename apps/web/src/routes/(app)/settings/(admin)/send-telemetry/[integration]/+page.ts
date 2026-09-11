import { error } from '@sveltejs/kit';
import { ApiError } from '$lib/api/errors';
import { listIndexes } from '$lib/api/indexes';
import { integrationById } from '$lib/send-telemetry/integrations';
import { DEP } from '$lib/api/deps';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params, depends }) => {
	depends(DEP.indexes);

	if (!integrationById.has(params.integration)) {
		error(404, 'Unknown integration');
	}

	// Upstream also listed this console's ingest API keys here, so the wizard could
	// drop a real secret into the snippets. It mints none now: a producer's
	// credential is a Tunda client registration, and the console never sees it.
	try {
		const indexes = await listIndexes();
		const traceIndexId = indexes.find((i) => i.isTraceIndex)?.indexId ?? null;
		return {
			integrationId: params.integration,
			indexes: indexes.filter((i) => !i.isTraceIndex),
			traceIndexId
		};
	} catch (e) {
		if (e instanceof ApiError) error(e.status, e.message);
		throw e;
	}
};
