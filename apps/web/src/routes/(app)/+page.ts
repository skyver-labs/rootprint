import type { PageLoad } from './$types';
import { getClusterDocumentStatus } from '$lib/api/admin';
import { listIndexes, toLogIndexOptions } from '$lib/api/indexes';
import { readString, writeString } from '$lib/utils/safe-storage';

const HAS_SEEN_DOCUMENTS_KEY = 'rootprint:has-seen-documents';

export const load = (async ({ parent }) => {
	const indexesPromise = listIndexes();
	void indexesPromise.catch(() => {});

	const { session } = await parent();
	const hasSeenDocuments = readString(HAS_SEEN_DOCUMENTS_KEY) === '1';
	// Was gated on `session.user.role === 'admin'`. There is no local role to read,
	// and this only decides whether to show a first-run hint — the call itself is
	// authorized server-side, and `.catch(() => null)` already handles a refusal.
	const documentStatusPromise =
		session !== null && !hasSeenDocuments
			? getClusterDocumentStatus().catch(() => null)
			: Promise.resolve(null);
	const [summaries, documentStatus] = await Promise.all([indexesPromise, documentStatusPromise]);
	if (documentStatus?.hasDocuments === true) writeString(HAS_SEEN_DOCUMENTS_KEY, '1');

	return {
		indexes: toLogIndexOptions(summaries),
		hasDocuments: hasSeenDocuments ? true : (documentStatus?.hasDocuments ?? null)
	};
}) satisfies PageLoad;
