import { eq } from 'drizzle-orm';

import { db } from '../lib/db.js';
import { indexSettings } from '../db/schema.js';
import type { PdpResource } from './pdp.js';

/**
 * What this console tells the PDP about an index.
 *
 * ## Why the attributes come from here and never from the request
 *
 * Because they decide the answer. `classification` is what separates "search the
 * build logs" from "search the payments index", and a caller who could set it
 * would set `NONE` and read everything. The spec states this as a MUST and it is
 * the single most load-bearing line in the console's half of authorization.
 *
 * So the only input is the index id — which is a *lookup key* into this console's
 * own metadata, exactly as a tenant id in a URL is a lookup key into a placement.
 * Naming an index does not describe it.
 *
 * ## Why a missing row yields an incomplete descriptor rather than a default
 *
 * An index nobody has classified has no classification, and the PDP's schema
 * marks that attribute required. Absence never satisfies a condition, so every
 * rule naming a classification fails to match and the decision is
 * `REQUIRED_ATTRIBUTE_MISSING` — a denial, produced by the policy engine rather
 * than by a guess made here.
 *
 * That is the behaviour to want. The alternative is this function inventing a
 * value, and there is no value it could invent that is right: a permissive one
 * makes an unclassified production index readable, and a restrictive one is a
 * decision the policy engine should have made and a lie about what the console
 * knows.
 */
export async function indexResource(indexId: string): Promise<PdpResource> {
	const [settings] = await db
		.select({
			classification: indexSettings.classification,
			environment: indexSettings.environment,
			owningService: indexSettings.owningService
		})
		.from(indexSettings)
		.where(eq(indexSettings.indexId, indexId))
		.limit(1);

	const attributes: Record<string, string> = { index_id: indexId };

	// Each written only when it has a value. An empty string is not an absent
	// attribute to a policy engine — `classification == ""` is a comparison that
	// evaluates, and it would evaluate false against every rule while looking, in
	// a decision record, exactly like a classification somebody chose.
	if (settings?.classification) {
		attributes['classification'] = settings.classification;
	}
	if (settings?.environment) {
		attributes['environment'] = settings.environment;
	}
	if (settings?.owningService) {
		attributes['owning_service'] = settings.owningService;
	}

	return { type: 'observability_index', id: indexId, attributes };
}

/**
 * An index that does not exist yet.
 *
 * The only descriptor built from a request body, and the exception is narrow:
 * `create` is the one action whose resource has no stored metadata, because the
 * point of the request is to bring it into existence. It is gated on
 * `platform_observability_admin` — AAL3, hardware key, five minutes — and the
 * holder of that role can set the classification a moment later through
 * `change_field_config` anyway, so nothing is granted by letting them state it
 * now rather than then.
 *
 * What it buys is that no index can be created unclassified. The policy schema
 * requires `classification` and `environment`, so an attempt without them is a
 * denial from the engine rather than a validation message from here — and the
 * index is classified from its first row rather than whenever somebody notices
 * that nobody can search it.
 */
export function proposedIndexResource(body: {
	indexId?: unknown;
	classification?: unknown;
	environment?: unknown;
	owningService?: unknown;
}): PdpResource {
	const attributes: Record<string, string> = {};

	if (typeof body.indexId === 'string' && body.indexId !== '') {
		attributes['index_id'] = body.indexId;
	}
	if (typeof body.classification === 'string' && body.classification !== '') {
		attributes['classification'] = body.classification;
	}
	if (typeof body.environment === 'string' && body.environment !== '') {
		attributes['environment'] = body.environment;
	}
	if (typeof body.owningService === 'string' && body.owningService !== '') {
		attributes['owning_service'] = body.owningService;
	}

	return {
		type: 'observability_index',
		id: typeof body.indexId === 'string' ? body.indexId : undefined,
		attributes
	};
}

/**
 * The console itself: its activity log, its metrics, its cluster.
 *
 * No attributes beyond the tenant, which the PDP supplies from the placement it
 * resolved rather than from anything sent here. There is one console per plane,
 * so an identifier for it would be a constant in every decision record.
 */
export function consoleResource(): PdpResource {
	return { type: 'observability_console', attributes: {} };
}
