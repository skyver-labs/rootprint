import { Hono } from 'hono';

import { exportsRouter } from './exports.js';
import { viewsRouter } from './views.js';

import { db } from '../lib/db.js';
import { quickwit } from '../lib/quickwit.js';
import { describe, validator } from '../lib/openapi/describe.js';
import type { AuthedEnv } from '../env.js';
import { authorize, authorizeEach } from '../middleware/authorize.js';
import { requireSession } from '../middleware/require-session.js';
import { rejectTraceIndex } from '../middleware/reject-trace-index.js';
import { readLimiter } from '../middleware/rate-limit.js';
import { withIndexConfig, withIndexMeta } from '../middleware/with-index.js';
import {
	createIndexSchema,
	FieldParams,
	FieldValuesBulkQuery,
	FieldValuesQuery,
	HistogramQuery,
	IndexFieldsQuery,
	PutPreferencesBody,
	saveIndexConfigSchema,
	SourceParams,
	StatsQuery,
	ToggleSourceBody,
	updateQuickwitConfigSchema
} from '../schemas/indexes.js';
import { createSourceSchema, updateSourceSchema } from '../schemas/sources.js';
import {
	FieldValuesBulkResponse,
	FieldValuesResponse,
	HistogramResponse,
	IndexDetailResponse,
	IndexFieldsResponse,
	IndexListResponse,
	IndexSourceSchema,
	IndexStatsResponse,
	IndexSummarySchema,
	IndexViewConfigResponse,
	LogSearchResponse,
	PreferencesResponse,
	SourceDetailSchema
} from '../schemas/responses/indexes.js';
import { SearchQuery } from '../schemas/search.js';
import {
	createIndex,
	deleteIndex,
	getIndexDetail,
	getIndexViewConfig,
	listIndexes,
	listIndexFields,
	saveIndexConfig,
	updateIndexConfig
} from '../services/index.service.js';
import {
	createSource,
	deleteSource,
	projectSource,
	resetSourceCheckpoint,
	setSourceEnabled,
	updateSource
} from '../services/index-source.service.js';
import { getStatsHistory } from '../services/index-stats.service.js';
import {
	fieldValues,
	fieldValuesBulk,
	histogramLogs,
	searchLogs
} from '../services/log.service.js';
import { getPreferences, putPreferences } from '../services/preference.service.js';
import { auditActor, withSearchAudit } from '../services/search-audit.service.js';
import { IndexIdParams } from '../utils/params.js';

export const indexesRouter = new Hono<AuthedEnv>()
	.get(
		'/',
		describe({
			tag: 'Index management',
			summary: 'List indexes',
			ok: IndexListResponse,
			security: [{ cookieAuth: [] }]
		}),
		requireSession,
		// No middleware guard, and that is a decision rather than an omission.
		//
		// "May this operator list indexes" is not one question. It is one per
		// index, because listing `payments-production` and listing the build logs
		// are different answers — and a single guard over the route would have to
		// pick one of them for everybody. The handler asks all of them in one
		// BatchCheck and returns what came back permitted.
		//
		// An index the operator may not list is absent rather than greyed out. A
		// picker entry that appears and then refuses on click is worse than one
		// that never appeared, and the name of an index is itself operational
		// information — which is why `list` is a separate action from `search`.
		async (c) => {
			const all = await listIndexes(db, quickwit);
			const permitted = new Set(
				await authorizeEach(
					c,
					'list',
					all.map((summary) => summary.indexId)
				)
			);
			return c.json(all.filter((summary) => permitted.has(summary.indexId)));
		}
	)
	.post(
		'/',
		describe({
			tag: 'Index management',
			summary: 'Create index',
			ok: IndexSummarySchema,
			okStatus: 201,
			errors: [400, 409]
		}),
		requireSession,
		// The validator runs BEFORE the authorization here, which is the reverse of
		// every other route in this file and is deliberate. `create` is the one
		// decision whose resource attributes come from the body — the index does
		// not exist yet — and policy must see the body the schema accepted rather
		// than whatever arrived. The caller is already authenticated by
		// `requireSession`, so what a malformed body leaks is a validation message
		// to somebody who has completed a Tunda sign-in.
		validator('json', createIndexSchema),
		authorize('create', { kind: 'observability_index', proposed: true }),
		async (c) => {
			const input = c.req.valid('json');
			const created = await createIndex(db, quickwit, input);
			return c.json(created, 201);
		}
	)
	.get(
		'/:indexId/fields',
		describe({
			tag: 'Index management',
			summary: 'List index fields',
			ok: IndexFieldsResponse,
			security: [{ cookieAuth: [] }]
		}),
		requireSession,
		authorize('view_fields', { kind: 'observability_index' }),
		rejectTraceIndex,
		withIndexMeta,
		validator('param', IndexIdParams),
		validator('query', IndexFieldsQuery),
		async (c) => {
			return c.json(await listIndexFields(c.get('indexMeta'), c.req.valid('query')));
		}
	)
	.get(
		'/:indexId/config',
		describe({
			tag: 'Index management',
			summary: 'Get index view config',
			ok: IndexViewConfigResponse,
			security: [{ cookieAuth: [] }]
		}),
		requireSession,
		authorize('search', { kind: 'observability_index' }),
		rejectTraceIndex,
		withIndexMeta,
		validator('param', IndexIdParams),
		async (c) => {
			const indexMeta = c.get('indexMeta');
			return c.json(getIndexViewConfig(indexMeta));
		}
	)
	.get(
		'/:indexId',
		describe({
			tag: 'Index management',
			summary: 'Get index detail',
			ok: IndexDetailResponse
		}),
		requireSession,
		authorize('list', { kind: 'observability_index' }),
		withIndexMeta,
		validator('param', IndexIdParams),
		async (c) => {
			return c.json(getIndexDetail(c.get('indexMeta')));
		}
	)
	.get(
		'/:indexId/stats',
		describe({
			tag: 'Index management',
			summary: 'Get index stats history',
			ok: IndexStatsResponse
		}),
		requireSession,
		authorize('list', { kind: 'observability_index' }),
		validator('param', IndexIdParams),
		validator('query', StatsQuery),
		async (c) => {
			const { indexId } = c.req.valid('param');
			const points = await getStatsHistory(db, indexId, c.req.valid('query'));
			return c.json({ indexId, points });
		}
	)
	.patch(
		'/:indexId',
		describe({
			tag: 'Index management',
			summary: 'Update index configuration',
			okStatus: 204,
			errors: [400]
		}),
		requireSession,
		authorize('change_field_config', { kind: 'observability_index' }),
		// The only mutation here that never touches Quickwit, so nothing else would 404 a bad index id.
		withIndexMeta,
		validator('param', IndexIdParams),
		validator('json', saveIndexConfigSchema),
		async (c) => {
			const { indexId } = c.req.valid('param');
			const body = c.req.valid('json');
			await saveIndexConfig(db, indexId, c.get('indexMeta').settings, body);
			return c.body(null, 204);
		}
	)
	.put(
		'/:indexId/quickwit-config',
		describe({
			tag: 'Index management',
			summary: 'Update Quickwit index configuration',
			okStatus: 204,
			errors: [400, 404, 409]
		}),
		requireSession,
		authorize('change_field_config', { kind: 'observability_index' }),
		withIndexMeta,
		validator('param', IndexIdParams),
		validator('json', updateQuickwitConfigSchema),
		async (c) => {
			const { indexId } = c.req.valid('param');
			const body = c.req.valid('json');
			await updateIndexConfig(quickwit, indexId, c.get('indexMeta').index.fields, body);
			return c.body(null, 204);
		}
	)
	.delete(
		'/:indexId',
		describe({
			tag: 'Index management',
			summary: 'Delete index',
			okStatus: 204,
			errors: [409]
		}),
		requireSession,
		authorize('delete', { kind: 'observability_index' }),
		validator('param', IndexIdParams),
		async (c) => {
			const { indexId } = c.req.valid('param');
			await deleteIndex(db, quickwit, indexId);
			return c.body(null, 204);
		}
	)
	.post(
		'/:indexId/sources',
		describe({
			tag: 'Index management',
			summary: 'Create index source',
			ok: IndexSourceSchema,
			okStatus: 201,
			errors: [400, 409]
		}),
		requireSession,
		authorize('change_field_config', { kind: 'observability_index' }),
		validator('param', IndexIdParams),
		validator('json', createSourceSchema),
		async (c) => {
			const { indexId } = c.req.valid('param');
			const input = c.req.valid('json');
			const created = await createSource(quickwit, indexId, input);
			return c.json(created, 201);
		}
	)
	.get(
		'/:indexId/sources/:sourceId',
		describe({
			tag: 'Index management',
			summary: 'Get index source',
			ok: SourceDetailSchema,
			errors: [404]
		}),
		requireSession,
		authorize('change_field_config', { kind: 'observability_index' }),
		withIndexMeta,
		validator('param', SourceParams),
		async (c) => {
			const { sourceId } = c.req.valid('param');
			return c.json(projectSource(c.get('indexMeta').index, sourceId));
		}
	)
	.put(
		'/:indexId/sources/:sourceId',
		describe({
			tag: 'Index management',
			summary: 'Update index source',
			ok: SourceDetailSchema,
			errors: [400, 404]
		}),
		requireSession,
		authorize('change_field_config', { kind: 'observability_index' }),
		validator('param', SourceParams),
		validator('json', updateSourceSchema),
		async (c) => {
			const { indexId, sourceId } = c.req.valid('param');
			const input = c.req.valid('json');
			const updated = await updateSource(quickwit, indexId, sourceId, input);
			return c.json(updated);
		}
	)
	.post(
		'/:indexId/sources/:sourceId/reset-checkpoint',
		describe({
			tag: 'Index management',
			summary: 'Reset source checkpoint',
			okStatus: 204,
			errors: [404]
		}),
		requireSession,
		authorize('change_field_config', { kind: 'observability_index' }),
		validator('param', SourceParams),
		async (c) => {
			const { indexId, sourceId } = c.req.valid('param');
			await resetSourceCheckpoint(quickwit, indexId, sourceId);
			return c.body(null, 204);
		}
	)
	.patch(
		'/:indexId/sources/:sourceId',
		describe({
			tag: 'Index management',
			summary: 'Toggle source enabled state',
			okStatus: 204,
			errors: [409]
		}),
		requireSession,
		authorize('change_field_config', { kind: 'observability_index' }),
		validator('param', SourceParams),
		validator('json', ToggleSourceBody),
		async (c) => {
			const { indexId, sourceId } = c.req.valid('param');
			const { enabled } = c.req.valid('json');
			await setSourceEnabled(quickwit, indexId, sourceId, enabled);
			return c.body(null, 204);
		}
	)
	.delete(
		'/:indexId/sources/:sourceId',
		describe({
			tag: 'Index management',
			summary: 'Delete index source',
			okStatus: 204,
			errors: [409]
		}),
		requireSession,
		authorize('change_field_config', { kind: 'observability_index' }),
		validator('param', SourceParams),
		async (c) => {
			const { indexId, sourceId } = c.req.valid('param');
			await deleteSource(quickwit, indexId, sourceId);
			return c.body(null, 204);
		}
	)
	.get(
		'/:indexId/logs',
		describe({
			tag: 'Log explorer',
			summary: 'Search logs',
			ok: LogSearchResponse,
			security: [{ cookieAuth: [] }],
			errors: [429]
		}),
		requireSession,
		authorize('search', { kind: 'observability_index' }),
		readLimiter,
		withIndexConfig,
		validator('query', SearchQuery),
		async (c) => {
			const q = c.req.valid('query');
			const indexConfig = c.get('indexConfig');
			const result = await withSearchAudit(
				db,
				auditActor(c.get('session').user.id),
				indexConfig.indexId,
				{ query: q.q ?? '', startTs: q.startTs, endTs: q.endTs },
				() => searchLogs(quickwit, indexConfig, q),
				(response) => response.numHits
			);
			return c.json(result);
		}
	)
	.get(
		'/:indexId/logs/histogram',
		describe({
			tag: 'Log explorer',
			summary: 'Get log histogram',
			ok: HistogramResponse,
			security: [{ cookieAuth: [] }],
			errors: [429]
		}),
		requireSession,
		authorize('search', { kind: 'observability_index' }),
		readLimiter,
		withIndexConfig,
		validator('query', HistogramQuery),
		async (c) => {
			const { q, startTs, endTs, interval } = c.req.valid('query');
			return c.json(
				await histogramLogs(quickwit, c.get('indexConfig'), { query: q, startTs, endTs, interval })
			);
		}
	)
	.get(
		'/:indexId/fields/values',
		describe({
			tag: 'Log explorer',
			summary: 'Get bulk field values',
			ok: FieldValuesBulkResponse,
			security: [{ cookieAuth: [] }],
			errors: [429]
		}),
		requireSession,
		authorize('search', { kind: 'observability_index' }),
		readLimiter,
		withIndexConfig,
		validator('query', FieldValuesBulkQuery),
		async (c) => {
			const { fields, q, filters, startTs, endTs, limit } = c.req.valid('query');
			return c.json(
				await fieldValuesBulk(quickwit, c.get('indexConfig'), {
					fields,
					query: q,
					filters,
					startTs,
					endTs,
					limit
				})
			);
		}
	)
	.get(
		'/:indexId/fields/:field/values',
		describe({
			tag: 'Log explorer',
			summary: 'Get field values',
			ok: FieldValuesResponse,
			security: [{ cookieAuth: [] }],
			errors: [429]
		}),
		requireSession,
		authorize('search', { kind: 'observability_index' }),
		readLimiter,
		withIndexConfig,
		validator('param', FieldParams),
		validator('query', FieldValuesQuery),
		async (c) => {
			const { field } = c.req.valid('param');
			const { q, startTs, endTs, limit } = c.req.valid('query');
			return c.json(
				await fieldValues(quickwit, c.get('indexConfig'), field, {
					query: q,
					startTs,
					endTs,
					limit
				})
			);
		}
	)
	.get(
		'/:indexId/preferences',
		describe({
			tag: 'Index management',
			summary: 'Get index preferences',
			ok: PreferencesResponse
		}),
		requireSession,
		withIndexMeta,
		validator('param', IndexIdParams),
		async (c) => {
			const { indexId } = c.req.valid('param');
			const session = c.get('session');
			return c.json(await getPreferences(db, session.user.id, indexId));
		}
	)
	.put(
		'/:indexId/preferences',
		describe({
			tag: 'Index management',
			summary: 'Save index preferences',
			ok: PreferencesResponse
		}),
		requireSession,
		withIndexMeta,
		validator('param', IndexIdParams),
		validator('json', PutPreferencesBody),
		async (c) => {
			const { indexId } = c.req.valid('param');
			const body = c.req.valid('json');
			const session = c.get('session');
			return c.json(await putPreferences(db, session.user.id, indexId, body));
		}
	)
	.route('/:indexId/logs/export', exportsRouter)
	.route('/:indexId/views', viewsRouter);
