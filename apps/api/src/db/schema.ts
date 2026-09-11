import { sql } from 'drizzle-orm';
import {
	bigint,
	bigserial,
	boolean,
	check,
	index,
	integer,
	jsonb,
	pgTable,
	serial,
	text,
	timestamp,
	uniqueIndex
} from 'drizzle-orm/pg-core';

import type { DisplayMode, Filter, TimeRange } from '../types.js';

import { consolePrincipal } from '../tunda/schema.js';

/**
 * Ownership points at the console's principal record, not at a local user.
 *
 * `console_principal` is a cache of a Tunda subject and holds no authority — no
 * role, no status, no credential. What it gives these tables is a stable key for
 * "who saved this view", which survives a person changing their email address in
 * a way an address-keyed row would not.
 */
const owner = consolePrincipal;

// `invite_token` and `api_key` were here. Both were credentials this console
// minted: an invite redeemed into an account, and an `rpk_` ingest key stored in
// plaintext alongside the index it was allowed to write. Neither has a successor
// in this schema — a person is invited in Tunda, and a producer is a Tunda client
// registration whose token this console verifies and never stores.

/**
 * How an index is classified, which is the input every read decision turns on.
 *
 * Deliberately not defaulted. See `indexSettings.classification`.
 */
export type IndexClassification = 'NONE' | 'INTERNAL' | 'PII' | 'RESTRICTED';

/** Whose day it ruins. Separate from classification; see Tunda's policy schema. */
export type IndexEnvironment = 'production' | 'staging' | 'sandbox';

export const indexSettings = pgTable('index_settings', {
	indexId: text('index_id').primaryKey(),
	displayName: text('display_name'),
	levelField: text('level_field').notNull().default('severity_text'),
	messageField: text('message_field').notNull().default('body.message'),
	tracebackField: text('traceback_field'),
	contextFields: jsonb('context_fields').$type<string[] | null>(),
	traceIdField: text('trace_id_field').notNull().default('trace_id'),

	/**
	 * What is in this index: `NONE`, `INTERNAL`, `PII` or `RESTRICTED`.
	 *
	 * **Nullable on purpose, and with no default.** Tunda's policy schema marks
	 * `classification` required, and absence never satisfies a condition there —
	 * so an index nobody has classified matches no rule, and a rule that does not
	 * match grants nothing. An unclassified index is unreadable.
	 *
	 * A default would undo exactly that. `INTERNAL` would make a production
	 * payments index readable because somebody created it and moved on;
	 * `RESTRICTED` would look safe and would instead teach every operator that the
	 * first step with a new index is to lower its classification, which is the
	 * habit that makes the field meaningless. Null is the honest third answer:
	 * nobody has said, so nobody may read.
	 *
	 * Set through `PATCH /api/indexes/:indexId`, which is governed by
	 * `change_field_config` — AAL3 with a hardware key proven in the last five
	 * minutes. Classification is a compliance control and is gated like one.
	 */
	classification: text('classification').$type<IndexClassification>(),

	/**
	 * `production`, `staging` or `sandbox`. Required by the same schema and null
	 * for the same reason: an index whose environment nobody stated is one no rule
	 * can evaluate, which is a denial.
	 */
	environment: text('environment').$type<IndexEnvironment>(),

	/**
	 * Which service writes to it. Carried into the decision rather than read by
	 * any rule — it is the first thing an investigation asks.
	 */
	owningService: text('owning_service'),

	createdAt: timestamp('created_at').defaultNow().notNull(),
	updatedAt: timestamp('updated_at')
		.defaultNow()
		.notNull()
		.$onUpdate(() => new Date())
});

export const userPreference = pgTable(
	'user_preference',
	{
		id: serial('id').primaryKey(),
		userId: text('user_id')
			.notNull()
			.references(() => owner.id, { onDelete: 'cascade' }),
		indexId: text('index_id').notNull(),
		displayFields: jsonb('display_fields').$type<string[]>(),
		lineWrap: boolean('line_wrap').notNull().default(false),
		displayMode: text('display_mode').$type<DisplayMode>().notNull().default('table'),
		createdAt: timestamp('created_at').defaultNow().notNull(),
		updatedAt: timestamp('updated_at')
			.defaultNow()
			.notNull()
			.$onUpdate(() => new Date())
	},
	(table) => [
		uniqueIndex('user_preference_unique').on(table.userId, table.indexId),
		index('user_preference_index_id').on(table.indexId)
	]
);

export const view = pgTable(
	'view',
	{
		id: serial('id').primaryKey(),
		userId: text('user_id')
			.notNull()
			.references(() => owner.id, { onDelete: 'cascade' }),
		indexId: text('index_id').notNull(),
		name: text('name').notNull(),
		query: text('query').notNull().default(''),
		filters: jsonb('filters').$type<Filter[]>().notNull().default([]),
		sortDirection: text('sort_direction').$type<'asc' | 'desc'>().notNull().default('desc'),
		columns: jsonb('columns').$type<string[]>(),
		timeRange: jsonb('time_range').$type<TimeRange>(),
		createdAt: timestamp('created_at').defaultNow().notNull(),
		updatedAt: timestamp('updated_at')
			.defaultNow()
			.notNull()
			.$onUpdate(() => new Date())
	},
	(table) => [
		uniqueIndex('view_user_index_name_unique').on(table.userId, table.indexId, table.name),
		index('view_index_id').on(table.indexId)
	]
);

export const share = pgTable(
	'share',
	{
		id: serial('id').primaryKey(),
		code: text('code').notNull().unique(),
		userId: text('user_id')
			.notNull()
			.references(() => owner.id, { onDelete: 'cascade' }),
		indexId: text('index_id').notNull(),
		query: text('query').notNull().default(''),
		startTime: integer('start_time').notNull(),
		endTime: integer('end_time').notNull(),
		hit: jsonb('hit').$type<Record<string, unknown>>().notNull(),
		filters: jsonb('filters').$type<Filter[]>().notNull().default([]),
		createdAt: timestamp('created_at').defaultNow().notNull()
	},
	(table) => [index('share_index_id').on(table.indexId)]
);

export const appSettings = pgTable('app_settings', {
	key: text('key').primaryKey(),
	value: text('value').notNull(),
	updatedAt: timestamp('updated_at')
		.defaultNow()
		.notNull()
		.$onUpdate(() => new Date())
});

export const indexStatsSnapshot = pgTable(
	'index_stats_snapshot',
	{
		id: serial('id').primaryKey(),
		indexId: text('index_id').notNull(),
		capturedAt: timestamp('captured_at').notNull(),
		numDocs: bigint('num_docs', { mode: 'number' }).notNull(),
		sizeBytes: bigint('size_bytes', { mode: 'number' }).notNull(),
		uncompressedBytes: bigint('uncompressed_bytes', { mode: 'number' }).notNull(),
		numSplits: integer('num_splits').notNull(),
		minTimestamp: bigint('min_timestamp', { mode: 'number' }),
		maxTimestamp: bigint('max_timestamp', { mode: 'number' })
	},
	(table) => [index('index_stats_snapshot_index_captured').on(table.indexId, table.capturedAt)]
);

export const searchAudit = pgTable(
	'search_audit',
	{
		id: bigserial('id', { mode: 'number' }).primaryKey(),
		executedAt: timestamp('executed_at', { withTimezone: true }).defaultNow().notNull(),
		source: text('source').$type<'ui' | 'token'>().notNull(),
		userId: text('user_id'),
		apiKeyId: text('api_key_id'),
		indexId: text('index_id').notNull(),
		query: text('query').notNull().default(''),
		startTs: bigint('start_ts', { mode: 'number' }),
		endTs: bigint('end_ts', { mode: 'number' }),
		status: text('status').$type<'success' | 'error'>().notNull(),
		durationMs: integer('duration_ms').notNull(),
		numHits: bigint('num_hits', { mode: 'number' }),
		errorCode: text('error_code'),
		errorMessage: text('error_message')
	},
	(table) => [
		index('search_audit_executed_at').on(table.executedAt),
		index('search_audit_user_executed')
			.on(table.userId, table.executedAt)
			.where(sql`${table.userId} IS NOT NULL`),
		index('search_audit_api_key_executed')
			.on(table.apiKeyId, table.executedAt)
			.where(sql`${table.apiKeyId} IS NOT NULL`),
		index('search_audit_index_executed').on(table.indexId, table.executedAt),
		check(
			'search_audit_actor_check',
			sql`(${table.source} = 'ui'    AND ${table.userId} IS NOT NULL AND ${table.apiKeyId} IS NULL)
			 OR (${table.source} = 'token' AND ${table.apiKeyId} IS NOT NULL AND ${table.userId} IS NULL)`
		)
	]
);

export * from '../tunda/schema.js';
