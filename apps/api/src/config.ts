import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { config as loadEnv } from 'dotenv';

import { intEnv, optionalUrlEnv, requireEnv, requireUrlEnv } from './utils/require-env.js';

const repoRootEnv = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../.env');
loadEnv({ path: repoRootEnv });

export const config = {
	databaseUrl: requireEnv('DATABASE_URL'),
	origin: requireUrlEnv('ORIGIN'),
	quickwitUrl: requireUrlEnv('QUICKWIT_URL'),
	traceIndexId: process.env.TRACE_INDEX_ID || 'otel-traces-v0_9',

	// Which deployment this is, as it appears in a producer token's
	// `signal:environment:index` destinations. A token issued for `staging` resolves
	// no destination here when this says `production`, so the batch is refused.
	//
	// One of `production`, `staging`, `sandbox`. Tunda fixes that set in a database
	// check constraint, so anything else here can never match a real grant and would
	// refuse every batch — silently, from the producer's side. This started as
	// `development`, which is exactly that mistake.
	//
	// The default is `sandbox` rather than `production` because that is the
	// fail-closed direction: a production console that was never configured refuses
	// writes, instead of accepting a sandbox producer's batch into a production index.
	environment: process.env.TUNDA_ENVIRONMENT || 'sandbox',
	frontendUrl: optionalUrlEnv('FRONTEND_URL'),
	port: intEnv('PORT', 8282),
	trustedProxyHops: intEnv('TRUST_PROXY_HOPS', 0),
	rateLimitWindowMs: intEnv('RATE_LIMIT_WINDOW_MS', 60_000),
	publicAuthRateLimit: intEnv('PUBLIC_AUTH_RATE_LIMIT', 30),
	readRateLimit: intEnv('READ_RATE_LIMIT', 300),
	searchAuditRetentionDays: intEnv('SEARCH_AUDIT_RETENTION_DAYS', 30, { min: 30 })
};
