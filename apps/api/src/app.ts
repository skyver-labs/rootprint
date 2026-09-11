import { Hono, type Context } from 'hono';
import type { Schema } from 'hono/types';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { ApplyGlobalResponse } from 'hono/client';
import { cors } from 'hono/cors';
import { compress } from 'hono/compress';
import { serveStatic } from 'hono/bun';
import { HTTPException } from 'hono/http-exception';
import { requestId as requestIdMiddleware } from 'hono/request-id';
import { secureHeaders } from 'hono/secure-headers';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { QuickwitError } from 'quickwit-js';

import { config } from './config.js';
import type { AppEnv, AuthedEnv } from './env.js';
import { connectDb, db, runMigrations } from './lib/db.js';
import { logger } from './lib/logger.js';
import { probeQuickwit, quickwit } from './lib/quickwit.js';
import { isApiPath, requestLogging } from './middleware/request-logging.js';
import { requireSession } from './middleware/require-session.js';
import { adminActivityRouter } from './routes/admin/activity.js';
import { clusterRouter } from './routes/admin/cluster.js';
import { metricsRouter } from './routes/admin/metrics.js';
import { authRouter } from './routes/auth.js';
import { healthRouter } from './routes/health.js';
import { indexesRouter } from './routes/indexes.js';
import { ndjsonRouter } from './routes/ingest/ndjson.js';
import { otlpRouter } from './routes/ingest/otlp.js';
import { sharesRouter } from './routes/shares.js';
import { monitoringRouter } from './routes/monitoring.js';
import { tracesRouter } from './routes/traces.js';
import type { ApiErrorBody } from './types.js';
import { HttpError } from './utils/http-error.js';
import { quickwitErrorToHttp } from './utils/quickwit-error.js';
import { Code, otlpError, otlpErrorFromHttpError } from './utils/otlp-response.js';
import { verifySigningKey } from './tunda/client-assertion.js';
import { verifyEnvelopeKey } from './tunda/crypto.js';
import { initIssuers } from './tunda/issuers.js';
import { startStatsCollector } from './services/index-stats.service.js';
import { buildSpec } from './lib/openapi/spec.js';

// Resolves to apps/web/build from both src/app.ts (dev) and dist/app.js (prod): both are two segments deep in apps/api.
const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../web/build');

function withAuth<E extends AuthedEnv, S extends Schema>(router: Hono<E, S, ''>) {
	return new Hono<AppEnv>().use('*', requireSession).route('/', router);
}

function errorJson(c: Context, body: ApiErrorBody['error'], status: ContentfulStatusCode) {
	return c.json({ error: body }, status);
}

export const app = new Hono<AppEnv>();

app.use('*', requestIdMiddleware());
app.use('*', secureHeaders({ strictTransportSecurity: false }));
app.use('*', requestLogging);
app.use('*', compress());
const allowedOrigins = new Set([
	config.origin,
	...(config.frontendUrl ? [config.frontendUrl] : [])
]);
app.use(
	'*',
	cors({
		origin: (origin) => (allowedOrigins.has(origin) ? origin : null),
		credentials: true
	})
);

app.onError((rawErr, c) => {
	const requestId = c.get('requestId');
	let err: Error = rawErr;
	if (rawErr instanceof QuickwitError) {
		err = quickwitErrorToHttp(rawErr);
	} else if (rawErr instanceof HTTPException) {
		const message = rawErr.message || 'Request failed';
		err =
			rawErr.status === 400
				? new HttpError(400, 'INVALID_JSON', message)
				: new HttpError(rawErr.status, 'HTTP_ERROR', message);
	}

	const logMeta =
		err instanceof HttpError
			? { requestId, path: c.req.path, statusCode: err.statusCode, code: err.code, err }
			: {
					requestId,
					path: c.req.path,
					name: err.name,
					code: String((err as { code?: unknown }).code),
					err
				};

	if (c.req.path.startsWith('/v1/')) {
		if (err instanceof HttpError) {
			logger[err.retryAfter == null && err.statusCode >= 500 ? 'error' : 'warn'](
				logMeta,
				'request failed'
			);
			return otlpErrorFromHttpError(err);
		}
		logger.error(logMeta, 'request failed');
		return otlpError(503, Code.UNAVAILABLE, 'Upstream unavailable', 5);
	}

	if (err instanceof HttpError) {
		const isServerError = err.statusCode >= 500;
		// retryAfter marks a client-safe transient error: keep its message, warn-log, advertise Retry-After. Genuine faults stay masked + error-logged.
		const isTransient = err.retryAfter != null;
		if (isTransient) {
			logger.warn(logMeta, 'request failed');
			c.header('Retry-After', String(err.retryAfter));
		} else if (isServerError) {
			logger.error(logMeta, 'request failed');
		}
		const maskMessage = isServerError && !isTransient;
		return errorJson(
			c,
			{
				code: err.code,
				message: maskMessage ? 'Internal server error' : err.message,
				statusCode: err.statusCode,
				requestId,
				...(!maskMessage && err.details ? { details: err.details } : {})
			},
			err.statusCode as ContentfulStatusCode
		);
	}

	logger.error(logMeta, 'request failed');
	return errorJson(
		c,
		{ code: 'INTERNAL', message: 'Internal server error', statusCode: 500, requestId },
		500
	);
});

app.notFound((c) => {
	if (c.req.path.startsWith('/v1/')) {
		return otlpError(404, Code.NOT_FOUND, 'Route not found');
	}
	return errorJson(
		c,
		{
			code: 'ROUTE_NOT_FOUND',
			message: 'Route not found',
			statusCode: 404,
			requestId: c.get('requestId')
		},
		404
	);
});

export const routes = app
	.route('/api/health', healthRouter)
	.route('/api/auth', authRouter)
	.route('/api/indexes', indexesRouter)
	.route('/api/traces', tracesRouter)
	.route('/api/monitoring', monitoringRouter)
	.route('/api/admin/metrics', withAuth(metricsRouter))
	.route('/api/admin/cluster', withAuth(clusterRouter))
	.route('/api/admin/activity', withAuth(adminActivityRouter))
	// /api/users, /api/service-accounts, /api/api-keys and /api/settings are gone
	// rather than moved. The first three administered an identity this console
	// owned; the fourth configured Google and GitHub sign-in. People and machine
	// credentials are administered in Tunda, and a console screen that edited them
	// would be editing a copy.
	.route('/api/shares', withAuth(sharesRouter))
	.route('/api/ingest', ndjsonRouter)
	.route('/v1', otlpRouter);

let openAPISpec: ReturnType<typeof buildSpec> | undefined;
app.get('/api/openapi.json', async (c) => {
	openAPISpec ??= buildSpec(app);
	return c.json(await openAPISpec);
});

// SPA static-file serving. Mounted AFTER `routes`, so an API path reaching here matched no route:
// send it to app.notFound()'s JSON 404 contract instead of the SPA handlers below.
app.use('*', async (c, next) => (isApiPath(c.req.path) ? c.notFound() : next()));

app.use('*', async (c, next) => {
	await next();
	if (c.req.path.startsWith('/_app/immutable/')) {
		c.header('Cache-Control', 'public, max-age=31536000, immutable');
	} else if (/\.(?:woff2?|png|ico|svg|webp)$/.test(c.req.path)) {
		c.header('Cache-Control', 'public, max-age=604800');
	} else {
		c.header('Cache-Control', 'no-cache');
	}
});

app.use('*', serveStatic({ root: webRoot }));

// SPA fallback: anything still unmatched gets index.html.
app.get('*', serveStatic({ path: 'index.html', root: webRoot }));

async function main(): Promise<void> {
	logger.info('booting api');

	// Configuration first, before the database and before the listener.
	//
	// Both of these throw on a missing or malformed value, and both are fatal.
	// A console without a configured Tunda issuer has no authentication authority
	// at all; one without a session key cannot read back a session it wrote. The
	// only safe thing either can do with a request is refuse it, so it does not
	// boot.
	//
	// Ordered before `connectDb()` deliberately. These checks cost nothing and
	// cannot fail transiently, so running them first means a misconfigured
	// deployment names the missing variable instead of migrating a database it
	// will not be able to serve — and instead of coming up healthy and failing at
	// the first callback, which is what a lazily-read key produces.
	initIssuers();
	await verifyEnvelopeKey();
	// The client signing key too. Without this the first failure is a sign-in that
	// gets all the way to the token exchange and dies there — after the person has
	// already authenticated with Tunda, which is the worst moment to discover a
	// configuration error.
	await verifySigningKey();

	await connectDb();
	await runMigrations();
	await probeQuickwit();

	const statsCollector = startStatsCollector(db, quickwit);

	const server = Bun.serve({
		fetch: app.fetch,
		hostname: '0.0.0.0',
		port: config.port,
		idleTimeout: 255
	});
	logger.info({ port: config.port }, 'api listening');

	const shutdown = () => {
		logger.info('shutting down api');
		statsCollector.stop();
		server.stop(true);
		process.exit(0);
	};
	process.on('SIGTERM', shutdown);
	process.on('SIGINT', shutdown);
}

if (import.meta.main) {
	main().catch((err) => {
		logger.error({ err }, 'boot failed');
		process.exit(1);
	});
}

export type RoutesWithErrors = ApplyGlobalResponse<
	typeof routes,
	{
		400: { json: ApiErrorBody };
		401: { json: ApiErrorBody };
		403: { json: ApiErrorBody };
		404: { json: ApiErrorBody };
		409: { json: ApiErrorBody };
		413: { json: ApiErrorBody };
		415: { json: ApiErrorBody };
		422: { json: ApiErrorBody };
		429: { json: ApiErrorBody };
		500: { json: ApiErrorBody };
		503: { json: ApiErrorBody };
	}
>;
