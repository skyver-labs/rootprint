import { Hono } from 'hono';

import { config } from '../../config.js';
import { CONTENT_TYPE_JSON } from '../../constants.js';
import type { MachineEnv } from '../../env.js';
import { describe } from '../../lib/openapi/describe.js';
import { quickwitUrl } from '../../lib/quickwit.js';
import { proxyToQuickwit } from '../../lib/quickwit-proxy.js';
import { requireMachine } from '../../middleware/require-machine.js';
import { permitsSignal, resolveDestination } from '../../tunda/machine-token.js';
import { badRequest, forbidden } from '../../utils/http-error.js';
import { INDEX_HEADER } from './destination.js';

export const ndjsonRouter = new Hono<MachineEnv>().post(
	'/ndjson',
	describe({
		tag: 'Log ingest',
		summary: 'Ingest NDJSON log documents',
		description:
			'Proxies an NDJSON (or JSON array) log payload to Quickwit. The destination index is one the ' +
			`producer's Tunda token names; when the token permits several, pick one with the \`${INDEX_HEADER}\` header. ` +
			'Accepts application/x-ndjson or application/json content-type. ' +
			'Success and 4xx responses are passed through from Quickwit (400 bodies carry per-document parse errors); ' +
			'upstream 5xx responses are mapped to the standard 503 error contract.',
		security: [{ ingestBearer: [] }],
		errors: [413, 429],
		rawResponses: {
			'200': {
				description: 'Documents accepted for processing',
				content: {
					'application/json': {
						schema: {
							type: 'object',
							description: 'Quickwit ingest acknowledgement',
							properties: {
								num_docs_for_processing: { type: 'integer' }
							}
						}
					}
				}
			}
		}
	}),
	requireMachine,
	async (c) => {
		const token = c.get('machine');
		if (!permitsSignal(token, 'logs')) {
			throw forbidden('This token may not write logs', 'INGEST_SIGNAL_NOT_PERMITTED');
		}

		const indexId = resolveDestination(
			token,
			'logs',
			config.environment,
			c.req.header(INDEX_HEADER)
		);
		if (indexId === null) {
			// Covers both "not permitted" and "permitted several, named none". Told apart
			// in neither the status nor the message: the difference would let a producer
			// enumerate which indexes exist by watching the refusals change.
			throw forbidden(
				`No destination resolved. The token must grant exactly one logs destination for this environment, or name one with the ${INDEX_HEADER} header.`,
				'INGEST_DESTINATION_NOT_RESOLVED'
			);
		}
		if (indexId === config.traceIndexId) {
			throw badRequest(
				'That destination is the span store. Send spans to POST /v1/traces instead.',
				'INDEX_IS_TRACE_INDEX'
			);
		}
		const upstreamUrl = quickwitUrl(`/api/v1/${encodeURIComponent(indexId)}/ingest`);
		const contentType = c.req.header('content-type') ?? CONTENT_TYPE_JSON;

		const headers: Record<string, string> = { 'content-type': contentType };
		const contentLength = c.req.header('content-length');
		if (contentLength) headers['content-length'] = contentLength;
		const contentEncoding = c.req.header('content-encoding');
		if (contentEncoding) headers['content-encoding'] = contentEncoding;

		const result = await proxyToQuickwit(c, { upstreamUrl, headers });

		const respHeaders: Record<string, string> = {};
		const upstreamCt = result.headers.get('content-type');
		if (upstreamCt) respHeaders['content-type'] = upstreamCt;
		return new Response(result.bodyBytes, { status: result.status, headers: respHeaders });
	}
);
