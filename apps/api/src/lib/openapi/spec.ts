import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { generateSpecs } from 'hono-openapi';
import type { GenerateSpecOptions } from 'hono-openapi';
import type { Env, Hono } from 'hono';
import type { Schema } from 'hono/types';

import { errorResponseComponents } from './errors.js';

function rootVersion(): string {
	const here = path.dirname(fileURLToPath(import.meta.url));
	const pkgPath = path.resolve(here, '../../../../../package.json');
	return JSON.parse(readFileSync(pkgPath, 'utf8')).version as string;
}

const documentation: GenerateSpecOptions['documentation'] = {
	openapi: '3.1.0',
	info: {
		title: 'Rootprint API',
		version: rootVersion(),
		description: 'HTTP API for the Rootprint log management platform.'
	},
	servers: [{ url: 'https://example.com', description: 'Rootprint API' }],
	components: {
		securitySchemes: {
			// The opaque console session. Its value is meaningless outside this
			// deployment's database, which is the point: a tool holding one can call
			// this API and can do nothing with it anywhere else.
			cookieAuth: { type: 'apiKey', in: 'cookie', name: '__Host-rp_session' },
			// A Tunda `client_credentials` access token, for producers only. There is
			// no read-capable bearer scheme: personal and service-account API keys
			// were this console's own credentials, and it no longer issues any.
			ingestBearer: {
				type: 'http',
				scheme: 'bearer',
				description: 'A Tunda access token for a registered telemetry producer'
			}
		},
		responses: errorResponseComponents
	},
	security: [{ cookieAuth: [] }]
};

// Single source of truth so the live /api/openapi.json and the generated file match.
export const specOptions = {
	documentation,
	excludeStaticFile: true,
	excludeMethods: ['OPTIONS', 'HEAD'],
	// Keep only the documented API surface; drop the SPA catch-all and asset routes.
	exclude: [/^\/(?!api\/|v1\/).*/]
} satisfies Partial<GenerateSpecOptions>;

export async function buildSpec<E extends Env, S extends Schema, P extends string>(
	app: Hono<E, S, P>
) {
	const spec = await generateSpecs(app, specOptions);

	return {
		...spec,
		paths: spec.paths,
		components: {
			...spec.components,
			securitySchemes: {
				...spec.components?.securitySchemes
			},
			schemas: spec.components?.schemas
		}
	};
}
