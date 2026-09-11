import type { MiddlewareHandler } from 'hono';

import type { MachineEnv } from '../env.js';
import { logger } from '../lib/logger.js';
import { TokenRejected } from '../tunda/human-token.js';
import { verifyMachineToken } from '../tunda/machine-token.js';
import { extractBearerToken } from '../utils/bearer.js';
import { forbidden, unauthorized } from '../utils/http-error.js';

/**
 * Authenticates a telemetry producer.
 *
 * ## What this replaced
 *
 * An `rpk_`-prefixed key this console minted and stored. That made the console an
 * issuer of credentials — one more place a secret lives, with its own rotation
 * story and no relationship to the platform that knows which services exist.
 *
 * A producer now presents a Tunda `client_credentials` token, one registration per
 * producer. The consequences are worth stating because they are the point:
 *
 * - **Rotation and revocation are Tunda's**, so a compromised host is one
 *   registration disabled rather than a key hunted through configuration.
 * - **Every accepted batch is attributable** to a registration, not to a string in
 *   a payload.
 * - **The destinations are in the token**, signed, so this console never reads
 *   where to store something from the thing it is being asked to store.
 */
export const requireMachine: MiddlewareHandler<MachineEnv> = async (c, next) => {
	const bearer = extractBearerToken(c.req.header('authorization'));
	if (!bearer) {
		throw unauthorized('Missing bearer token', 'INGEST_MISSING_BEARER');
	}

	try {
		c.set('machine', await verifyMachineToken(bearer));
	} catch (err) {
		if (err instanceof TokenRejected) {
			// The reason is for this console's logs. A producer learns only that the
			// token was not accepted: an expired token and a forged one told apart is
			// a forgery oracle, and a producer can do nothing differently either way.
			logger.warn({ reason: err.reason }, 'ingest token rejected');
			throw forbidden('Invalid ingest token', 'INGEST_INVALID_TOKEN');
		}
		throw err;
	}

	await next();
};
