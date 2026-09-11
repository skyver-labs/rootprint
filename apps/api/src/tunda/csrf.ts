import type { Context } from 'hono';

import { config } from '../config.js';

/**
 * Cross-site request forgery defence for cookie-authenticated writes.
 *
 * ## Why `SameSite=Lax` is not enough on its own
 *
 * The session cookie is `Lax`, which already refuses a cross-site `POST`. That
 * covers the classic form-submission attack and does not cover everything: `Lax`
 * still sends the cookie on a top-level cross-site `GET`, browsers differ on what
 * counts as top-level, and a mistake that turns a state change into a `GET` is one
 * route definition away.
 *
 * So unsafe methods carry two further checks, and both are cheap:
 *
 * - **`Origin` must be one this console serves.** Every browser sends it on an
 *   unsafe request. A request with none, or with somebody else's, is refused.
 * - **`Sec-Fetch-Site` must not be cross-site.** Defence in depth — it is not
 *   universally present, so its absence is tolerated and its presence is believed.
 *
 * ## What this deliberately does not apply to
 *
 * Bearer-authenticated traffic: telemetry producers, and anything presenting a
 * token rather than a cookie. CSRF is an attack on *ambient* credentials — a
 * browser attaching a cookie the user did not intend to send. A caller that has to
 * construct an `Authorization` header is not doing that, and requiring an origin
 * from an OpenTelemetry collector would only break it.
 */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Whether this request may proceed as a cookie-authenticated write. */
export function passesCsrfChecks(c: Context): boolean {
	if (SAFE_METHODS.has(c.req.method)) {
		return true;
	}

	// Present and believed when present. `cross-site` is the only value that is
	// definitively an attack; `none` is a user typing a URL, which cannot carry a
	// body anyway.
	const fetchSite = c.req.header('sec-fetch-site');
	if (fetchSite === 'cross-site') {
		return false;
	}

	const origin = c.req.header('origin');
	if (origin === undefined || origin === 'null') {
		// No Origin on an unsafe request means either a very old browser or a
		// non-browser client that should be using a bearer token. Both are refused
		// on the cookie path.
		return false;
	}

	return allowedOrigins().has(origin);
}

function allowedOrigins(): ReadonlySet<string> {
	const origins = new Set<string>([config.origin]);
	if (config.frontendUrl) {
		origins.add(config.frontendUrl);
	}
	return origins;
}
