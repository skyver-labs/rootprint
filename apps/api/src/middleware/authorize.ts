import type { MiddlewareHandler } from 'hono';

import type { AuthedEnv } from '../env.js';

/**
 * Where an authorization decision will go, and what happens until it does.
 *
 * ## Phase 1 grants every authenticated principal
 *
 * This is deliberate, documented, and temporary. It replaced
 * `session.user.role !== 'admin'` — a comparison against a column this console
 * owned, which was the second authority the fork exists to remove.
 *
 * The increment is defensible on its own: after Phase 1, **only Tunda can
 * authenticate**, which is the property ADR 0036 is about. Nobody reaches this
 * function who has not completed a Tunda authorization-code flow at the assurance
 * Tunda's own risk engine demanded.
 *
 * What it is not is fine-grained. Every operator can currently do everything an
 * operator can do, and that is a smaller surface than upstream's `admin | user`
 * only because there is no longer a way to become an operator without Tunda.
 *
 * ## What replaces the body in Phase 2
 *
 * A `Check` against `tunda.internal.v1.AuthorizationService` over mutual TLS,
 * carrying the subject, the action, the resource and the assurance from the
 * verified token — and carrying **no roles**, because the PDP reads those from the
 * tenant directory at decision time. Obligations come back and must be enforced
 * or the permit becomes a denial.
 *
 * The signature already takes the action and the resource so that adding the call
 * is a change to this function rather than to every call site. That is the only
 * reason those parameters exist today.
 *
 * A production release does not ship with this body. §18.6 of the console
 * specification states the gate: no production release with "every authenticated
 * user is an operator" as the final state.
 */
export function authorize(
	_action: string,
	_resource?: { kind: string; id?: string }
): MiddlewareHandler<AuthedEnv> {
	return async (_c, next) => {
		// Phase 1: authenticated is authorized. See the note above.
		await next();
	};
}

/**
 * The operator surface.
 *
 * Named for what it will mean rather than for what it currently does, so the call
 * sites do not have to change when the body does.
 */
export const requireOperator: MiddlewareHandler<AuthedEnv> = authorize('operate');
