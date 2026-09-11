import type { Context, MiddlewareHandler } from 'hono';

import type { AuthedEnv } from '../env.js';
import { consoleAuthorization } from '../tunda/schema.js';
import { consoleResource, indexResource, proposedIndexResource } from '../tunda/index-resource.js';
import { db } from '../lib/db.js';
import { logger } from '../lib/logger.js';
import { randomToken } from '../tunda/crypto.js';
import { batchCheck, check, type PdpDecision, type PdpPrincipal } from '../tunda/pdp.js';

/**
 * Every authorization decision this console makes, made by Tunda.
 *
 * ## What this replaced
 *
 * Two things, in order. First `session.user.role !== 'admin'` — a comparison
 * against a column this console owned, which was the second authority the fork
 * exists to remove. Then a body that granted every authenticated principal and
 * said so:
 *
 *     // Phase 1: authenticated is authorized. See the note above.
 *     await next();
 *
 * That was defensible as an increment, because after Phase 1 only Tunda could
 * authenticate and nobody reached it without completing a flow at the assurance
 * Tunda's risk engine demanded. It was not fine-grained, and §18.6 of the console
 * specification named it the release gate: no production ship with "every
 * authenticated user is an operator" as the final state.
 *
 * ## What it does now
 *
 * One `Check` against `tunda.internal.v1.AuthorizationService`, carrying the
 * subject, the action, the resource and the assurance from the verified session —
 * and carrying **no roles**, because the PDP reads those from the tenant
 * directory at decision time. That is what makes a revocation take effect on the
 * next request rather than on the next token.
 *
 * ## Why the signature did not change
 *
 * `authorize(action, resource)` already took both parameters through Phase 1,
 * when it used neither. They existed precisely so that wiring the PDP would be a
 * change to this function rather than to thirty call sites, and it was.
 *
 * What did change is what the actions say. `requireOperator` — one generic
 * `operate` covering index management, the activity log and the cluster view — is
 * gone, because the policy bundle distinguishes those and a middleware that
 * collapsed them would have thrown the distinction away at the door. Deleting a
 * log index and reading a metric are not the same permission.
 */

/**
 * Which resource a route is about.
 *
 * `observability_index` resolves its id from the route parameter and its
 * attributes from this console's own metadata — never from the request. See
 * `index-resource.ts`.
 */
export type ResourceSelector =
	| { kind: 'observability_index'; param?: string }
	| { kind: 'observability_index'; indexId: string }
	| { kind: 'observability_index'; proposed: true }
	| { kind: 'observability_console' };

/** The principal, as the PDP needs them. Read from the verified session, nowhere else. */
function principalOf(c: Context<AuthedEnv>): PdpPrincipal {
	const tunda = c.get('tunda');
	return {
		tenantId: tunda.tundaTenantId,
		subject: tunda.subject,
		acr: tunda.acr,
		amr: tunda.amr,
		authTime: tunda.authTime
	};
}

/**
 * Records what was decided and what this console did about it.
 *
 * This is how the `AUDIT` obligation is honoured, and honouring it is a condition
 * of the permit rather than a courtesy: `authorization.proto` says an obligation
 * the caller does not enforce makes the decision an authorization failure. So the
 * row is written **before** the handler runs, and a failure to write it refuses
 * the request — a permit whose audit record did not survive is a permit that was
 * never valid.
 *
 * Denials are recorded too, including the ones where the PDP never answered.
 * "Nobody could search anything for four minutes" is a fact worth having and is
 * invisible if only permits are written.
 */
async function record(
	c: Context<AuthedEnv>,
	action: string,
	resourceType: string,
	resourceId: string | undefined,
	decision: PdpDecision
): Promise<void> {
	const tunda = c.get('tunda');

	await db.insert(consoleAuthorization).values({
		id: randomToken(),
		principalId: tunda.principalId,
		tundaTenantId: tunda.tundaTenantId,
		tundaUserId: tunda.subject,
		action,
		resourceType,
		resourceId: resourceId ?? null,
		decision: decision.allowed ? 'PERMIT' : decision.challenge ? 'CHALLENGE' : 'DENY',
		reasonCode: decision.reasonCode,
		// Null rather than an empty string when the PDP never answered: a timeout
		// has no decision id, and inventing one would make an outage join to
		// nothing during an investigation while looking like it should.
		decisionId: decision.decisionId === '' ? null : decision.decisionId,
		acr: tunda.acr,
		traceId: c.get('requestId')
	});
}

/**
 * The response to a refusal.
 *
 * A `CHALLENGE` is answered differently from a `DENY`, because the operator's
 * correct next move differs: one is a step-up they can complete, the other is a
 * permission they do not have. Collapsing them would leave somebody staring at a
 * refusal they could have cleared in ten seconds.
 *
 * Neither carries the reason to the browser. `RESTRICTED_INDEX_REQUIRES_GRANT`
 * and `NO_MATCHING_RULE` are different answers to "does this index exist and what
 * is in it", and telling them apart is a probe. The reason is in the log and in
 * `console_authorization`, where an operator can read it and an attacker cannot.
 */
function refuse(c: Context<AuthedEnv>, decision: PdpDecision): Response {
	if (decision.challenge) {
		return c.json(
			{
				error: {
					code: 'STEP_UP_REQUIRED',
					message: 'This action needs a stronger authentication than the current session.',
					// AAL3 is the only level anything in this console steps up to: every
					// rule that can challenge here is one of the hardware-key rules.
					// Named rather than left for the browser to guess, because a guess
					// that is too low starts a ceremony that ends in the same refusal.
					requiredAcr: 'urn:tunda:aal:3'
				}
			},
			403
		);
	}

	return c.json(
		{ error: { code: 'FORBIDDEN', message: 'You do not have permission to do that.' } },
		403
	);
}

/** Resolves the resource a request is about. */
async function resourceFor(c: Context<AuthedEnv>, selector: ResourceSelector) {
	if (selector.kind === 'observability_console') {
		return consoleResource();
	}

	if ('proposed' in selector) {
		// Creating an index, which does not exist yet and therefore has no stored
		// metadata to read. The attributes come from the request body — the one
		// place in this console where they do.
		//
		// That is not the hole it looks like. `create` requires
		// `platform_observability_admin`: AAL3, a hardware key proven in the last
		// five minutes. Somebody who holds that can create an index and then set
		// its classification to anything, because `change_field_config` is the same
		// derived role — so stating it in the create body grants nothing that was
		// not already held, and it forces the question to be answered while
		// somebody is still thinking about what the index is for.
		//
		// The rule that matters is untouched: the classification behind a *read*
		// decision comes from `index_settings`, never from a request. See
		// `index-resource.ts`.
		// `c.req.valid('json')` rather than a fresh parse: the route runs its
		// validator before this middleware for exactly that reason, so the body
		// reaching policy is the one the schema accepted rather than whatever
		// arrived.
		return proposedIndexResource(c.req.valid('json' as never) ?? {});
	}

	// A route that always searches the same index — the trace store behind the
	// monitoring and trace views — names it here rather than in its path. Still
	// looked up in `index_settings` like any other: a hard-coded id says which
	// index, never what is in it.
	if ('indexId' in selector) {
		return indexResource(selector.indexId);
	}

	const name = selector.param ?? 'indexId';
	const indexId = c.req.param(name);

	if (indexId === undefined || indexId === '') {
		// A route declared as being about an index with no index in its path.
		// Thrown rather than decided about a blank id, which would ask the PDP a
		// question with no subject and act on an answer that means nothing.
		throw new Error(
			`authorize() was told this route is about an observability_index, but no '${name}'` +
				' parameter is in the path'
		);
	}

	return indexResource(indexId);
}

/**
 * Decides one request, or refuses it.
 *
 * @param action the policy action, e.g. `search`, `delete`, `view_activity`.
 *   Exactly the names in Tunda's resource policies — a name invented here matches
 *   no rule, which is a denial nobody can explain.
 */
export function authorize(
	action: string,
	selector: ResourceSelector
): MiddlewareHandler<AuthedEnv> {
	return async (c, next) => {
		const resource = await resourceFor(c, selector);
		const decision = await check(principalOf(c), action, resource, c.get('requestId'));

		await record(c, action, resource.type, resource.id, decision);

		if (!decision.allowed) {
			logger.info(
				{
					action,
					resource: resource.type,
					resourceId: resource.id,
					reason: decision.reasonCode,
					decisionId: decision.decisionId || undefined
				},
				'authorization refused'
			);
			return refuse(c, decision);
		}

		await next();
		return;
	};
}

/**
 * Decides many resources in one round trip.
 *
 * Rendering the index picker is one `BatchCheck`, not one `Check` per index. The
 * contract exists for this and says so: an RPC per row turns a page render into a
 * latency multiplier, and the natural fix for that is caching decisions — which
 * is the thing ADR 0030 spent its length arguing against.
 *
 * Returns the ids the principal may act on, in the order given. A caller filters
 * its own list with this rather than asking per row, and a refused index is
 * simply absent: the picker shows what can be searched, and an entry that appears
 * and then refuses on click is worse than one that never appeared.
 */
export async function authorizeEach(
	c: Context<AuthedEnv>,
	action: string,
	indexIds: readonly string[]
): Promise<string[]> {
	if (indexIds.length === 0) {
		return [];
	}

	const resources = await Promise.all(indexIds.map((indexId) => indexResource(indexId)));
	const decisions = await batchCheck(
		principalOf(c),
		resources.map((resource) => ({ action, resource })),
		c.get('requestId')
	);

	// Every decision is recorded, permits and refusals alike. A batch is where the
	// temptation to record only the permits is strongest — it is N rows for one
	// page render — and it is also where the interesting fact lives: an operator
	// whose visible index list shrank overnight is a role change nobody announced.
	await Promise.all(
		decisions.map((decision, i) =>
			record(c, action, 'observability_index', resources[i]?.id, decision)
		)
	);

	return indexIds.filter((_id, i) => decisions[i]?.allowed === true);
}
