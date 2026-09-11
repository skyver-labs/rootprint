import { afterEach, describe, expect, test } from 'bun:test';
import { Code, ConnectError, type Transport } from '@connectrpc/connect';
import { create } from '@bufbuild/protobuf';

import {
	BatchCheckRequestSchema,
	BatchCheckResponseSchema,
	CheckResponseSchema,
	CheckResponse_Decision,
	type BatchCheckRequest
} from '../gen/tunda/internal/v1/authorization_pb.js';
import { batchCheck, check, interpret, setPdpTransport, type PdpPrincipal } from './pdp.js';

/**
 * Two properties, and the tests are shaped around them rather than around the
 * functions.
 *
 * **What goes out.** The console tells the PDP who is asking and what about, and
 * nothing else. `subject.roles` and `subject.attributes` must leave empty — a
 * caller that could name its own roles would be granting itself whatever it
 * named, and `security_domain` is the attribute every platform rule in Tunda's
 * bundle is gated on. The server refuses a populated one, so a regression here
 * fails closed; it also breaks every decision at once, which is why it is worth
 * a test that says so in one line.
 *
 * **What comes back.** Exactly one shape produces a permit. Everything else — a
 * timeout, a transport error, `DECISION_UNSPECIFIED`, a short batch, an
 * obligation this console cannot honour — is a denial. That rule is the whole of
 * `interpret`, and the cases below are the ways it could quietly stop holding.
 *
 * A transport double rather than a live node: these are properties of what this
 * module sends and accepts. `make dev-smoke` in the platform repository drives
 * the real thing end to end.
 */

const PRINCIPAL: PdpPrincipal = {
	tenantId: 'tnt_01K3ST0000E008000000000081',
	subject: 'usr_01K3ST0000E0080000000000D1',
	acr: 'urn:tunda:aal:3',
	amr: ['hwk', 'pwd'],
	authTime: new Date('2026-09-11T09:00:00Z')
};

const RESOURCE = {
	type: 'observability_index',
	id: 'otel-logs-v0_9',
	attributes: { classification: 'INTERNAL', environment: 'sandbox' }
} as const;

type Responder = (request: BatchCheckRequest) => unknown;

/** A transport that records what was sent and replies with whatever the test wants. */
function fakeTransport(respond: Responder): { transport: Transport; sent: BatchCheckRequest[] } {
	const sent: BatchCheckRequest[] = [];
	const transport: Transport = {
		async unary(_method, _signal, _timeoutMs, _header, input) {
			const request = create(BatchCheckRequestSchema, input as never);
			sent.push(request);
			const message = respond(request);
			if (message instanceof Error) {
				throw message;
			}
			return {
				stream: false,
				service: {} as never,
				method: {} as never,
				header: new Headers(),
				trailer: new Headers(),
				message: message as never
			};
		},
		async stream() {
			throw new Error('the PDP client makes no streaming calls');
		}
	};
	return { transport, sent };
}

function permit(correlationId: string, obligations: { type: string }[] = []) {
	return create(CheckResponseSchema, {
		decision: CheckResponse_Decision.PERMIT,
		reasonCode: 'POLICY_MATCH',
		decisionId: 'dec_01M28KFFPST0PG8RJDPG0ZBKS1',
		obligations: obligations.map((o) => ({ type: o.type, parameters: {} }))
	});
}

function batchOf(...results: { correlationId: string; response: ReturnType<typeof permit> }[]) {
	return create(BatchCheckResponseSchema, { results });
}

afterEach(() => setPdpTransport(null));

describe('what the console sends', () => {
	test('carries no roles and no attributes, whatever the principal holds', async () => {
		// The single most important line in this file. Tunda reads roles from
		// `user_role_assignment` at decision time, which is what makes a revocation
		// take effect on the next request — a console that sent its own would be
		// deciding its own authorization and calling it a check.
		const { transport, sent } = fakeTransport((request) =>
			batchOf({ correlationId: request.items[0]!.correlationId, response: permit('0') })
		);
		setPdpTransport(transport);

		await check(PRINCIPAL, 'search', RESOURCE);

		expect(sent[0]!.subject!.roles).toEqual([]);
		expect(sent[0]!.subject!.attributes).toEqual({});
	});

	test('carries the assurance the token asserted, not a summary of it', async () => {
		// `acr`, `amr` and `auth_time` all travel: a rule saying "AAL2 within five
		// minutes" cannot be evaluated without the third, and one saying "with a
		// hardware key" cannot be evaluated without the second.
		const { transport, sent } = fakeTransport((request) =>
			batchOf({ correlationId: request.items[0]!.correlationId, response: permit('0') })
		);
		setPdpTransport(transport);

		await check(PRINCIPAL, 'search', RESOURCE);

		expect(sent[0]!.assurance!.level).toBe('urn:tunda:aal:3');
		expect(sent[0]!.assurance!.methods).toEqual(['hwk', 'pwd']);
		expect(sent[0]!.assurance!.authenticatedAtEpochSeconds).toBe(
			BigInt(Math.floor(PRINCIPAL.authTime.getTime() / 1000))
		);
	});

	test('asks about every index in one batch, not one call each', async () => {
		const { transport, sent } = fakeTransport((request) =>
			batchOf(
				...request.items.map((item) => ({
					correlationId: item.correlationId,
					response: permit(item.correlationId)
				}))
			)
		);
		setPdpTransport(transport);

		await batchCheck(
			PRINCIPAL,
			['a', 'b', 'c'].map((id) => ({ action: 'list', resource: { ...RESOURCE, id } }))
		);

		expect(sent).toHaveLength(1);
		expect(sent[0]!.items).toHaveLength(3);
	});
});

describe('what the console accepts', () => {
	test('a clean permit, and only then', async () => {
		const { transport } = fakeTransport((request) =>
			batchOf({ correlationId: request.items[0]!.correlationId, response: permit('0') })
		);
		setPdpTransport(transport);

		expect((await check(PRINCIPAL, 'search', RESOURCE)).allowed).toBe(true);
	});

	test('refuses when the transport fails', async () => {
		setPdpTransport(
			fakeTransport(() => new ConnectError('unreachable', Code.Unavailable)).transport
		);

		const decision = await check(PRINCIPAL, 'search', RESOURCE);

		expect(decision.allowed).toBe(false);
		expect(decision.reasonCode).toBe('PDP_UNAVAILABLE_Unavailable');
	});

	test('refuses when the PDP does not answer in time', async () => {
		// A PDP that has not answered in 250ms has not answered. Asserted as its own
		// case because a timeout is the failure most likely to be retried into a
		// grant by somebody making the console feel faster.
		setPdpTransport(
			fakeTransport(() => new ConnectError('timed out', Code.DeadlineExceeded)).transport
		);

		const decision = await check(PRINCIPAL, 'search', RESOURCE);

		expect(decision.allowed).toBe(false);
		expect(decision.reasonCode).toBe('PDP_UNAVAILABLE_DeadlineExceeded');
	});

	test('refuses when the batch comes back short', async () => {
		// Three asked, two answered. The missing one is a denial rather than an
		// index quietly dropped from a permitted list — and the ordering is not
		// trusted either: results are paired by correlation id.
		const { transport } = fakeTransport((request) =>
			batchOf(
				{ correlationId: request.items[0]!.correlationId, response: permit('0') },
				{ correlationId: request.items[2]!.correlationId, response: permit('2') }
			)
		);
		setPdpTransport(transport);

		const decisions = await batchCheck(
			PRINCIPAL,
			['a', 'b', 'c'].map((id) => ({ action: 'list', resource: { ...RESOURCE, id } }))
		);

		expect(decisions.map((d) => d.allowed)).toEqual([true, false, true]);
		expect(decisions[1]!.reasonCode).toBe('PDP_RETURNED_NO_DECISION');
	});

	test('refuses a permit carrying an obligation it cannot honour', () => {
		// The case that matters most and is easiest to get wrong. MASK_FIELDS is a
		// permit — the policy says this operator may search a PII index provided
		// these fields are redacted — and nothing in this console redacts anything,
		// so acting on it would return the customer data the policy said to remove.
		const decision = interpret(
			create(CheckResponseSchema, {
				decision: CheckResponse_Decision.PERMIT,
				reasonCode: 'POLICY_MATCH',
				decisionId: 'dec_x',
				obligations: [{ type: 'MASK_FIELDS', parameters: { fields: 'user.email' } }]
			})
		);

		expect(decision.allowed).toBe(false);
		expect(decision.reasonCode).toBe('OBLIGATION_NOT_ENFORCEABLE');
		// The decision id survives the refusal: an investigation needs to find the
		// platform's own evidence row for a permit this console declined to use.
		expect(decision.decisionId).toBe('dec_x');
	});

	test('refuses a permit needing a second pair of eyes, which nothing here collects', () => {
		const decision = interpret(
			create(CheckResponseSchema, {
				decision: CheckResponse_Decision.PERMIT,
				obligations: [{ type: 'REQUIRE_DUAL_APPROVAL', parameters: { scope: 'x' } }]
			})
		);

		expect(decision.allowed).toBe(false);
	});

	test('accepts a permit whose only obligation is AUDIT', () => {
		const decision = interpret(
			create(CheckResponseSchema, {
				decision: CheckResponse_Decision.PERMIT,
				obligations: [{ type: 'AUDIT', parameters: { level: 'HIGH' } }]
			})
		);

		expect(decision.allowed).toBe(true);
		expect(decision.obligations).toEqual([{ type: 'AUDIT', parameters: { level: 'HIGH' } }]);
	});

	test('refuses a response that decided nothing', () => {
		// `DECISION_UNSPECIFIED` is the proto's zero value, which is also what a
		// field this console's generated types do not understand decodes to. Both
		// are "the server did not say permit", and neither is a grant.
		const decision = interpret(create(CheckResponseSchema, {}));

		expect(decision.allowed).toBe(false);
	});

	test('reports a challenge as a challenge, not as a flat refusal', () => {
		// The operator's correct next move differs: one is a step-up they can
		// complete in ten seconds, the other is a permission they do not have.
		const decision = interpret(
			create(CheckResponseSchema, {
				decision: CheckResponse_Decision.CHALLENGE,
				reasonCode: 'STEP_UP_REQUIRED'
			})
		);

		expect(decision.allowed).toBe(false);
		expect(decision.challenge).toBe(true);
	});

	test('a challenge carries no obligations forward', () => {
		// Nothing was permitted, so there is nothing to honour. A challenge that
		// leaked an AUDIT obligation would have the console recording a permit that
		// did not happen.
		const decision = interpret(
			create(CheckResponseSchema, {
				decision: CheckResponse_Decision.CHALLENGE,
				obligations: [{ type: 'AUDIT', parameters: { level: 'HIGH' } }]
			})
		);

		expect(decision.obligations).toEqual([]);
	});

	test('a denial carries none either', () => {
		const decision = interpret(
			create(CheckResponseSchema, {
				decision: CheckResponse_Decision.DENY,
				reasonCode: 'RESTRICTED_INDEX_REQUIRES_GRANT',
				obligations: [{ type: 'AUDIT', parameters: { level: 'CRITICAL' } }]
			})
		);

		expect(decision.allowed).toBe(false);
		expect(decision.obligations).toEqual([]);
		expect(decision.reasonCode).toBe('RESTRICTED_INDEX_REQUIRES_GRANT');
	});
});
