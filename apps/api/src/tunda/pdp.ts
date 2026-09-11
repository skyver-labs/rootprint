import { Code, ConnectError, createClient, type Client, type Transport } from '@connectrpc/connect';
import { createGrpcTransport } from '@connectrpc/connect-node';

import {
	AuthorizationService,
	CheckResponse_Decision,
	type CheckResponse,
	type Obligation
} from '../gen/tunda/internal/v1/authorization_pb.js';
import { logger } from '../lib/logger.js';

/**
 * The policy decision point, which is not in this process.
 *
 * ## Why a remote call and not a role column
 *
 * Because the alternative is a second authority, and this fork exists to have
 * one. The obvious cheap designs are a `role` claim in the access token and a
 * mirrored role table fed by events, and both have the same defect: a revocation
 * takes effect when the token expires or when the mirror catches up, not when
 * somebody revokes it. ADR 0030 refused that for every Java surface in the
 * platform and this console does not get an exception for being written in
 * TypeScript.
 *
 * What the console sends is **who is asking** and **what they are asking about**.
 * What it never sends is what they may do. `subject.roles` and
 * `subject.attributes` go out empty, and the server refuses the call outright if
 * they are not — a caller that could name its own roles would be granting itself
 * whatever it named, and `security_domain` is the attribute every platform rule
 * in the bundle is gated on.
 *
 * ## Fail closed, and what that actually means here
 *
 * The only path that returns a permit is an explicit `PERMIT` whose every
 * obligation this console knows how to honour. A timeout, a transport error, an
 * unreachable node, an unparseable response, `DECISION_UNSPECIFIED`, an
 * obligation nobody here implements — all denials.
 *
 * That last one is the interesting case and it is not a technicality.
 * `authorization.proto` is explicit: an obligation the caller does not enforce
 * makes the whole decision an authorization failure. So a permit carrying
 * `MASK_FIELDS` is a **denial in this console today**, because nothing here masks
 * a field, and returning those rows would be returning customer data the policy
 * said to redact. The permit becomes real when the masking does. See
 * {@link SUPPORTED_OBLIGATIONS}.
 *
 * ## The availability objection
 *
 * "Now the console cannot serve a page when the platform is down." It could not
 * anyway — the operator cannot sign in. What this adds is that an *established*
 * session cannot search during a PDP outage, and that is bounded by running a cas
 * node beside the observability cell: a node holds its policy bundle in its own
 * image and authenticates through a control-plane outage, so the PDP's
 * availability is the local node's rather than a remote cell's.
 */

/**
 * How long a decision has to arrive.
 *
 * A PDP that has not answered in 250ms has not answered. Short deliberately: it
 * sits in front of every read, the node is meant to be co-located, and a generous
 * deadline here turns a slow PDP into a slow console rather than into an alert.
 */
const DEADLINE_MS = 250;

/*
 * Measured against a co-located node in the development stack: p50 26ms, p95
 * 38ms, worst of twenty-five 84ms. Roughly three times the headroom, which is
 * the right amount for a number that decides whether a page renders.
 *
 * The first call after a node restart is the exception and can exceed a second
 * while the JVM warms and the policy bundle loads. That request is refused, and
 * refusing it is correct: a retry here would be indistinguishable from a retry
 * against a PDP that is genuinely too slow to be relied on, and the second one
 * must not be papered over.
 */

/**
 * The obligations this console can actually honour.
 *
 * An explicit allowlist, and the shape matters more than the contents. The
 * tempting implementation is a switch that handles what it knows and ignores the
 * rest, which silently converts "mask these fields" into "return them" — so
 * anything not named here is a denial, and adding an obligation type to the
 * policy bundle cannot widen what this console returns until somebody implements
 * it here.
 *
 * `AUDIT` only, today. `MASK_FIELDS`, `FILTER_RESULTS` and
 * `REQUIRE_DUAL_APPROVAL` are all things the bundle emits and this console
 * cannot do, so the surfaces that attract them — searching a PII index,
 * deleting an index — are refused rather than served unredacted or unapproved.
 */
const SUPPORTED_OBLIGATIONS: ReadonlySet<string> = new Set(['AUDIT']);

/**
 * Who is asking, as the PDP needs them.
 *
 * A shape rather than one of this console's token types, because both a
 * `VerifiedHumanToken` and a stored `ConsoleSession` satisfy it and neither
 * should have to be converted into the other to ask a question. It is also the
 * complete list of what this console tells the PDP about a principal: an
 * identifier, a tenant, and what was proven. Nothing about what they may do.
 */
export type PdpPrincipal = {
	readonly tenantId: string;
	readonly subject: string;
	readonly acr: string;
	readonly amr: readonly string[];
	readonly authTime: Date;
};

/** What the console asks about. Never derived from a request parameter. */
export type PdpResource = {
	readonly type: string;
	readonly id?: string;

	/**
	 * The attributes policy compares.
	 *
	 * Console-supplied, and therefore trusted exactly as far as this console is.
	 * They MUST come from the console's own metadata — a user who could set
	 * `classification: "NONE"` on a request could read any index. The schema
	 * requires `classification` and `environment`, and absence never satisfies a
	 * condition, so an index this console failed to classify is refused rather
	 * than readable.
	 */
	readonly attributes: Readonly<Record<string, string>>;
};

/** One question, for a batch. */
export type PdpQuery = {
	readonly action: string;
	readonly resource: PdpResource;
};

/** What came back, reduced to what a caller may act on. */
export type PdpDecision = {
	readonly allowed: boolean;

	/**
	 * Whether the refusal is "prove more", not "no".
	 *
	 * The PDP distinguishes these and the console must too: `CHALLENGE` means the
	 * operator should be sent to a step-up, and rendering it as a flat refusal
	 * would leave them staring at a denial they could have cleared.
	 */
	readonly challenge: boolean;

	/** Stable and machine-readable, so a denial is explainable months later. */
	readonly reasonCode: string;

	/** Correlates with the evidence record the PDP wrote. Empty if it never answered. */
	readonly decisionId: string;

	/** The obligations that came back, all of which are in {@link SUPPORTED_OBLIGATIONS}. */
	readonly obligations: readonly { type: string; parameters: Record<string, string> }[];
};

/** The denial every failure produces. Never constructed with `allowed: true`. */
function refused(reasonCode: string, decisionId = ''): PdpDecision {
	return { allowed: false, challenge: false, reasonCode, decisionId, obligations: [] };
}

let client: Client<typeof AuthorizationService> | null = null;

/**
 * The transport, built once.
 *
 * HTTP/2 with no TLS in a development stack, where the node is a container on the
 * same network and the PDP is configured to decide for callers the transport did
 * not authenticate. In any other deployment this is mutual TLS and the node
 * refuses the call without a client certificate — which is the correct default
 * and the reason the insecure one has to be asked for by URL scheme rather than
 * arrived at.
 */
function pdp(): Client<typeof AuthorizationService> {
	if (client === null) {
		const baseUrl = process.env['TUNDA_PDP_URL'];
		if (baseUrl === undefined || baseUrl === '') {
			// Refused at first use rather than defaulted to a localhost guess. A
			// console that silently pointed at nothing would fail every decision
			// closed — correct, and indistinguishable from a policy that denies.
			throw new Error(
				'TUNDA_PDP_URL is required: the console does not evaluate policy and has nowhere' +
					' to ask. Point it at a cas node serving tunda.internal.v1.AuthorizationService,' +
					' e.g. http://cas:9090.'
			);
		}
		client = createClient(AuthorizationService, createGrpcTransport({ baseUrl }));
	}
	return client;
}

/**
 * Replaces the client, or resets it. Tests only.
 *
 * Present so the two properties that matter can be asserted without a live node:
 * that the request carries no roles and no attributes, and that every response
 * other than a clean permit is a denial. Both are invariants of what this module
 * *sends and accepts*, which a transport double observes exactly and an
 * integration test observes only indirectly.
 */
export function setPdpTransport(transport: Transport | null): void {
	client = transport === null ? null : createClient(AuthorizationService, transport);
}

/**
 * Decides one access request.
 *
 * Returns a denial rather than throwing on every failure, so a caller cannot
 * accidentally treat "the PDP is down" as a different case from "the policy said
 * no" and handle only one of them.
 */
export async function check(
	principal: PdpPrincipal,
	action: string,
	resource: PdpResource,
	traceId?: string
): Promise<PdpDecision> {
	const [decision] = await batchCheck(principal, [{ action, resource }], traceId);
	return decision ?? refused('PDP_RETURNED_NO_DECISION');
}

/**
 * Decides several in one round trip.
 *
 * Rendering the index picker is one call, not one per index. The contract exists
 * for this and says so: issuing an RPC per row turns a page render into a latency
 * multiplier, and the natural fix for that — caching decisions — is the thing
 * ADR 0030 spent its length arguing against.
 *
 * Always returns exactly one decision per query, in order. A short or reordered
 * response is itself a failure and produces denials.
 */
export async function batchCheck(
	principal: PdpPrincipal,
	queries: readonly PdpQuery[],
	traceId?: string
): Promise<PdpDecision[]> {
	if (queries.length === 0) {
		return [];
	}

	const subject = {
		subjectId: principal.subject,
		subjectType: 'user',
		// Both empty, and the server refuses the call if they are not. See the
		// module note: these are the two fields that would let a caller decide its
		// own authorization, and the platform treats a populated one as a defect
		// rather than as something to ignore.
		roles: [],
		attributes: {}
	};

	const assurance = {
		level: principal.acr,
		methods: [...principal.amr],
		authenticatedAtEpochSeconds: BigInt(Math.floor(principal.authTime.getTime() / 1000))
	};

	let response;
	try {
		response = await pdp().batchCheck(
			{
				tenant: { tenantId: principal.tenantId },
				subject,
				assurance,
				items: queries.map((query, index) => ({
					// The index, so a result can be paired with its question without
					// depending on the order the server happened to answer in.
					correlationId: String(index),
					action: query.action,
					resource: {
						type: query.resource.type,
						id: query.resource.id ?? '',
						attributes: { ...query.resource.attributes }
					}
				})),
				trace: traceId === undefined ? undefined : { traceId }
			},
			{ timeoutMs: DEADLINE_MS }
		);
	} catch (err) {
		// Every transport outcome is one denial per query. The reason code is for
		// this console's logs and for an operator reading a 403; it never reaches a
		// browser in enough detail to distinguish "the PDP is down" from "you may
		// not", because that distinction is a probe.
		const code = err instanceof ConnectError ? Code[err.code] : 'UNKNOWN';
		logger.warn(
			{ reason: code, detail: err instanceof ConnectError ? err.rawMessage : undefined },
			'authorization decision could not be obtained'
		);
		return queries.map(() => refused(`PDP_UNAVAILABLE_${code}`));
	}

	// Paired by correlation id rather than by position. The server returns results
	// in request order today and the proto says the id exists so a caller need not
	// depend on that.
	const byCorrelation = new Map(response.results.map((result) => [result.correlationId, result]));

	return queries.map((_query, index) => {
		const result = byCorrelation.get(String(index));
		if (result === undefined || result.response === undefined) {
			return refused('PDP_RETURNED_NO_DECISION');
		}
		return interpret(result.response);
	});
}

/**
 * One `CheckResponse`, reduced to an answer this console may act on.
 *
 * Exported for its tests. It is the whole of the fail-closed rule in one
 * function, and a rule that can only be exercised through a live gRPC server is
 * one whose edge cases nobody writes a test for.
 *
 * The only branch producing `allowed: true` is an explicit `PERMIT` every one of
 * whose obligations is supported. `DECISION_UNSPECIFIED` — a server that answered
 * without deciding, or a field this console's generated types do not know — falls
 * through to a denial rather than to a default.
 */
export function interpret(response: CheckResponse): PdpDecision {
	if (response.decision === CheckResponse_Decision.CHALLENGE) {
		return {
			allowed: false,
			challenge: true,
			reasonCode: response.reasonCode || 'STEP_UP_REQUIRED',
			decisionId: response.decisionId,
			obligations: []
		};
	}

	if (response.decision !== CheckResponse_Decision.PERMIT) {
		return refused(response.reasonCode || 'DENIED', response.decisionId);
	}

	const unsupported = response.obligations.filter(
		(obligation: Obligation) => !SUPPORTED_OBLIGATIONS.has(obligation.type)
	);

	if (unsupported.length > 0) {
		// A permit this console must not act on. Logged at WARN and not at ERROR:
		// nothing is broken, the policy is asking for something that is not built
		// yet, and the correct behaviour — refusing — is what is happening.
		logger.warn(
			{
				decisionId: response.decisionId,
				obligations: unsupported.map((obligation) => obligation.type)
			},
			'permit refused: the policy attached an obligation this console does not enforce'
		);
		return refused('OBLIGATION_NOT_ENFORCEABLE', response.decisionId);
	}

	return {
		allowed: true,
		challenge: false,
		reasonCode: response.reasonCode,
		decisionId: response.decisionId,
		obligations: response.obligations.map((obligation) => ({
			type: obligation.type,
			parameters: { ...obligation.parameters }
		}))
	};
}
