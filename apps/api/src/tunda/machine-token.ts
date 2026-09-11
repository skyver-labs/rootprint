import { jwtVerify, type JWTPayload } from 'jose';

import { issuerFor } from './issuers.js';
import { TokenRejected } from './human-token.js';

/**
 * Verifying an access token Tunda issued to a telemetry producer.
 *
 * ## Why this is separate from the human verifier
 *
 * The two are different security objects and sharing a verifier would mean one
 * function with a branch on every claim that differs — and the branch that
 * eventually goes wrong is the one that lets a machine token establish a browser
 * session, or a person's token write into an index.
 *
 * A machine token has no `sid`, no `acr`, no `amr` and no `auth_time`, because no
 * person authenticated. Requiring them would make every producer's token invalid;
 * *accepting* them here would let a human session be presented as a producer.
 *
 * ## The destination comes from the token, never from the payload
 *
 * An OTLP batch names itself:
 *
 * ```
 * service.name = identity-service
 * ```
 *
 * That is data. It was written by whatever sent the batch, and a producer wanting
 * to write into another service's index would simply change it. So the producer's
 * identity and its permitted destinations both come from the signed claim Tunda
 * put there at issue time, and the payload is checked against them.
 */

const PERMITTED_ALGORITHMS = ['ES256'] as const;
const CLOCK_SKEW_SECONDS = 60;

/** The claim Tunda carries a producer's permitted destinations in. Namespaced and versioned. */
const TELEMETRY_CLAIM = 'tunda_obs_v1';

export type TelemetrySignal = 'logs' | 'traces' | 'metrics';

export type VerifiedMachineToken = {
	/** The authenticated producer — the client registration, not anything in the payload. */
	readonly producer: string;
	readonly clientId: string;
	readonly scopes: readonly string[];

	/** Every permitted `signal:environment:index` triple, exactly as signed. */
	readonly destinations: readonly string[];
	readonly expiresAt: Date;
};

/** Verifies a producer's token, or throws {@link TokenRejected}. */
export async function verifyMachineToken(token: string): Promise<VerifiedMachineToken> {
	const claimedIssuer = readIssuerClaim(token);
	const issuer = issuerFor(claimedIssuer);
	if (issuer === undefined) {
		throw new TokenRejected('issuer is not configured');
	}

	let payload: JWTPayload;
	try {
		({ payload } = await jwtVerify(token, issuer.jwks, {
			algorithms: [...PERMITTED_ALGORITHMS],
			issuer: issuer.issuer,
			audience: issuer.audience,
			clockTolerance: CLOCK_SKEW_SECONDS
		}));
	} catch (err) {
		throw new TokenRejected(err instanceof Error ? err.name : 'verification failed');
	}

	// A token carrying a session is a person's. Refused here rather than merely
	// unused: a human token reaching the ingest path would otherwise write telemetry
	// attributed to whatever the payload claimed.
	if (typeof payload['sid'] === 'string') {
		throw new TokenRejected('a session-bound token is not a producer credential');
	}

	const telemetry = payload[TELEMETRY_CLAIM];
	if (typeof telemetry !== 'object' || telemetry === null) {
		// No telemetry scope means this registration was never granted a destination.
		// A producer with no destination may write nothing, and Tunda omits the claim
		// entirely rather than sending an empty one — an empty list reads as
		// "unrestricted" to anybody checking for presence.
		throw new TokenRejected('no telemetry scope');
	}

	const { producer, destinations } = telemetry as {
		producer?: unknown;
		destinations?: unknown;
	};

	if (typeof producer !== 'string' || producer === '') {
		throw new TokenRejected('telemetry scope names no producer');
	}
	if (!Array.isArray(destinations) || destinations.length === 0) {
		throw new TokenRejected('telemetry scope names no destination');
	}

	return {
		producer,
		clientId: typeof payload['client_id'] === 'string' ? payload['client_id'] : producer,
		scopes: readScopes(payload),
		destinations: destinations.filter((d): d is string => typeof d === 'string'),
		expiresAt: new Date((payload['exp'] as number) * 1000)
	};
}

/**
 * The index this batch may be written to, or `null`.
 *
 * `requested` is what the caller asked for, which may be nothing. When the token
 * grants exactly one destination for this signal, that one is used — which keeps
 * the ergonomics of a credential scoped to a single index. When it grants several
 * and the caller named none, the request is ambiguous and is refused rather than
 * resolved by picking: a producer whose batch silently landed in the wrong index
 * has corrupted the evidence somebody will later read.
 */
export function resolveDestination(
	token: VerifiedMachineToken,
	signal: TelemetrySignal,
	environment: string,
	requested: string | undefined
): string | null {
	const prefix = `${signal}:${environment}:`;
	const permitted = token.destinations
		.filter((destination) => destination.startsWith(prefix))
		.map((destination) => destination.slice(prefix.length));

	if (requested !== undefined && requested !== '') {
		return permitted.includes(requested) ? requested : null;
	}
	return permitted.length === 1 ? permitted[0]! : null;
}

/** Whether the token carries the scope this signal's ingestion requires. */
export function permitsSignal(token: VerifiedMachineToken, signal: TelemetrySignal): boolean {
	// Separate scopes per signal, deliberately: a producer that ships logs has no
	// business writing spans, and a compromised log shipper able to forge a trace
	// could make an intrusion look like ordinary traffic.
	return token.scopes.includes(`observability.${signal}.ingest`);
}

function readScopes(payload: JWTPayload): string[] {
	const scope = payload['scope'];
	if (typeof scope !== 'string' || scope.trim() === '') {
		return [];
	}
	return scope.trim().split(/\s+/);
}

/** See the note on the human verifier: a lookup key, never a grant of trust. */
function readIssuerClaim(token: string): string | undefined {
	const segments = token.split('.');
	if (segments.length !== 3) {
		return undefined;
	}
	try {
		const payload: unknown = JSON.parse(Buffer.from(segments[1]!, 'base64url').toString('utf8'));
		if (typeof payload === 'object' && payload !== null && 'iss' in payload) {
			const iss = (payload as { iss: unknown }).iss;
			return typeof iss === 'string' ? iss : undefined;
		}
		return undefined;
	} catch {
		return undefined;
	}
}
