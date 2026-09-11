import type { ConsoleSession } from './tunda/sessions.js';
import type { VerifiedMachineToken } from './tunda/machine-token.js';

/**
 * What a request carries once authentication has run.
 *
 * ## Why `session.user.id` survived the identity replacement
 *
 * It is now a `console_principal` id rather than a Better Auth `user` id, and the
 * shape is deliberately unchanged: every handler that records who saved a view or
 * created a share keeps working, and the diff against upstream stays confined to
 * authentication rather than spreading into every route.
 *
 * What is gone is `role`. There is no local role to read — authorization is a
 * decision Tunda makes against current state, and a field here that a handler
 * could branch on would be a second answer to the same question.
 */

/** The console's own identity for a Tunda subject. Ownership of saved views, shares, preferences. */
export type RequestSession = { user: { id: string } };

export type AppEnv = {
	Variables: {
		requestId: string;

		/** Present once `requireSession` has run. */
		session?: RequestSession;

		/**
		 * The verified Tunda session, for a handler that needs the access token or the
		 * assurance behind it — a PDP call, a step-up decision.
		 */
		tunda?: ConsoleSession;

		/** Present once `requireMachine` has run, on the telemetry ingest paths only. */
		machine?: VerifiedMachineToken;
	};
};

export type AuthedEnv = {
	Variables: AppEnv['Variables'] & { session: RequestSession; tunda: ConsoleSession };
};

export type MachineEnv = {
	Variables: AppEnv['Variables'] & { machine: VerifiedMachineToken };
};
