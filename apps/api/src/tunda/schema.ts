import { relations } from 'drizzle-orm';
import { boolean, customType, index, pgTable, text, timestamp } from 'drizzle-orm/pg-core';

/**
 * `bytea`, which Drizzle does not ship a column type for.
 *
 * Used for every hash and every ciphertext here. Storing those as text would mean
 * choosing an encoding, and the first person to pick a different one on a read
 * path than on a write path produces a session that silently never matches.
 */
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
	dataType() {
		return 'bytea';
	}
});

/**
 * The console's identity tables.
 *
 * ## What is deliberately absent, and why it must stay absent
 *
 * No `password`. No `role`. No `status`, `banned`, or `email_verified`. No API
 * key.
 *
 * Every one of those is an authority — a column this console could read to decide
 * that somebody may do something. Tunda decides that, per request, against
 * current state. A column here that authorization consulted would be a second
 * answer to the same question, and the first time the two disagreed this console
 * would be the one that was wrong, on the surface that reads production logs.
 *
 * `NoLocalAuthority` in the test suite asserts this as a schema property rather
 * than a convention, because a convention is what a well-meant pull request adds
 * `isAdmin` to.
 */

/**
 * A Tunda subject this console has seen.
 *
 * A cache and a foreign-key target, never an authority. A row appears on first
 * successful sign-in; there is no invitation, no provisioning, and no screen that
 * creates one. Onboarding an operator is `POST /t/{tenantId}/admin/v1/users` in
 * Tunda and nothing else.
 */
export const consolePrincipal = pgTable(
	'console_principal',
	{
		id: text('id').primaryKey(),

		/**
		 * The canonical identity: issuer-scoped tenant plus subject.
		 *
		 * Not email. An address is a routing detail that people change, and using it
		 * as the join key means a person who changes theirs becomes a different
		 * principal — silently inheriting nothing, or worse, inheriting somebody
		 * else's history.
		 */
		tundaTenantId: text('tunda_tenant_id').notNull(),
		tundaUserId: text('tunda_user_id').notNull(),

		/**
		 * Rendering metadata, written from whatever the last sign-in carried.
		 *
		 * It grants nothing. A stale one is a cosmetic defect, which is the only kind
		 * of defect a column in this table is allowed to cause.
		 */
		displayName: text('display_name'),

		firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).defaultNow().notNull(),
		lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).defaultNow().notNull()
	},
	(table) => [index('console_principal_identity_idx').on(table.tundaTenantId, table.tundaUserId)]
);

/**
 * A browser session derived from a Tunda authentication.
 *
 * The browser holds an opaque value; this row holds everything else. Tunda's own
 * tokens live here encrypted and never reach JavaScript — a log console renders
 * attacker-influenced content by definition, so a token the page could read is a
 * token one rendering defect away from exfiltration.
 */
export const consoleSession = pgTable(
	'console_session',
	{
		id: text('id').primaryKey(),

		/**
		 * SHA-256 of the cookie value, never the value.
		 *
		 * A database dump must not be a set of live sessions.
		 */
		tokenHash: bytea('token_hash').notNull().unique(),

		principalId: text('principal_id')
			.notNull()
			.references(() => consolePrincipal.id, { onDelete: 'cascade' }),

		tundaTenantId: text('tunda_tenant_id').notNull(),

		/** Tunda's own session id, so a revocation event can name this row. */
		tundaSid: text('tunda_sid').notNull(),

		/**
		 * What was proven, and when — copied from the verified token.
		 *
		 * Held for rendering and for the step-up flow. Never read as the authority on
		 * assurance: every PDP call takes these from the token it just verified, not
		 * from here, because a row is a snapshot and a token is evidence.
		 */
		acr: text('acr').notNull(),
		amr: text('amr').array().notNull(),
		authTime: timestamp('auth_time', { withTimezone: true }).notNull(),

		accessTokenEnc: bytea('access_token_enc').notNull(),
		accessExpiresAt: timestamp('access_expires_at', { withTimezone: true }).notNull(),
		refreshTokenEnc: bytea('refresh_token_enc'),
		idTokenEnc: bytea('id_token_enc'),

		createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
		lastUsedAt: timestamp('last_used_at', { withTimezone: true }).defaultNow().notNull(),

		/** Never extended. An idle timeout that can be refreshed forever is not a bound. */
		absoluteExpiresAt: timestamp('absolute_expires_at', { withTimezone: true }).notNull(),

		endedAt: timestamp('ended_at', { withTimezone: true }),

		/**
		 * Why it ended.
		 *
		 * Recorded because "why was I signed out" is the first question of every
		 * support ticket, and a null column turns it into an investigation.
		 */
		endedReason: text('ended_reason')
	},
	(table) => [
		index('console_session_principal_idx').on(table.principalId),
		index('console_session_tunda_sid_idx').on(table.tundaSid)
	]
);

/**
 * One in-flight authorization-code flow.
 *
 * Server-side because the browser must not hold the authoritative record of what
 * a flow has established. Signing a cookie stops forgery, not replay — a cookie
 * captured mid-flow replays as mid-flow forever.
 */
export const consoleAuthTransaction = pgTable('console_auth_transaction', {
	id: text('id').primaryKey(),

	/** SHA-256 of the transaction cookie value. */
	tokenHash: bytea('token_hash').notNull().unique(),

	tundaTenantId: text('tunda_tenant_id').notNull(),

	/** SHA-256 of `state` and `nonce`. Compared, never rendered. */
	stateHash: bytea('state_hash').notNull(),
	nonceHash: bytea('nonce_hash').notNull(),

	pkceVerifierEnc: bytea('pkce_verifier_enc').notNull(),

	/** Where to return afterwards. Validated as a local path before it is stored. */
	nextPath: text('next_path').notNull(),

	/** Whether this flow is a step-up on an existing session rather than a new sign-in. */
	stepUp: boolean('step_up').default(false).notNull(),

	createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
	expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),

	/** Set on redemption. A transaction is single-use. */
	usedAt: timestamp('used_at', { withTimezone: true })
});

export const consolePrincipalRelations = relations(consolePrincipal, ({ many }) => ({
	sessions: many(consoleSession)
}));

export const consoleSessionRelations = relations(consoleSession, ({ one }) => ({
	principal: one(consolePrincipal, {
		fields: [consoleSession.principalId],
		references: [consolePrincipal.id]
	})
}));
