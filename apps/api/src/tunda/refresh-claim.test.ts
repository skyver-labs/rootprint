import { describe, expect, test } from 'bun:test';

// Every import of application code in this file is dynamic and inside a test.
//
// A module-scope `import … from './sessions.js'` defeats the guard below: the
// import chain reaches the configuration module, which refuses to load without
// DATABASE_URL, and it does that while the file is being evaluated — before
// `describe.skip` has had a chance to skip anything. CI proved it, by failing on
// a suite that was supposed to be skipped.

/**
 * Exactly one request per session may refresh it.
 *
 * ## Why this is worth a test against a real database
 *
 * Because the property is a property of the SQL, not of the TypeScript. The
 * function is three lines and every one of them is a clause in a conditional
 * `UPDATE`; a test with a fake database would assert that the code calls the
 * query it calls.
 *
 * What matters is that two callers racing for the same row produce one winner.
 * Tunda rotates refresh tokens and revokes the whole family when a consumed one
 * is presented again — correctly, since it cannot tell the legitimate client from
 * the thief — so two concurrent refreshes of one session sign the user out. That
 * was documented in the code as a narrow window worth accepting, and it is not
 * narrow: the access token lives five minutes, the refresh fires at T−60s, and a
 * browser loading a page issues several requests at once.
 *
 * Skipped without a database rather than mocked, because a green run against a
 * mock here would be worse than no run at all.
 *
 * Needs `ORIGIN` as well as `DATABASE_URL`: importing the database module pulls in
 * the application's configuration, which refuses to load half-configured — on
 * purpose, so a misconfigured deployment names the missing variable instead of
 * failing at the first request. Both are present wherever the console itself runs.
 *
 *     docker compose exec console bun test src/tunda/refresh-claim.test.ts
 */

const CONFIGURED = process.env['DATABASE_URL'] && process.env['ORIGIN'];

const describeWithDatabase = CONFIGURED ? describe : describe.skip;

describeWithDatabase('the refresh claim', () => {
	async function withSession(run: (sessionId: string) => Promise<void>): Promise<void> {
		const { db } = await import('../lib/db.js');
		const { consolePrincipal, consoleSession } = await import('./schema.js');
		const { randomToken, digest } = await import('./crypto.js');
		const { eq } = await import('drizzle-orm');

		const principalId = randomToken();
		const sessionId = randomToken();

		await db.insert(consolePrincipal).values({
			id: principalId,
			tundaTenantId: 'tnt_test',
			tundaUserId: `usr_${principalId.slice(0, 12)}`,
			firstSeenAt: new Date(),
			lastSeenAt: new Date()
		});

		await db.insert(consoleSession).values({
			id: sessionId,
			tokenHash: await digest(randomToken()),
			principalId,
			tundaTenantId: 'tnt_test',
			tundaSid: 'ses_test',
			acr: 'urn:tunda:aal:2',
			amr: ['pwd', 'otp'],
			authTime: new Date(),
			accessTokenEnc: Buffer.from('x'),
			accessExpiresAt: new Date(Date.now() + 300_000),
			absoluteExpiresAt: new Date(Date.now() + 3_600_000)
		});

		try {
			await run(sessionId);
		} finally {
			await db.delete(consoleSession).where(eq(consoleSession.id, sessionId));
			await db.delete(consolePrincipal).where(eq(consolePrincipal.id, principalId));
		}
	}

	test('is granted to exactly one of several simultaneous requests', async () => {
		// The case that used to end sessions. Eight concurrent claims, one winner —
		// asserted against the database because that is where the exclusion lives.
		const { claimRefresh } = await import('./sessions.js');

		await withSession(async (sessionId) => {
			const claims = await Promise.all(Array.from({ length: 8 }, () => claimRefresh(sessionId)));

			expect(claims.filter(Boolean)).toHaveLength(1);
		});
	});

	test('is available again once the winner releases it', async () => {
		const { claimRefresh, releaseRefreshClaim } = await import('./sessions.js');

		await withSession(async (sessionId) => {
			expect(await claimRefresh(sessionId)).toBe(true);
			expect(await claimRefresh(sessionId)).toBe(false);

			await releaseRefreshClaim(sessionId);

			expect(await claimRefresh(sessionId)).toBe(true);
		});
	});

	test('is taken from a holder that never released it, so a dead process cannot block forever', async () => {
		// A process that dies mid-refresh holds the claim. Without expiry this
		// session could never refresh again — a worse failure than the reuse the
		// claim prevents, because it is permanent.
		const { claimRefresh } = await import('./sessions.js');

		await withSession(async (sessionId) => {
			const { db } = await import('../lib/db.js');
			const { consoleSession } = await import('./schema.js');
			const { eq } = await import('drizzle-orm');

			await db
				.update(consoleSession)
				.set({ refreshingAt: new Date(Date.now() - 120_000) })
				.where(eq(consoleSession.id, sessionId));

			expect(await claimRefresh(sessionId)).toBe(true);
		});
	});

	test('is refused on a session that has ended', async () => {
		const { claimRefresh } = await import('./sessions.js');

		await withSession(async (sessionId) => {
			const { db } = await import('../lib/db.js');
			const { consoleSession } = await import('./schema.js');
			const { eq } = await import('drizzle-orm');

			await db
				.update(consoleSession)
				.set({ endedAt: new Date(), endedReason: 'LOGOUT' })
				.where(eq(consoleSession.id, sessionId));

			expect(await claimRefresh(sessionId)).toBe(false);
		});
	});
});
