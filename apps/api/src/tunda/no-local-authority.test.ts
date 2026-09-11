import { describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { is } from 'drizzle-orm';
import { getTableConfig, PgTable } from 'drizzle-orm/pg-core';

import * as schema from '../db/schema.js';
import { consolePrincipal, consoleSession } from './schema.js';

/**
 * The one property this fork exists to establish, asserted rather than described.
 *
 *   No code path in this console can produce a session from anything other than a
 *   live Tunda authentication.
 *
 * ## Why these are tests and not only CI greps
 *
 * `.github/workflows/tunda-invariants.yml` checks the same property from the
 * outside — manifests, filenames, migration text — which catches the blunt way it
 * gets undone: an upstream merge restoring a provider. What it cannot see is the
 * subtle way: a column quietly added to `console_principal` that something then
 * starts branching on.
 *
 * That is the failure worth a test. A `role` column here would not break a build
 * or trip a grep; it would work, and it would be a second answer to a question
 * Tunda already answers — stale from the moment somebody's access changed.
 */

const SRC = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/** Every `.ts` under `src/`, so a new file is covered without being registered anywhere. */
function sourceFiles(dir: string = SRC): string[] {
	return readdirSync(dir).flatMap((entry) => {
		const full = path.join(dir, entry);
		if (statSync(full).isDirectory()) return sourceFiles(full);
		return full.endsWith('.ts') ? [full] : [];
	});
}

describe('the console holds no identity authority', () => {
	test('no table this console owns could authenticate anybody', () => {
		// Better Auth's five, plus this console's own two. Named literally rather
		// than derived, so restoring one by any route — an import, an upstream merge,
		// a copy under a new file — fails here.
		const forbidden = [
			'user',
			'session',
			'account',
			'verification',
			'apikey',
			'api_key',
			'invite_token'
		];

		// Every table the schema module exports, whatever it is called — so a table
		// reintroduced under a new export name is still caught.
		const present = Object.values(schema)
			.filter((value) => is(value, PgTable))
			.map((table) => getTableConfig(table).name);

		expect(present).not.toBeEmpty();
		for (const name of forbidden) {
			expect(present).not.toContain(name);
		}
	});

	test('console_principal carries nothing that grants or proves anything', () => {
		// It is a cache of a Tunda subject. The moment it holds a role, a status or a
		// credential, something will read it instead of asking — and will be reading a
		// copy that nothing refreshes when access is revoked.
		const columns = getTableConfig(consolePrincipal).columns.map((c) => c.name);

		expect(columns.toSorted()).toEqual(
			[
				'id',
				'tunda_tenant_id',
				'tunda_user_id',
				'display_name',
				'first_seen_at',
				'last_seen_at'
			].toSorted()
		);
	});

	test('console_session keeps Tunda’s tokens sealed and its own handle hashed', () => {
		const columns = new Map(getTableConfig(consoleSession).columns.map((c) => [c.name, c]));

		// A handle that could be read out of a database dump and replayed would make
		// read access to this table equivalent to a session. Only the hash is stored.
		expect(columns.has('token')).toBe(false);
		expect(columns.get('token_hash')?.getSQLType()).toBe('bytea');

		// Tunda's tokens are bearer credentials for the whole platform, not just this
		// console. They are sealed, and the columns are named so that a plaintext one
		// would be visible in a diff.
		for (const sealed of ['access_token_enc', 'refresh_token_enc', 'id_token_enc']) {
			expect(columns.get(sealed)?.getSQLType()).toBe('bytea');
		}
		for (const plain of ['access_token', 'refresh_token', 'id_token']) {
			expect(columns.has(plain)).toBe(false);
		}
	});

	test('nothing imports a second identity library, and nothing hashes a password', () => {
		// This console verifies no credential, so it needs no hasher. One appearing
		// means something is storing a secret it could check — which is the whole of
		// what "a second identity authority" means.
		const offenders = sourceFiles()
			.filter((file) => !file.endsWith('no-local-authority.test.ts'))
			.filter((file) => {
				const body = readFileSync(file, 'utf8');
				return (
					/from ['"]better-auth/.test(body) ||
					/from ['"]@better-auth\//.test(body) ||
					/from ['"](bcrypt|argon2|scrypt)['"]/.test(body) ||
					/Bun\.password/.test(body)
				);
			})
			.map((file) => path.relative(SRC, file));

		expect(offenders).toEqual([]);
	});

	test('the authentication surface is four routes, none of which verifies a credential', () => {
		const body = readFileSync(path.join(SRC, 'routes', 'auth.ts'), 'utf8');
		const declared = [...body.matchAll(/\.(get|post)\('(\/[a-z-]*)'/g)].map((m) => m[2]);

		expect(declared.toSorted()).toEqual(['/callback', '/login', '/logout', '/session', '/step-up']);

		// Each of these was a way to obtain a session without Tunda: bootstrap the
		// first administrator, redeem an invite, set a password, list social
		// providers, or hand Better Auth the whole namespace on a wildcard.
		for (const gone of ['setup-admin', 'verify-invite', 'setup-password', 'providers', '/*']) {
			expect(body).not.toContain(`'/${gone.replace(/^\//, '')}'`);
		}
	});
});
