# This is a fork

Upstream: [`rootprint/rootprint`](https://github.com/rootprint/rootprint), Apache-2.0.
Fork: `skyver-labs/rootprint`, the observability console for the Tunda Identity
Platform.

Decision record: `nexus/docs/adr/0036-the-observability-console-is-a-relying-party.md`.
Specification: `nexus/docs/architecture/observability-console-authentication-implementation-specification.md`.

---

## The one property this fork exists to establish

**No code path in this console can produce a session from anything other than a
live Tunda authentication.**

Upstream ships a complete second identity system — Better Auth, with email and
password, Google and GitHub social login, an admin plugin owning a binary
`admin | user` role, an API-key plugin owning machine identity, and its own
`user`, `session`, `account`, `verification` and `apikey` tables. Its session
signing secret is read from its own database at boot.

Configuring that to prefer Tunda would not have been enough. "Tunda is the
preferred login" is a configuration claim that survives exactly until somebody
re-enables a password provider to debug a lockout at 02:00. A _deleted_ password
provider is provable.

So the identity system is removed rather than disabled, and CI refuses to let it
back in.

---

## Why a fork rather than a contribution

Nothing here is a general improvement to a log-search product. It is the
replacement of one identity model with another organisation's, which is not a
change upstream should carry.

What _is_ generally useful — an authentication-provider seam, so the next
organisation does not have to fork — is worth offering upstream separately. It
would shrink this diff permanently. It is not a prerequisite for anything here.

---

## How the divergence is structured

The rule is: **delete an upstream file and add a Tunda one, rather than editing
upstream in place.**

A deleted file produces a clean conflict on the next upstream merge — one
somebody reads and resolves deliberately. An edited file produces a subtle one,
resolved by whoever is least aware of why the edit existed.

Everything new lives under `apps/api/src/tunda/`. Nothing upstream imports from
it; it is imported by the small number of files that had to be replaced.

---

## Divergence register

Every entry is a deliberate departure. A change here that is not in this table is
a change nobody decided.

### Removed

| Upstream path                                                                                                               | Replaced by                                                              | Why                                                                                       |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `apps/api/src/lib/auth.ts`                                                                                                  | `apps/api/src/tunda/oidc.ts`, `sessions.ts`                              | The Better Auth instance: password provider, Google, GitHub, admin plugin, api-key plugin |
| `apps/api/src/lib/auth-admin.ts`                                                                                            | —                                                                        | Better Auth's admin API. Users are administered in Tunda                                  |
| `apps/api/src/db/auth.schema.ts`                                                                                            | `apps/api/src/tunda/schema.ts`                                           | `user`, `session`, `account`, `verification`, `apikey`                                    |
| `apps/api/src/services/auth.service.ts`                                                                                     | —                                                                        | Passwords, invite tokens, Google domain and GitHub org allowlists                         |
| `apps/api/src/services/github.service.ts`                                                                                   | —                                                                        | GitHub org membership checks                                                              |
| `apps/api/src/services/api-key.service.ts`                                                                                  | —                                                                        | `rpk_` keys. Machine identity is a Tunda `client_credentials` registration                |
| `apps/api/src/services/service-account.service.ts`                                                                          | —                                                                        | Service accounts as `user` rows                                                           |
| `apps/api/src/lib/secret.ts`                                                                                                | —                                                                        | Read the session signing secret from the database at boot                                 |
| `apps/api/src/middleware/require-user.ts`                                                                                   | `apps/api/src/middleware/require-session.ts`                             | Better Auth session lookup                                                                |
| `apps/api/src/middleware/require-admin.ts`                                                                                  | `apps/api/src/middleware/authorize.ts`                                   | `session.user.role !== 'admin'`. Authorization is a PDP decision                          |
| `apps/api/src/middleware/require-api-key.ts`                                                                                | `apps/api/src/tunda/machine-token.ts` (Phase 2)                          | `rpk_` ingest keys                                                                        |
| `apps/api/src/middleware/require-user-or-personal-key.ts`                                                                   | `apps/api/src/middleware/require-session.ts`                             | Personal API keys                                                                         |
| `apps/api/src/routes/auth.ts` — `setup-admin`, `verify-invite`, `setup-password`, `providers`, and the Better Auth wildcard | `apps/api/src/routes/auth.ts` — `login`, `callback`, `logout`, `session` | Five authentication paths outside Tunda                                                   |
| `apps/api/src/routes/api-keys.ts`, `service-accounts.ts`                                                                    | —                                                                        | Console-issued credentials                                                                |
| `apps/web/src/lib/auth-client.ts`                                                                                           | —                                                                        | Better Auth browser SDK                                                                   |
| `apps/web/src/routes/auth/{sign-in,setup,setup-admin}`                                                                      | `apps/web/src/routes/auth/signed-out`                                    | Sign-in screens. Tunda renders its own                                                    |
| `apps/web/src/routes/(app)/settings/(admin)/authentication/**`                                                              | —                                                                        | Google and GitHub provider configuration                                                  |
| `apps/web/src/lib/components/admin/authentication/**`                                                                       | —                                                                        | ditto                                                                                     |
| `better-auth`, `@better-auth/api-key` in `package.json`                                                                     | —                                                                        | A removed screen with the library still installed is a removed screen                     |

### Added

| Path                                         | What                                                                                                                         |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `apps/api/src/tunda/issuers.ts`              | The closed set of trusted Tunda issuers, per-tenant config, JWKS cache                                                       |
| `apps/api/src/tunda/human-token.ts`          | ES256 verification: pinned algorithm, exact issuer, audience, bounded skew, required claims                                  |
| `apps/api/src/tunda/oidc.ts`                 | Auth transactions, PKCE, code exchange, serialized refresh                                                                   |
| `apps/api/src/tunda/sessions.ts`             | The opaque `__Host-` session, envelope-encrypted token custody                                                               |
| `apps/api/src/tunda/crypto.ts`               | SHA-256 for values only ever compared, AES-256-GCM envelope encryption for Tunda's tokens, one CSPRNG for every opaque value |
| `apps/api/src/tunda/csrf.ts`                 | Origin and token checks for cookie-authenticated writes                                                                      |
| `apps/api/src/tunda/schema.ts`               | `console_principal`, `console_session`, `console_auth_transaction`                                                           |
| `apps/api/src/middleware/require-session.ts` | Cookie → session → token freshness                                                                                           |
| `apps/api/src/middleware/authorize.ts`       | Phase 2: the PDP call                                                                                                        |

### Changed in place — and why each was unavoidable

| Path                    | Change                                                                                                           |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `apps/api/src/app.ts`   | Route table and boot sequence. Cannot be replaced wholesale without diverging from every upstream route addition |
| `apps/api/package.json` | Dependency removal                                                                                               |

---

## CI invariants

`.github/workflows/tunda-invariants.yml` fails the build if any of these becomes
untrue. They are the mechanism by which an upstream merge cannot quietly undo the
decision above.

1. `better-auth` or `@better-auth/*` appears in `package.json` or the lockfile.
2. A password-hashing library appears (`bcrypt`, `argon2`, `scrypt`).
3. `apps/api/src/db/auth.schema.ts` exists again.
4. Any of the deleted authentication routes reappears.
5. A migration creates `account`, `verification` or `apikey`.

---

## Merging from upstream

Track **tags**, not `main`. Upstream is pre-1.0 and warns of breaking changes
between releases.

```bash
git fetch upstream --tags
git merge v0.5.0          # the tag, never upstream/main
```

Then, in order:

```bash
bun install
bun run check && bun run lint && bun run format:check   # upstream's own checks, unmodified
bun --filter api test                                    # including the Tunda invariant tests
```

A fork that stops running upstream's checks has stopped being a fork.

Resolve conflicts by re-applying the register above: if a conflict is in a file
this document lists as _removed_, the resolution is to remove it again.
