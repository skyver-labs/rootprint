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

| Upstream path                                                                                                               | Replaced by                                                              | Why                                                                                             |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `apps/api/src/lib/auth.ts`                                                                                                  | `apps/api/src/tunda/oidc.ts`, `sessions.ts`                              | The Better Auth instance: password provider, Google, GitHub, admin plugin, api-key plugin       |
| `apps/api/src/lib/auth-admin.ts`                                                                                            | —                                                                        | Better Auth's admin API. Users are administered in Tunda                                        |
| `apps/api/src/db/auth.schema.ts`                                                                                            | `apps/api/src/tunda/schema.ts`                                           | `user`, `session`, `account`, `verification`, `apikey`                                          |
| `apps/api/src/services/auth.service.ts`                                                                                     | —                                                                        | Passwords, invite tokens, Google domain and GitHub org allowlists                               |
| `apps/api/src/services/github.service.ts`                                                                                   | —                                                                        | GitHub org membership checks                                                                    |
| `apps/api/src/services/api-key.service.ts`                                                                                  | —                                                                        | `rpk_` keys. Machine identity is a Tunda `client_credentials` registration                      |
| `apps/api/src/services/service-account.service.ts`                                                                          | —                                                                        | Service accounts as `user` rows                                                                 |
| `apps/api/src/lib/secret.ts`                                                                                                | —                                                                        | Read the session signing secret from the database at boot                                       |
| `apps/api/src/middleware/require-user.ts`                                                                                   | `apps/api/src/middleware/require-session.ts`                             | Better Auth session lookup                                                                      |
| `apps/api/src/middleware/require-admin.ts`                                                                                  | `apps/api/src/middleware/authorize.ts`                                   | `session.user.role !== 'admin'`. Authorization is a PDP decision                                |
| `apps/api/src/middleware/require-api-key.ts`                                                                                | `apps/api/src/middleware/require-machine.ts`                             | `rpk_` ingest keys                                                                              |
| `apps/api/src/middleware/require-user-or-personal-key.ts`                                                                   | `apps/api/src/middleware/require-session.ts`                             | Personal API keys                                                                               |
| `apps/api/src/routes/auth.ts` — `setup-admin`, `verify-invite`, `setup-password`, `providers`, and the Better Auth wildcard | `apps/api/src/routes/auth.ts` — `login`, `callback`, `logout`, `session` | Five authentication paths outside Tunda                                                         |
| `apps/api/src/routes/api-keys.ts`, `service-accounts.ts`                                                                    | —                                                                        | Console-issued credentials                                                                      |
| `apps/web/src/lib/auth-client.ts`                                                                                           | —                                                                        | Better Auth browser SDK                                                                         |
| `apps/web/src/routes/auth/{sign-in,setup,setup-admin}`                                                                      | `apps/web/src/routes/auth/signed-out`                                    | Sign-in screens. Tunda renders its own                                                          |
| `apps/web/src/routes/(app)/settings/(admin)/authentication/**`                                                              | —                                                                        | Google and GitHub provider configuration                                                        |
| `apps/web/src/lib/components/admin/authentication/**`                                                                       | —                                                                        | ditto                                                                                           |
| `apps/api/src/routes/settings.ts`, `services/settings.service.ts`                                                           | —                                                                        | Google and GitHub OAuth provider configuration. The whole router was this                       |
| `apps/api/src/schemas/{users,service-accounts,settings,auth,api-keys}.ts` and their `responses/`                            | —                                                                        | The API shapes of a second identity system                                                      |
| `api_key`, `invite_token` tables (`db/schema.ts`)                                                                           | —                                                                        | This console's own credentials: a plaintext `rpk_` key, and an invite redeemable for an account |
| `apps/web/src/lib/api/users.ts`, `lib/components/{account,admin/users,admin/service-accounts}/**`                           | —                                                                        | Password change, personal API keys, user and service-account administration                     |
| `apps/web/src/routes/(app)/settings/profile/**`                                                                             | —                                                                        | Account management for an account this console does not own                                     |
| `personalBearer` in the OpenAPI security schemes                                                                            | —                                                                        | A published contract advertising a read-capable bearer this console no longer accepts           |
| `better-auth`, `@better-auth/api-key` in `package.json`                                                                     | —                                                                        | A removed screen with the library still installed is a removed screen                           |

### Added

| Path                                            | What                                                                                                                         |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `apps/api/src/tunda/issuers.ts`                 | The closed set of trusted Tunda issuers, per-tenant config, JWKS cache                                                       |
| `apps/api/src/tunda/human-token.ts`             | ES256 verification: pinned algorithm, exact issuer, audience, bounded skew, required claims                                  |
| `apps/api/src/tunda/oidc.ts`                    | Auth transactions, PKCE, code exchange, serialized refresh                                                                   |
| `apps/api/src/tunda/sessions.ts`                | The opaque `__Host-` session, envelope-encrypted token custody                                                               |
| `apps/api/src/tunda/crypto.ts`                  | SHA-256 for values only ever compared, AES-256-GCM envelope encryption for Tunda's tokens, one CSPRNG for every opaque value |
| `apps/api/src/tunda/csrf.ts`                    | Origin and token checks for cookie-authenticated writes                                                                      |
| `apps/api/src/tunda/schema.ts`                  | `console_principal`, `console_session`, `console_auth_transaction`                                                           |
| `apps/api/src/middleware/require-session.ts`    | Cookie → session → token freshness                                                                                           |
| `apps/api/src/tunda/machine-token.ts`           | A producer's `client_credentials` token: signed destinations, per-signal scopes, no session                                  |
| `apps/api/src/tunda/no-local-authority.test.ts` | The central property, asserted: table shapes, sealed columns, the size of the authentication surface                         |
| `apps/api/src/middleware/require-machine.ts`    | Bearer → verified producer, on the ingest paths only                                                                         |
| `apps/api/src/middleware/authorize.ts`          | Phase 1: authenticated is authorized, stated as such. Phase 2: the PDP call                                                  |
| `apps/api/src/routes/ingest/destination.ts`     | The header a producer picks among the destinations its token already grants                                                  |
| `apps/api/src/drizzle/0022`, `0023`             | `console_*` created and every local identity table dropped, including the secrets in `app_settings`                          |
| `apps/web/src/lib/api/session.ts`               | What the browser knows about who is signed in — for rendering, and for nothing else                                          |
| `apps/web/src/routes/auth/signed-out/`          | The one page left under `/auth`                                                                                              |
| `.github/workflows/tunda-publish.yml`           | The fork's GHCR image, gated on the invariants so a failing check publishes nothing                                          |
| `.github/workflows/tunda-upstream-sync.yml`     | Opens a PR per upstream release, resolving what this register calls mechanical and naming what is not                        |

### Changed in place — and why each was unavoidable

| Path                                                    | Change                                                                                                               |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Path                                                    | Change                                                                                                               |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `apps/api/src/app.ts`                                   | Route table and boot sequence. Cannot be replaced wholesale without diverging from every upstream route addition     |
| `apps/api/package.json`                                 | Dependency removal                                                                                                   |
| `apps/api/src/config.ts`                                | `environment`, which a producer token's destinations are scoped to                                                   |
| `apps/api/src/db/schema.ts`                             | Ownership foreign keys repointed from `user.id` to `console_principal.id`                                            |
| `apps/api/src/routes/ingest/{ndjson,otlp}.ts`           | The destination comes from the signed token rather than from a key row                                               |
| `apps/api/src/services/search-audit.service.ts`         | The actor is a Tunda principal; the `token` arm is read-only history                                                 |
| `apps/api/src/services/search-activity.service.ts`      | Actor labels come from `console_principal.display_name`, not from an email                                           |
| `apps/api/src/lib/openapi/spec.ts`                      | One bearer scheme, for producers. The cookie is `__Host-rp_session`                                                  |
| `apps/web/src/routes/+layout.ts`                        | Session lookup and the sign-in redirect. There is no first-admin bootstrap to ask about                              |
| `apps/web/src/lib/settings-nav.ts`                      | Five destinations removed; `adminOnly` removed with the role it read                                                 |
| `apps/web/.../send-telemetry/**`                        | The wizard shows a placeholder token and explains where a real one comes from                                        |
| `README.md`                                             | The banner, and the two sections that told people to create an admin account and mint an ingest key                  |
| `docker-compose.yml`, `.env.example`                    | The Tunda variables, all required; the Better Auth ones removed                                                      |
| `apps/api/src/app.ts` — boot order                      | Configuration is validated before the database, so a missing variable names itself                                   |
| `.github/workflows/tunda-invariants.yml`                | Also `workflow_call`, so the publish workflow can gate on it                                                         |

---

## CI invariants

`.github/workflows/tunda-invariants.yml` fails the build if any of these becomes
untrue. They are the mechanism by which an upstream merge cannot quietly undo the
decision above.

1. `better-auth` or `@better-auth/*` appears in `package.json` or the lockfile.
2. A source file under `apps/*/src` imports it. The manifest check is not enough
   on its own: `utils/http-error.ts` kept importing `better-auth/api` for a full
   workstream after the dependency left the lockfile, resolving from a stale
   package store, and the typecheck passed the whole time.
3. A password-hashing library appears (`bcrypt`, `argon2`, `scrypt`, `Bun.password`).
4. `apps/api/src/db/auth.schema.ts` exists again.
5. Any of the deleted authentication routes reappears.
6. A migration creates `account`, `verification` or `apikey`.
7. `bun --filter api test` fails — see below.
8. A file under `src/tunda/` is not named in the register above.

`apps/api/src/tunda/no-local-authority.test.ts` asserts from the inside what those
greps assert from the outside, and catches the quieter failure: not a provider
restored, but a column added. It pins the exact column list of
`console_principal`, that `console_session` stores a hash and three sealed
tokens and no plaintext, and that `/api/auth` has five routes and no wildcard.

---

## What Phase 1 does not do

**Authorization is binary.** `middleware/authorize.ts` grants every authenticated
principal, and says so at length in its own header. That replaced
`session.user.role !== 'admin'` — a comparison against a column this console
owned — and it is a smaller surface than upstream's only because there is now no
way to become an operator without Tunda.

It is still not fine-grained, and a production release does not ship with it.
Phase 2 replaces the body with a `Check` against
`tunda.internal.v1.AuthorizationService`, carrying the subject, action, resource
and assurance from the verified token and no roles at all. The signature already
takes the action and the resource so that the change lands in one function rather
than at every call site.

**The migration is one-way.** `0022` deletes saved views, shares and display
preferences whose owner was a local account, because a Better Auth `user` is not a
Tunda subject and cannot be turned into one. It destroys nothing that identifies
a person and nothing that grants access. `0023` also deletes the Better Auth
signing secret and the Google and GitHub client secrets from `app_settings`: a
secret nothing reads is still a secret somebody can read.

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

**`.github/workflows/tunda-upstream-sync.yml` does the mechanical half.** Weekly,
it finds the newest unmerged upstream tag, attempts the merge, and applies exactly
that rule — anything conflicting in the Removed table is removed again. What it
cannot resolve it leaves in the tree with the markers in place and labels the pull
request `needs-human`, because a conflict outside the register means upstream has
changed something this fork genuinely builds on, and that is a judgement rather
than a procedure.

It opens a PR either way. A workflow that found a hard merge and quietly did
nothing is how a fork ends up six releases behind without anybody deciding to.
