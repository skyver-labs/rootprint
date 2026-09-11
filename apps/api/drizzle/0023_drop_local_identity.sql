-- Every table that could produce a session, or a credential, without Tunda.
--
-- `user`, `session`, `account`, `verification` and `apikey` are Better Auth's:
-- passwords, social links, verification tokens and API keys. `api_key` and
-- `invite_token` are this console's own — an `rpk_` ingest key stored in
-- plaintext, and an invite redeemable into an account.
--
-- Dropped rather than emptied. An empty table with a login route four lines away
-- is not a removed login route; a dropped one makes the route fail to start.
--
-- `CASCADE` is the generated default and is accurate here: 0022 already moved the
-- foreign keys that pointed at `user`, so what cascades is Better Auth's own
-- internal references.
DROP TABLE "api_key" CASCADE;--> statement-breakpoint
DROP TABLE "invite_token" CASCADE;--> statement-breakpoint
DROP TABLE "account" CASCADE;--> statement-breakpoint
DROP TABLE "apikey" CASCADE;--> statement-breakpoint
DROP TABLE "session" CASCADE;--> statement-breakpoint
DROP TABLE "user" CASCADE;--> statement-breakpoint
DROP TABLE "verification" CASCADE;--> statement-breakpoint
-- The credentials that lived in app_settings.
--
-- `better_auth_secret` signed this console's own sessions — it is the reason the
-- console was an issuer at all. The Google and GitHub rows are live OAuth client
-- secrets for providers that no longer exist here, and a secret nothing reads is
-- still a secret somebody can read.
DELETE FROM "app_settings"
 WHERE "key" IN (
   'better_auth_secret',
   'google_client_id', 'google_client_secret', 'google_allowed_domains',
   'github_client_id', 'github_client_secret', 'github_allowed_orgs'
 );
