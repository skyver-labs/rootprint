-- The console's identity becomes a cache of a Tunda subject.
--
-- `console_principal` is what a `user` row is not: it holds no credential, no
-- role, no status and no ban flag. Nothing in it grants anything — it exists so
-- that "who saved this view" survives a person changing their email address, and
-- so that ownership has a foreign key to point at.
--
-- `console_session` holds Tunda's tokens under envelope encryption and is keyed
-- by a hash of a value only ever compared. `console_auth_transaction` is one
-- in-flight authorization-code flow, spent before the code is exchanged.

CREATE TABLE "console_auth_transaction" (
	"id" text PRIMARY KEY NOT NULL,
	"token_hash" "bytea" NOT NULL,
	"tunda_tenant_id" text NOT NULL,
	"state_hash" "bytea" NOT NULL,
	"nonce_hash" "bytea" NOT NULL,
	"pkce_verifier_enc" "bytea" NOT NULL,
	"next_path" text NOT NULL,
	"step_up" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	CONSTRAINT "console_auth_transaction_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "console_principal" (
	"id" text PRIMARY KEY NOT NULL,
	"tunda_tenant_id" text NOT NULL,
	"tunda_user_id" text NOT NULL,
	"display_name" text,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "console_session" (
	"id" text PRIMARY KEY NOT NULL,
	"token_hash" "bytea" NOT NULL,
	"principal_id" text NOT NULL,
	"tunda_tenant_id" text NOT NULL,
	"tunda_sid" text NOT NULL,
	"acr" text NOT NULL,
	"amr" text[] NOT NULL,
	"auth_time" timestamp with time zone NOT NULL,
	"access_token_enc" "bytea" NOT NULL,
	"access_expires_at" timestamp with time zone NOT NULL,
	"refresh_token_enc" "bytea",
	"id_token_enc" "bytea",
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone DEFAULT now() NOT NULL,
	"absolute_expires_at" timestamp with time zone NOT NULL,
	"ended_at" timestamp with time zone,
	"ended_reason" text,
	CONSTRAINT "console_session_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
ALTER TABLE "share" DROP CONSTRAINT "share_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "user_preference" DROP CONSTRAINT "user_preference_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "view" DROP CONSTRAINT "view_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "console_session" ADD CONSTRAINT "console_session_principal_id_console_principal_id_fk" FOREIGN KEY ("principal_id") REFERENCES "public"."console_principal"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "console_principal_identity_idx" ON "console_principal" USING btree ("tunda_tenant_id","tunda_user_id");--> statement-breakpoint
CREATE INDEX "console_session_principal_idx" ON "console_session" USING btree ("principal_id");--> statement-breakpoint
CREATE INDEX "console_session_tunda_sid_idx" ON "console_session" USING btree ("tunda_sid");--> statement-breakpoint
-- Ownership rows whose owner cannot be identified.
--
-- A Better Auth `user` is not a Tunda subject and cannot be turned into one:
-- there is no issuer, no tenant and no `sub` to map from, and inventing a
-- principal for each would attach somebody's saved views to an identity nobody
-- can authenticate as. So rows owned by a user that has no principal are deleted
-- before the new foreign keys are added, rather than the migration failing and
-- leaving the console unable to start.
--
-- This is one-way and it destroys saved views, shares and display preferences.
-- It destroys nothing that identifies a person, and nothing that grants access.
-- On a console that has never run against Tunda — the expected case — it deletes
-- everything these three tables hold.
DO $$
DECLARE
	removed_views    bigint;
	removed_shares   bigint;
	removed_prefs    bigint;
BEGIN
	DELETE FROM "view" v
	 WHERE NOT EXISTS (SELECT 1 FROM "console_principal" p WHERE p."id" = v."user_id");
	GET DIAGNOSTICS removed_views = ROW_COUNT;

	DELETE FROM "share" s
	 WHERE NOT EXISTS (SELECT 1 FROM "console_principal" p WHERE p."id" = s."user_id");
	GET DIAGNOSTICS removed_shares = ROW_COUNT;

	DELETE FROM "user_preference" up
	 WHERE NOT EXISTS (SELECT 1 FROM "console_principal" p WHERE p."id" = up."user_id");
	GET DIAGNOSTICS removed_prefs = ROW_COUNT;

	IF removed_views + removed_shares + removed_prefs > 0 THEN
		RAISE NOTICE
			'Tunda migration: removed % saved view(s), % share(s) and % preference row(s) whose owner was a local account.',
			removed_views, removed_shares, removed_prefs;
	END IF;
END $$;
--> statement-breakpoint
ALTER TABLE "share" ADD CONSTRAINT "share_user_id_console_principal_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."console_principal"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_preference" ADD CONSTRAINT "user_preference_user_id_console_principal_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."console_principal"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "view" ADD CONSTRAINT "view_user_id_console_principal_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."console_principal"("id") ON DELETE cascade ON UPDATE no action;