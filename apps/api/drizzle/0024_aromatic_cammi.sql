-- Authorization stops being this console's decision.
--
-- Two things arrive together because they are two halves of one change.
--
-- `console_authorization` is how the PDP's `AUDIT` obligation is honoured.
-- `authorization.proto` says an obligation the caller does not enforce makes the
-- whole decision an authorization failure, so a permit carrying `AUDIT` is only
-- valid if a record was written — and a record written to stdout is one a log
-- rotation removes. Denials land here too, including the ones where the PDP never
-- answered: "nobody could search anything for four minutes" is a fact worth
-- having and is invisible if only permits are recorded.
--
-- `classification`, `environment` and `owning_service` on `index_settings` are
-- what the decision is made against. Nullable, with no default, and that is the
-- whole mechanism rather than an oversight: Tunda's policy schema marks the first
-- two required, absence never satisfies a condition there, and an index nobody
-- has classified therefore matches no rule and is unreadable.
--
-- A default would undo exactly that. `INTERNAL` would make a production payments
-- index readable because somebody created it and moved on; `RESTRICTED` would
-- look safe and would teach every operator that the first step with a new index
-- is to lower its classification, which is the habit that makes the column
-- meaningless. NULL is the honest third answer: nobody has said, so nobody may
-- read.
--
-- Existing indexes are therefore unreadable until somebody classifies them. That
-- is the migration doing its job — there is no value this file could choose on
-- their behalf that is not a guess about what is in them — and it is a two-field
-- edit per index at `PATCH /api/indexes/:indexId`.

CREATE TABLE "console_authorization" (
	"id" text PRIMARY KEY NOT NULL,
	"decided_at" timestamp with time zone DEFAULT now() NOT NULL,
	"principal_id" text,
	"tunda_tenant_id" text NOT NULL,
	"tunda_user_id" text NOT NULL,
	"action" text NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" text,
	"decision" text NOT NULL,
	"reason_code" text NOT NULL,
	"decision_id" text,
	"acr" text NOT NULL,
	"trace_id" text
);
--> statement-breakpoint
ALTER TABLE "index_settings" ADD COLUMN "classification" text;--> statement-breakpoint
ALTER TABLE "index_settings" ADD COLUMN "environment" text;--> statement-breakpoint
ALTER TABLE "index_settings" ADD COLUMN "owning_service" text;--> statement-breakpoint
CREATE INDEX "console_authorization_decided_at" ON "console_authorization" USING btree ("decided_at");--> statement-breakpoint
CREATE INDEX "console_authorization_subject_decided" ON "console_authorization" USING btree ("tunda_user_id","decided_at");--> statement-breakpoint
CREATE INDEX "console_authorization_decision_id" ON "console_authorization" USING btree ("decision_id");