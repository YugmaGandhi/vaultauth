ALTER TYPE "public"."audit_event_type" ADD VALUE 'mfa_enrolled';--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'mfa_disabled';--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'mfa_verified';--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'mfa_recovery_used';--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'mfa_recovery_regenerated';--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'org_mfa_enforced';--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'org_mfa_unenforced';--> statement-breakpoint
CREATE TABLE "mfa_recovery_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"code_hash" varchar(255) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "mfa_settings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"encrypted_secret" varchar(255) NOT NULL,
	"is_enabled" boolean DEFAULT false NOT NULL,
	"enabled_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "mfa_settings_user_id_unique" UNIQUE("user_id")
);
--> statement-breakpoint
CREATE TABLE "org_mfa_policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"require_mfa" boolean DEFAULT false NOT NULL,
	"enforced_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "org_mfa_policies_org_id_unique" UNIQUE("org_id")
);
--> statement-breakpoint
ALTER TABLE "mfa_recovery_codes" ADD CONSTRAINT "mfa_recovery_codes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mfa_settings" ADD CONSTRAINT "mfa_settings_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_mfa_policies" ADD CONSTRAINT "org_mfa_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "mfa_recovery_codes_user_id_idx" ON "mfa_recovery_codes" USING btree ("user_id");