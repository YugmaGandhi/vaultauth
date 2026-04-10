CREATE TYPE "public"."deletion_status" AS ENUM('pending', 'cancelled', 'completed');--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'account_deletion_requested';--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'account_deletion_cancelled';--> statement-breakpoint
ALTER TYPE "public"."audit_event_type" ADD VALUE 'account_deleted';--> statement-breakpoint
CREATE TABLE "deletion_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid,
	"requested_at" timestamp with time zone DEFAULT now() NOT NULL,
	"scheduled_purge_at" timestamp with time zone NOT NULL,
	"status" "deletion_status" DEFAULT 'pending' NOT NULL,
	"cancelled_at" timestamp with time zone,
	"forced_by_admin" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
ALTER TABLE "deletion_requests" ADD CONSTRAINT "deletion_requests_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;