-- create "refresh_tokens" table
CREATE TABLE "public"."refresh_tokens" (
  "id" uuid NOT NULL,
  "user_id" uuid NOT NULL,
  "hash" text NOT NULL,
  "created_at" bigint NOT NULL DEFAULT EXTRACT(epoch FROM now()),
  "expires_at" bigint NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_refresh_tokens_user_id" FOREIGN KEY ("user_id") REFERENCES "public"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- create index "idx_refresh_tokens_hash" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_hash" ON "public"."refresh_tokens" ("hash");
-- create index "idx_refresh_tokens_user_id" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_user_id" ON "public"."refresh_tokens" ("user_id");
