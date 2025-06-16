-- reverse: create index "idx_refresh_tokens_user_id" to table: "refresh_tokens"
DROP INDEX "public"."idx_refresh_tokens_user_id";
-- reverse: create index "idx_refresh_tokens_hash" to table: "refresh_tokens"
DROP INDEX "public"."idx_refresh_tokens_hash";
-- reverse: create "refresh_tokens" table
DROP TABLE "public"."refresh_tokens";
