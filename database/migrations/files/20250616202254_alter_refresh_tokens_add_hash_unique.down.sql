-- reverse: create index "idx_refresh_tokens_hash" to table: "refresh_tokens"
DROP INDEX "public"."idx_refresh_tokens_hash";
-- reverse: drop index "idx_refresh_tokens_hash" from table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_hash" ON "public"."refresh_tokens" ("hash");
