schema "public" {}

table "users" {
  schema = schema.public

  column "id" {
    type = uuid
    null = false
  }

  column "name" {
    type = text
    null = false
  }

  column "email" {
    type = text
    null = false
  }

  column "password" {
    type = text
    null = false
  }

  column "admin" {
    type    = bool
    default = false
  }

  column "created_at" {
    type    = bigint
    null    = false
    default = "EXTRACT(epoch FROM NOW())"
  }

  column "updated_at" {
    type    = bigint
    null    = false
    default = "EXTRACT(epoch FROM NOW())"
  }

  column "deleted_at" {
    type = bigint
    null = true
  }

  primary_key {
    columns = [column.id]
  }

  index "idx_users_email" {
    columns = [column.email]
    unique  = true
  }
}

table "refresh_tokens" {
  schema = schema.public

  column "id" {
    type = uuid
    null = false
  }

  column "user_id" {
    type = uuid
    null = false
  }

  column "hash" {
    type = text
    null = false
  }

  column "created_at" {
    type    = bigint
    null    = false
    default = "EXTRACT(epoch FROM NOW())"
  }

  column "expires_at" {
    type = bigint
    null = false
  }

  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_refresh_tokens_user_id" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
    on_delete   = CASCADE
  }
  index "idx_refresh_tokens_user_id" {
    columns = [column.user_id]
  }
  index "idx_refresh_tokens_hash" {
    columns = [column.hash]
  }
}
