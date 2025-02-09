package postgres

import (
	"context"
	"database/sql"

	"github.com/XSAM/otelsql"
	"github.com/henrywhitaker3/go-template/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func Open(ctx context.Context, url string, tracing config.Tracing) (*sql.DB, error) {
	var db *sql.DB
	var err error
	if *tracing.Enabled {
		db, err = otelsql.Open(
			"pgx",
			url,
			otelsql.WithSpanOptions(otelsql.SpanOptions{
				OmitConnResetSession: true,
				OmitConnectorConnect: true,
			}),
		)
	} else {
		db, err = sql.Open("pgx", url)
	}

	if err != nil {
		return nil, err
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}
