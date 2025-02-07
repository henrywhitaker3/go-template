package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/XSAM/otelsql"
	"github.com/henrywhitaker3/go-template/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func Open(ctx context.Context, conf config.Postgres, tracing config.Tracing) (*sql.DB, error) {
	if conf.CaCertFile != "" {
		if !strings.Contains(conf.Url, "?") {
			conf.Url += "&"
		}
		conf.Url = fmt.Sprintf("%ssslrootcert=%s", conf.Url, conf.CaCertFile)
	}
	var db *sql.DB
	var err error
	if tracing.Enabled {
		db, err = otelsql.Open(
			"pgx",
			conf.Url,
			otelsql.WithSpanOptions(otelsql.SpanOptions{
				OmitConnResetSession: true,
				OmitConnectorConnect: true,
			}),
		)
	} else {
		db, err = sql.Open("pgx", conf.Url)
	}

	if err != nil {
		return nil, err
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}
