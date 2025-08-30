package users

import (
	"context"
	"time"

	"github.com/henrywhitaker3/go-template/database/queries"
	"github.com/henrywhitaker3/windowframe/workers"
)

type Expirer struct {
	db *queries.Queries
}

func NewExpirer(db *queries.Queries) *Expirer {
	return &Expirer{
		db: db,
	}
}

func (e *Expirer) Run(ctx context.Context) error {
	return e.db.DeleteExpiredRefreshTokens(ctx, time.Now().Unix())
}

func (e *Expirer) Name() string {
	return "users:expirer"
}

func (e *Expirer) Timeout() time.Duration {
	return time.Second * 15
}

func (e *Expirer) Interval() workers.Interval {
	return workers.NewInterval(time.Minute)
}
