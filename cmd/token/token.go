package token

import (
	"fmt"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/spf13/cobra"
)

var (
	expiry time.Duration
)

func New(b *boiler.Boiler) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "token [role]",
		Short:   "Generate a generic jwt token",
		GroupID: "app",
		Args:    cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			app.RegisterBase(b)
			b.MustBootstrap()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, err := boiler.Resolve[*jwt.Jwt](b)
			if err != nil {
				return err
			}
			token, err := svc.Generic(jwt.Role(args[0]), expiry)
			if err != nil {
				return err
			}
			fmt.Println(token)
			return nil
		},
	}

	cmd.Flags().
		DurationVar(&expiry, "expiry", time.Hour*24*30, "The duration of time the token is valid for")

	return cmd
}
