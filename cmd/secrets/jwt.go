package secrets

import (
	"fmt"

	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/spf13/cobra"
)

var (
	jwtSize int
)

func newJwt() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwt",
		Short: "Generate a new JWT secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := jwt.GenerateSecret(jwtSize)
			if err != nil {
				return err
			}
			fmt.Println(key)
			return nil
		},
	}

	cmd.Flags().IntVar(&jwtSize, "size", 256, "The size in bits of the jwt sercet")

	return cmd
}
