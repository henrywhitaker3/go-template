package secrets

import (
	"fmt"

	"github.com/henrywhitaker3/windowframe/crypto"
	"github.com/spf13/cobra"
)

var (
	encSize int
)

func newKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Generate a new encryption key",
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := crypto.GenerateAesKey(encSize)
			if err != nil {
				return err
			}
			fmt.Println(key)
			return nil
		},
	}

	cmd.Flags().IntVar(&encSize, "size", 256, "The size in bits of the encryption key")

	return cmd
}
