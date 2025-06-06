package cmd


import (
	"fmt"
	"encoding/hex"

	"github.com/spf13/cobra"

	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

var genCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"g"},
	Short:   "Generate an NT Hash",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		pwd, _ := cmd.Flags().GetString("password")

		hash := hex.EncodeToString(crypto.GetNTHash(pwd))
		fmt.Println(hash)

	},
}

func init() {
	rootCmd.AddCommand(genCmd)

	genCmd.Flags().StringP("password", "p", "", "Plaintext password")
	genCmd.MarkFlagRequired("password")
}
