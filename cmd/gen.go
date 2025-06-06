package cmd


import (
	"fmt"
	"os"
	"time"
	"encoding/hex"

	"github.com/spf13/cobra"

	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

var genCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"g"},
	Short:   "Generate an NT Hash or flatfile entry",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		usr, _ := cmd.Flags().GetString("username")
		pwd, _ := cmd.Flags().GetString("password")

		hash := hex.EncodeToString(crypto.GetNTHash(pwd))

		if usr == "" {
			fmt.Println(hash)
			os.Exit(0)
		}

		// Generate flatfile entry
		// Format: username:hash:expiration

		fmt.Printf("%s:%s:%d\n", usr, hash, time.Now().AddDate(1, 0, 0).Unix())
		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(genCmd)

	genCmd.Flags().StringP("username", "u", "", "Username")
	genCmd.Flags().StringP("password", "p", "", "Plaintext password")

	genCmd.MarkFlagRequired("password")
}
