package cmd


import (
	"fmt"
	"os"
	"time"
	"encoding/hex"

	"github.com/spf13/cobra"
	"github.com/pterm/pterm"

	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

var genCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"g", "gen"},
	Short:   "Generate an NT Hash or flatfile entry",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		usr, _ := cmd.Flags().GetString("username")
		pwd, _ := cmd.Flags().GetString("password")

		if pwd == "" {
			// ask for password if not provided, hide user input for security
			pwd, _ = pterm.DefaultInteractiveTextInput.WithMask("*").Show("Enter password")
		}

		hash := hex.EncodeToString(crypto.GetNTHash(pwd))

		if usr == "" {
			fmt.Println(hash)
			os.Exit(0)
		}

		// Generate flatfile entry
		// Format: username:hash:expiration
		file, _ := cmd.Flags().GetString("file")
		if file != "" {
			// append to file
			err := os.WriteFile(file, []byte(fmt.Sprintf("%s:%s:%d\n", usr, hash, time.Now().AddDate(1, 0, 0).Unix())), 0644)
			if err != nil {
				pterm.Error.Println(err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("%s:%s:%d\n", usr, hash, time.Now().AddDate(1, 0, 0).Unix())
		}

		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(genCmd)

	genCmd.Flags().StringP("username", "u", "", "Username")
	genCmd.Flags().StringP("password", "p", "", "Plaintext password")
}
