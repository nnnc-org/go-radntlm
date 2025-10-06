package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

var genCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"g", "gen"},
	Short:   "Generate an NT Hash",
	Long:    ``,
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
		} else {
			fmt.Printf("%s:%s:%d\n", usr, hash, time.Now().AddDate(1, 0, 0).Unix())
		}
		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(genCmd)

	genCmd.Flags().StringP("username", "u", "", "Username (optional)")
	genCmd.Flags().StringP("password", "p", "", "Plaintext password")
}
