package cmd

import (
	"encoding/hex"
	"os"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/nnnc-org/go-radntlm/internal/backends"
	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

var addCmd = &cobra.Command{
	Use:     "add",
	Aliases: []string{},
	Short:   "Manually add a login to the specified backend",
	Long:    ``,
	Run: func(cmd *cobra.Command, args []string) {
		usr, _ := cmd.Flags().GetString("username")
		pwd, _ := cmd.Flags().GetString("password")
		expire, _ := cmd.Flags().GetBool("expire")

		if pwd == "" {
			// ask for password if not provided, hide user input for security
			pwd, _ = pterm.DefaultInteractiveTextInput.WithMask("*").Show("Enter password")
		}

		hash := hex.EncodeToString(crypto.GetNTHash(pwd))

		file, _ := cmd.Flags().GetString("file")
		vaultPath, _ := cmd.Flags().GetString("database")

		if file != "" && vaultPath != "" {
			cmd.PrintErrf("Cannot use both flatfile and db backends simultaneously\n")
			os.Exit(3)
		}

		db, err := backends.Init(file, vaultPath)
		if err != nil {
			cmd.PrintErrf("Error initializing backend: %v\n", err)
			os.Exit(3)
		}
		defer db.Close()

		// add user to db
		if err := db.Add(usr, hash, expire); err != nil {
			cmd.PrintErrf("Error adding user: %v\n", err)
			os.Exit(3)
		}
		pterm.Success.Printf("Added user %s\n", usr)

		os.Exit(0)

	},
}

func init() {
	rootCmd.AddCommand(addCmd)

	addCmd.Flags().StringP("username", "u", "", "Username")
	addCmd.Flags().StringP("password", "p", "", "Plaintext password")
	addCmd.Flags().BoolP("expire", "e", false, "Set expiration to 1 year from now")

	addCmd.MarkFlagRequired("username")

	//addCmd.MarkFlagsOneRequired("file", "database")
}
