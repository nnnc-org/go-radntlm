package cmd

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/nnnc-org/go-radntlm/internal/backends"
	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

var authCmd = &cobra.Command{
	Use:     "auth",
	Aliases: []string{"a"},
	Short:   "Manually authenticate an NT-Response",
	Long:    ``,
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		ntResponse, _ := cmd.Flags().GetString("nt-response")
		challenge, _ := cmd.Flags().GetString("challenge")

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

		// search for user in db
		ud, err := db.Search(username)
		if err != nil {
			cmd.PrintErrf("Error searching for user: %v\n", err)
			os.Exit(3)
		}

		if ud.Hash == "" {
			pterm.Error.Printf("User %s contains empty hash\n", username)
			os.Exit(2)
		}

		if ud.IsExpired() {
			pterm.Error.Printf("Password for '%s' has expired\n", username)
			os.Exit(3)
		}

		valid, err := crypto.ValidateNTResponse(ntResponse, challenge, ud.Hash)
		if err != nil {
			pterm.Error.Printf("Error validating NT-Response: %v\n", err)
			os.Exit(3)
		}
		if valid {
			// return nt key
			ntKey := crypto.CreateNTSessionKey(ud.Hash)
			fmt.Fprintln(cmd.OutOrStdout(), "NT_KEY:", ntKey)
			os.Exit(0)
		} else {
			pterm.Error.Println("Incorrect Password")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(authCmd)

	authCmd.Flags().StringP("username", "u", "", "Username to authenticate")
	authCmd.Flags().StringP("nt-response", "n", "", "NT-Response to process")
	authCmd.Flags().StringP("challenge", "c", "", "Challenge used to process the NT-Response")
	//authCmd.Flags().StringP("server", "s", "", "Server and port to connect to")

	authCmd.MarkFlagRequired("username")
	authCmd.MarkFlagRequired("nt-response")
	authCmd.MarkFlagRequired("challenge")
}
