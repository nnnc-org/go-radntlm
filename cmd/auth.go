package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/nnnc-org/go-radntlm/internal/backends"
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

		ntKey, err := backends.AuthenticateUser(db, username, ntResponse, challenge)
		if err != nil {
			cmd.PrintErrf("Authentication failed for %s: %v\n", username, err)
			os.Exit(1)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "NT_KEY:", ntKey)
		os.Exit(0)
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
