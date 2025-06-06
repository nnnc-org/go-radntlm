package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/nnnc-org/go-radntlm/internal/crypto"
	"github.com/nnnc-org/go-radntlm/internal/backends"
)

var authCmd = &cobra.Command{
	Use:     "auth",
	Aliases: []string{"a"},
	Short:   "Authenticate an NT-Response",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		ntResponse, _ := cmd.Flags().GetString("nt-response")
		challenge, _ := cmd.Flags().GetString("challenge")
		server, _ := cmd.Flags().GetString("server")

		file, _ := cmd.Flags().GetString("file")

		if server != "" {
			// handle later
			return
		}

		if file != "" {
			// Handle flatfile authentication
			hash, expiration, err := backends.FlatfileSearch(file, username)
			if err != nil {
				cmd.PrintErrf("Error searching flatfile: %v\n", err)
				os.Exit(3)
			}

			if hash == "" {
				cmd.PrintErrf("Username (%s) not found in flatfile\n", username)
				os.Exit(3)
			}

			if expiration != 0 && expiration < time.Now().Unix() {
				cmd.PrintErrf("Password for '%s' has expired\n", username)
				os.Exit(3)
			}

			valid, err := crypto.ValidateNTResponse(ntResponse, challenge, hash)
			if err != nil {
				cmd.PrintErrf("Error validating NT-Response: %v\n", err)
				os.Exit(3)
			}
			if valid {
				cmd.Println("Authentication successful")
				os.Exit(0)
			} else {
				cmd.Println("Incorrect Password")
				os.Exit(1)
			}
			return
		}



	},
}

func init() {
	rootCmd.AddCommand(authCmd)

	authCmd.Flags().StringP("username", "u", "", "Username to authenticate")
	authCmd.Flags().StringP("nt-response", "n", "", "NT-Response to process")
	authCmd.Flags().StringP("challenge", "c", "", "Challenge used to process the NT-Response")
	authCmd.Flags().StringP("server", "s", "", "Server and port to connect to")

	authCmd.MarkFlagRequired("username")
	authCmd.MarkFlagRequired("nt-response")
	authCmd.MarkFlagRequired("challenge")
}
