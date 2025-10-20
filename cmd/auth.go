package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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
		server, _ := cmd.Flags().GetString("server")

		if server != "" {
			token, _ := cmd.Flags().GetString("token")
			ntKey, err := serverAuth(username, ntResponse, challenge, server, token)
			if err != nil {
				cmd.PrintErrf("Authentication failed for %s: %v\n", username, err)
				os.Exit(1)
			}
			fmt.Fprintln(cmd.OutOrStdout(), ntKey)
			os.Exit(0)

		}

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
		fmt.Fprint(cmd.OutOrStdout(), "NT_KEY:", ntKey)
		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(authCmd)

	authCmd.Flags().StringP("username", "u", "", "Username to authenticate")
	authCmd.Flags().StringP("nt-response", "n", "", "NT-Response to process")
	authCmd.Flags().StringP("challenge", "c", "", "Challenge used to process the NT-Response")

	authCmd.Flags().StringP("server", "s", "", "Server and port to connect to")
	authCmd.Flags().StringP("token", "t", "", "Auth token for the auth API")

	authCmd.MarkFlagRequired("username")
	authCmd.MarkFlagRequired("nt-response")
	authCmd.MarkFlagRequired("challenge")
}

func serverAuth(username string, ntResponse string, challenge string, server string, token string) (string, error) {
	authString := fmt.Sprintf("username=%s&nt-response=%s&challenge=%s", username, ntResponse, challenge)

	// http client
	client := &http.Client{}
	req, err := http.NewRequest("POST", server, bytes.NewBufferString(authString))
	if err != nil {
		return "", err
	}

	// set auth header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}
