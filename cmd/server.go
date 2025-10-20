package cmd

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nnnc-org/go-radntlm/internal/authapi"
	"github.com/nnnc-org/go-radntlm/internal/backends"
	"github.com/nnnc-org/go-radntlm/internal/webui"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the server-side component",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		startServers(cmd)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringP("webui", "w", ":8080", "HTTP server listen address for the web UI access")
	serverCmd.Flags().StringP("authapi", "a", ":8081", "HTTP server listen address for auth API access")
	serverCmd.Flags().StringP("token", "t", "", "Auth token for the auth API")

	// SAML Settings
	serverCmd.Flags().StringP("saml-domain", "", "", "Site domain (e.g., radius.example.com)")
	serverCmd.Flags().StringP("saml-metadata-url", "", "", "SAML IDP Metadata URL")
	serverCmd.Flags().StringP("saml-metadata-file", "", "", "Path to IDP Metadata XML File")
	serverCmd.Flags().StringP("saml-cert-file", "", "./signing-cert.pem", "Path to signing certificate file. Will be generated if not provided")
	serverCmd.Flags().StringP("saml-key-file", "", "./signing-cert.key", "Path to signing certificate key file. Will be generated if not provided")

}

func startServers(cmd *cobra.Command) {
	// fix log output
	log.SetFlags(log.LstdFlags)

	clientAddr, _ := cmd.Flags().GetString("webui")
	authAPIAddr, _ := cmd.Flags().GetString("authapi")
	token, _ := cmd.Flags().GetString("token")

	vaultPath, _ := cmd.Flags().GetString("database")
	file, _ := cmd.Flags().GetString("file")

	db, err := backends.Init(file, vaultPath)
	if err != nil {
		cmd.PrintErrf("Error initializing backend: %v\n", err)
		return
	}
	defer db.Close()

	// Create a context that cancels on SIGINT/SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signal
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Println("Shutdown signal received")
		cancel()
	}()

	// Start the client webui server
	samlConfig := webui.SAMLConfig{
		Domain:       paramEval(cmd, "saml-domain", "DOMAIN", ""),
		MetadataURL:  paramEval(cmd, "saml-metadata-url", "METADATA_URL", ""),
		MetadataFile: paramEval(cmd, "saml-metadata-file", "METADATA_FILE", ""),
		CertFile:     paramEval(cmd, "saml-cert-file", "CERT_FILE", "./signing-cert.pem"),
		KeyFile:      paramEval(cmd, "saml-key-file", "KEY_FILE", "./signing-cert.key"),
	}
	go webui.StartServer(ctx, clientAddr, db, samlConfig)

	// Start the auth API server
	go authapi.StartServer(ctx, authAPIAddr, db, token)

	// Handle Token Expiration every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				log.Println("Cleaning up expired tokens")
				if err := db.Cleanup(); err != nil {
					log.Println("DB write error:", err)
				}
			case <-ctx.Done():
				log.Println("Stopping token cleanup job")
				return
			}
		}
	}()

	// Block until context is canceled
	<-ctx.Done()
	log.Println("Stopping services...")

	if err := db.Close(); err != nil {
		log.Println("Error closing database:", err)
	}
	log.Println("All services stopped, exiting.")
}

func paramEval(cmd *cobra.Command, param string, env string, defaultValue string) string {
	value, _ := cmd.Flags().GetString(param)
	if value != "" {
		return value
	}
	if envValue, ok := os.LookupEnv(env); ok {
		return envValue
	}
	return defaultValue
}
