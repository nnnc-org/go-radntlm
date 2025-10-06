package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "go-radntlm",
	Short: "Simple tool to respond to MSCHAP-V2 requests",
	Long:  ``,
	//PersistentPreRun: func(cmd *cobra.Command, args []string) {
	//},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringP("file", "F", "", "Flatfile location")
	rootCmd.PersistentFlags().StringP("database", "D", "", "DB location")
}
