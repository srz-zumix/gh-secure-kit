package cmd

import (
	"github.com/spf13/cobra"
	codesecurity "github.com/srz-zumix/gh-secure-kit/cmd/code_security"
)

func init() {
	rootCmd.AddCommand(NewCodeSecurityCmd())
}

// NewCodeSecurityCmd returns the code-security parent command
func NewCodeSecurityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "code-security",
		Short: "Manage code security configurations",
		Long:  "Manage code security configurations for organizations and repositories.",
	}
	cmd.AddCommand(codesecurity.NewConfigurationsCmd())
	return cmd
}
