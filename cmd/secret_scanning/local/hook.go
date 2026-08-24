package local

import (
	"github.com/spf13/cobra"
	hookcmd "github.com/srz-zumix/gh-secure-kit/cmd/secret_scanning/local/hook"
)

// NewHookCmd returns the secret-scanning local hook parent command
func NewHookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage the git hooks that run local secret scanning",
		Long:  "Install, remove and inspect the pre-commit and pre-push git hooks that run 'secret-scanning local check', so that commits and pushes are aborted when a secret is detected.",
	}
	cmd.AddCommand(hookcmd.NewInstallCmd())
	cmd.AddCommand(hookcmd.NewStatusCmd())
	cmd.AddCommand(hookcmd.NewUninstallCmd())
	return cmd
}
