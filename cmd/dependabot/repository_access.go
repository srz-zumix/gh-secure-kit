package dependabot

import (
	"github.com/spf13/cobra"
	repositoryaccess "github.com/srz-zumix/gh-secure-kit/cmd/dependabot/repository_access"
)

// NewRepositoryAccessCmd returns the dependabot repository-access parent command
func NewRepositoryAccessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repository-access",
		Short: "Manage Dependabot repository access",
	}
	cmd.AddCommand(repositoryaccess.NewListCmd())
	cmd.AddCommand(repositoryaccess.NewSetDefaultLevelCmd())
	cmd.AddCommand(repositoryaccess.NewUpdateCmd())
	return cmd
}
