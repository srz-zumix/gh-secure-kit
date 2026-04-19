package repositoryaccess

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// ListOptions holds the format exporter for list command output.
type ListOptions struct {
	Exporter cmdutil.Exporter
}

// NewListCmd returns the dependabot repository-access list command
func NewListCmd() *cobra.Command {
	var owner string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List repositories Dependabot can access",
		Long:  "Lists repositories that organization admins have allowed Dependabot to access when updating dependencies.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			access, err := gh.ListOrgDependabotRepositoryAccess(ctx, client, repository.Owner)
			if err != nil {
				return err
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderDependabotRepositoryAccess(access)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
