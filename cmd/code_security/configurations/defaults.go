package configurations

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// DefaultsOptions holds the format exporter for defaults command output.
type DefaultsOptions struct {
	Exporter cmdutil.Exporter
}

// NewDefaultsCmd returns the code-security configurations defaults command
func NewDefaultsCmd() *cobra.Command {
	var owner string
	opts := &DefaultsOptions{}

	cmd := &cobra.Command{
		Use:   "defaults",
		Short: "List default code security configurations",
		Long:  "List the default code security configurations applied to new repositories in an organization.",
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
			defaults, err := gh.ListDefaultCodeSecurityConfigurations(ctx, client, repository)
			if err != nil {
				return fmt.Errorf("failed to list default code security configurations: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderDefaultCodeSecurityConfigurations(defaults)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
