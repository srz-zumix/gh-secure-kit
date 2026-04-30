package configurations

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

// NewListCmd returns the code-security configurations list command
func NewListCmd() *cobra.Command {
	var owner string
	var targetType string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List code security configurations",
		Long:  "List all code security configurations available in an organization.",
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
			configs, err := gh.ListCodeSecurityConfigurations(ctx, client, repository, &gh.ListCodeSecurityConfigurationsOptions{TargetType: targetType})
			if err != nil {
				return fmt.Errorf("failed to list code security configurations: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeSecurityConfigurations(configs)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.StringEnumFlag(cmd, &targetType, "target-type", "", "", gh.CodeSecurityListTargetTypes, "Filter by target type")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
