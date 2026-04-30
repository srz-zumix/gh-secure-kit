package configurations

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// CreateOptions holds the format exporter for create command output.
type CreateOptions struct {
	Exporter cmdutil.Exporter
}

// NewCreateCmd returns the code-security configurations create command
func NewCreateCmd() *cobra.Command {
	var owner string
	configOpts := &gh.CodeSecurityConfigurationOptions{}
	opts := &CreateOptions{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a code security configuration",
		Long:  "Create a code security configuration in an organization. --name and --description are required.",
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
			c, err := gh.CreateCodeSecurityConfiguration(ctx, client, repository, configOpts)
			if err != nil {
				return fmt.Errorf("failed to create code security configuration: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeSecurityConfiguration(c)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	addConfigFeatureFlags(cmd, configOpts)
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("description")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
