package configurations

import (
	"fmt"
	"strconv"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// UpdateOptions holds the format exporter for update command output.
type UpdateOptions struct {
	Exporter cmdutil.Exporter
}

// NewUpdateCmd returns the code-security configurations update command
func NewUpdateCmd() *cobra.Command {
	var owner string
	configOpts := &gh.CodeSecurityConfigurationOptions{}
	opts := &UpdateOptions{}

	cmd := &cobra.Command{
		Use:   "update <configuration-id>",
		Short: "Update a code security configuration",
		Long:  "Update a code security configuration in an organization. Only specified fields are sent.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid configuration id %q: %w", args[0], err)
			}
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			c, err := gh.UpdateCodeSecurityConfiguration(ctx, client, repository, id, configOpts)
			if err != nil {
				return fmt.Errorf("failed to update code security configuration: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeSecurityConfiguration(c)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	addConfigFeatureFlags(cmd, configOpts)
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
