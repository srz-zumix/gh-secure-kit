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

// SetDefaultOptions holds the format exporter for set-default command output.
type SetDefaultOptions struct {
	Exporter cmdutil.Exporter
}

// NewSetDefaultCmd returns the code-security configurations set-default command
func NewSetDefaultCmd() *cobra.Command {
	var owner string
	var defaultForNewRepos string
	opts := &SetDefaultOptions{}

	cmd := &cobra.Command{
		Use:   "set-default <configuration-id>",
		Short: "Set a code security configuration as default",
		Long:  "Set a code security configuration as default for new repositories in an organization.",
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
			d, err := gh.SetDefaultCodeSecurityConfiguration(ctx, client, repository, id, defaultForNewRepos)
			if err != nil {
				return fmt.Errorf("failed to set default code security configuration: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderDefaultCodeSecurityConfiguration(d)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.StringEnumFlag(cmd, &defaultForNewRepos, "default-for-new-repos", "", "", gh.CodeSecurityDefaultForNewRepos, "Repository types this configuration applies to by default")
	_ = cmd.MarkFlagRequired("default-for-new-repos")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
