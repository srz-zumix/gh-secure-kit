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

// RepositoriesOptions holds the format exporter for repositories command output.
type RepositoriesOptions struct {
	Exporter cmdutil.Exporter
}

// NewRepositoriesCmd returns the code-security configurations repositories command
func NewRepositoriesCmd() *cobra.Command {
	var owner string
	var status string
	opts := &RepositoriesOptions{}

	cmd := &cobra.Command{
		Use:   "repositories <configuration-id>",
		Short: "List repositories attached to a code security configuration",
		Long:  "List the repositories associated with a code security configuration in an organization.",
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
			attachments, err := gh.ListCodeSecurityConfigurationRepositories(ctx, client, repository, id, &gh.ListCodeSecurityConfigurationRepositoriesOptions{Status: status})
			if err != nil {
				return fmt.Errorf("failed to list repositories for code security configuration: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeSecurityConfigurationRepositories(attachments)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.StringEnumFlag(cmd, &status, "status", "", "", gh.CodeSecurityRepositoryStatuses, "Filter by attachment status")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
