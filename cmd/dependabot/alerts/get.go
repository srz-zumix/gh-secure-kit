package alerts

import (
	"fmt"
	"strconv"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// GetOptions holds the format exporter for get command output.
type GetOptions struct {
	Exporter cmdutil.Exporter
}

// NewGetCmd returns the dependabot alerts get command
func NewGetCmd() *cobra.Command {
	var repo string
	opts := &GetOptions{}

	cmd := &cobra.Command{
		Use:   "get <alert-number>",
		Short: "Get a Dependabot alert",
		Long:  "Get a single Dependabot alert by its number for a repository.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alertNumber, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid alert number %q: %w", args[0], err)
			}

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			alert, err := gh.GetDependabotAlert(ctx, client, repository, alertNumber)
			if err != nil {
				return err
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderDependabotAlert(alert)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
