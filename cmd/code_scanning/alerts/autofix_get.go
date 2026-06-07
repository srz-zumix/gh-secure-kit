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

// AutofixGetOptions holds the format exporter for autofix get command output.
type AutofixGetOptions struct {
	Exporter cmdutil.Exporter
}

// NewAutofixGetCmd returns the code-scanning alerts autofix get command.
func NewAutofixGetCmd() *cobra.Command {
	var repo string
	opts := &AutofixGetOptions{}

	cmd := &cobra.Command{
		Use:   "get <alert-number>",
		Short: "Get the autofix status for a code scanning alert",
		Long:  "Get the status and description of an autofix for a code scanning alert on the repository's default branch.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alertNumber, err := strconv.ParseInt(args[0], 10, 64)
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
			autofix, err := gh.GetCodeScanningAutofix(ctx, client, repository, alertNumber)
			if err != nil {
				return fmt.Errorf("failed to get autofix for code scanning alert #%d: %w", alertNumber, err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeScanningAutofix(autofix)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
