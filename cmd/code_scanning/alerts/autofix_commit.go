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

// AutofixCommitOptions holds the format exporter for autofix commit command output.
type AutofixCommitOptions struct {
	Exporter cmdutil.Exporter
}

// NewAutofixCommitCmd returns the code-scanning alerts autofix commit command.
func NewAutofixCommitCmd() *cobra.Command {
	var repo string
	var targetRef string
	var message string
	opts := &AutofixCommitOptions{}

	cmd := &cobra.Command{
		Use:   "commit <alert-number>",
		Short: "Commit an autofix for a code scanning alert",
		Long: `Commit an autofix for a code scanning alert from the repository's default branch.

The target branch must already exist. If omitted, the default branch is used.`,
		Args: cobra.ExactArgs(1),
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

			commitOpts := &gh.CommitCodeScanningAutofixOptions{
				TargetRef: targetRef,
				Message:   message,
			}

			ctx := cmd.Context()
			commit, err := gh.CommitCodeScanningAutofix(ctx, client, repository, alertNumber, commitOpts)
			if err != nil {
				return fmt.Errorf("failed to commit autofix for code scanning alert #%d: %w", alertNumber, err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeScanningAutofixCommit(commit)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVar(&targetRef, "target-ref", "", "The Git reference of the target branch for the commit (e.g. refs/heads/my-fix)")
	f.StringVar(&message, "message", "", "Commit message for the autofix commit")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
