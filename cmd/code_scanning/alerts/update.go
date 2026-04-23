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

// UpdateOptions holds the format exporter for update command output.
type UpdateOptions struct {
	Exporter cmdutil.Exporter
}

// NewUpdateCmd returns the code-scanning alerts update command
func NewUpdateCmd() *cobra.Command {
	var repo string
	var state string
	var dismissedReason string
	var dismissedComment string
	opts := &UpdateOptions{}

	cmd := &cobra.Command{
		Use:   "update <alert-number>",
		Short: "Update a code scanning alert",
		Long:  "Update a code scanning alert for a repository. Use --state to change the alert state. A --dismissed-reason is required when setting state to dismissed.",
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

			updateOpts := &gh.UpdateCodeScanningAlertOptions{
				State:            state,
				DismissedReason:  dismissedReason,
				DismissedComment: dismissedComment,
			}

			ctx := cmd.Context()
			alert, err := gh.UpdateCodeScanningAlert(ctx, client, repository, alertNumber, updateOpts)
			if err != nil {
				return fmt.Errorf("failed to update code scanning alert: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeScanningAlert(alert)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", gh.CodeScanningAlertUpdateStates, "The state to set")
	_ = cmd.MarkFlagRequired("state")
	cmdutil.StringEnumFlag(cmd, &dismissedReason, "dismissed-reason", "", "", gh.CodeScanningAlertDismissedReasons, "Reason for dismissing; required when state is dismissed")
	f.StringVar(&dismissedComment, "dismissed-comment", "", "Optional comment associated with dismissing the alert")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
