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

// NewUpdateCmd returns the secret-scanning alerts update command
func NewUpdateCmd() *cobra.Command {
	var repo string
	var state string
	var resolution string
	var resolutionComment string
	opts := &UpdateOptions{}

	cmd := &cobra.Command{
		Use:   "update <alert-number>",
		Short: "Update a secret scanning alert",
		Long:  "Update a secret scanning alert for a repository. Use --state to change the alert state. A --resolution is required when setting state to resolved.",
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

			updateOpts := &gh.UpdateSecretScanningAlertOptions{
				State:             state,
				Resolution:        resolution,
				ResolutionComment: resolutionComment,
			}

			ctx := cmd.Context()
			alert, err := gh.UpdateSecretScanningAlert(ctx, client, repository, alertNumber, updateOpts)
			if err != nil {
				return fmt.Errorf("failed to update secret scanning alert: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderSecretScanningAlert(alert)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", gh.SecretScanningAlertUpdateStates, "The state to set")
	_ = cmd.MarkFlagRequired("state")
	cmdutil.StringEnumFlag(cmd, &resolution, "resolution", "", "", gh.SecretScanningAlertUpdateResolutions, "Reason for resolving; required when state is resolved")
	f.StringVar(&resolutionComment, "resolution-comment", "", "Optional comment associated with resolving the alert")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
