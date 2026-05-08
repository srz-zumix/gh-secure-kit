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

// LocationsOptions holds the format exporter for locations command output.
type LocationsOptions struct {
	Exporter cmdutil.Exporter
}

// NewLocationsCmd returns the secret-scanning alerts locations command
func NewLocationsCmd() *cobra.Command {
	var repo string
	opts := &LocationsOptions{}

	cmd := &cobra.Command{
		Use:   "locations <alert-number>",
		Short: "List locations for a secret scanning alert",
		Long:  "List all locations where a secret scanning alert was detected in the repository.",
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
			locations, err := gh.ListSecretScanningAlertLocations(ctx, client, repository, alertNumber)
			if err != nil {
				return fmt.Errorf("failed to list locations for secret scanning alert: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderSecretScanningAlertLocations(locations)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
