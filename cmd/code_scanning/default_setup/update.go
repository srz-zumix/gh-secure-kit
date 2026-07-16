package defaultsetup

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// CodeScanningDefaultSetupStates is the list of valid state values for the default setup configuration.
var CodeScanningDefaultSetupStates = []string{
	"configured",
	"not-configured",
}

// UpdateOptions holds the format exporter for update command output.
type UpdateOptions struct {
	Exporter cmdutil.Exporter
}

// NewUpdateCmd returns the code-scanning default-setup update command.
func NewUpdateCmd() *cobra.Command {
	var repo string
	var state string
	var querySuite string
	var languages []string
	opts := &UpdateOptions{}

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a code scanning default setup configuration for a repository",
		Long:  "Updates the code scanning default setup configuration for a repository.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}
			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}
			updateOpts := &gh.UpdateCodeScanningDefaultSetupConfigurationOptions{
				State:      state,
				QuerySuite: querySuite,
				Languages:  languages,
			}
			result, err := gh.UpdateCodeScanningDefaultSetupConfiguration(cmd.Context(), client, repository, updateOpts)
			if err != nil {
				return fmt.Errorf("failed to update code scanning default setup configuration: %w", err)
			}
			logger.Info("Updated code scanning default setup configuration", "repo", repository.Owner+"/"+repository.Name)
			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderUpdateCodeScanningDefaultSetupConfigurationResponse(result)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", CodeScanningDefaultSetupStates, "The desired state of code scanning default setup (required)")
	cmdutil.StringEnumFlag(cmd, &querySuite, "query-suite", "", "", gh.CodeScanningQuerySuites, "CodeQL query suite to be used")
	f.StringSliceVar(&languages, "languages", nil, "CodeQL languages to be analyzed (comma-separated, defaults to auto-detected languages)")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	_ = cmd.MarkFlagRequired("state")
	return cmd
}
