package setup

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/gh/client"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewUpdateCmd returns the code-quality setup update command
func NewUpdateCmd() *cobra.Command {
	var repo string
	var state string
	var runnerType string
	var runnerLabel string
	var languages []string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a code quality setup configuration",
		Long: `Updates the code quality setup configuration for a repository.

Use --state to enable or disable code quality analysis.
Use --language to specify which languages to analyze (can be specified multiple times).
Use --runner-type to set the runner type (standard or labeled).
Use --runner-label to specify the runner label when runner-type is labeled.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			ghClient, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			update := &client.CodeQualitySetupUpdate{
				State:      state,
				RunnerType: runnerType,
				Languages:  languages,
			}
			if cmd.Flags().Changed("runner-label") {
				update.RunnerLabel = &runnerLabel
			}

			ctx := cmd.Context()
			if err := gh.UpdateCodeQualitySetup(ctx, ghClient, repository, update); err != nil {
				return fmt.Errorf("failed to update code quality setup: %w", err)
			}

			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringEnumFlag(cmd, &state, "state", "", "", gh.CodeQualitySetupStates, "The desired state of code quality setup")
	cmdutil.StringEnumFlag(cmd, &runnerType, "runner-type", "", "", gh.CodeQualitySetupRunnerTypes, "Runner type to be used (standard, labeled)")
	f.StringVar(&runnerLabel, "runner-label", "", "Runner label to use when runner-type is labeled")
	f.StringArrayVar(&languages, "language", nil, fmt.Sprintf("Language to analyze; can be specified multiple times. Supported: %v", gh.CodeQualitySetupLanguages))
	return cmd
}
