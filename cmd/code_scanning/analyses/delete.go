package analyses

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewDeleteCmd returns the code-scanning analyses delete command
func NewDeleteCmd() *cobra.Command {
	var repo string
	var confirmDelete bool

	cmd := &cobra.Command{
		Use:   "delete <analysis-id>",
		Short: "Delete a code scanning analysis",
		Long:  "Deletes a specified code scanning analysis from a repository. You can delete one analysis at a time, starting with the most recent.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			analysisID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid analysis ID %q: %w", args[0], err)
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
			result, err := gh.DeleteCodeScanningAnalysis(ctx, client, repository, analysisID, confirmDelete)
			if err != nil {
				return fmt.Errorf("failed to delete code scanning analysis: %w", err)
			}

			logger.Info("Deleted code scanning analysis", "id", analysisID, "repo", repository.Owner+"/"+repository.Name)
			if result.NextAnalysisURL != nil {
				logger.Info("Next deletable analysis", "url", *result.NextAnalysisURL)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.BoolVar(&confirmDelete, "confirm-delete", false, "Allow deletion if the specified analysis is the last in a set")
	return cmd
}
