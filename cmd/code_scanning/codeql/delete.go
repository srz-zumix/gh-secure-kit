package codeql

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewDeleteCmd returns the code-scanning codeql delete command
func NewDeleteCmd() *cobra.Command {
	var repo string

	cmd := &cobra.Command{
		Use:   "delete <language>",
		Short: "Delete a CodeQL database",
		Long:  "Deletes a CodeQL database for a language in a repository.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			language := args[0]

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			if err := gh.DeleteCodeQLDatabase(ctx, client, repository, language); err != nil {
				return fmt.Errorf("failed to delete CodeQL database: %w", err)
			}

			logger.Info("Deleted CodeQL database", "language", language, "repo", repository.Owner+"/"+repository.Name)
			return nil
		},
	}
	cmd.Flags().StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	return cmd
}
