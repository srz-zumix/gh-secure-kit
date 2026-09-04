package recommended

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// applyFileViaPullRequest commits the given file to a new branch (created from
// the repository's default branch) and opens a pull request against the
// default branch, instead of committing directly to it, so the change can be
// reviewed before it takes effect. Reuses an existing branch/PR if one from a
// previous run is already present.
func applyFileViaPullRequest(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts, branchName, path, commitMessage, prTitle, prBody string, content []byte) error {
	defaultBranch := f.Repo.GetDefaultBranch()

	base, err := gh.GetBranch(ctx, g, repo, defaultBranch)
	if err != nil {
		return fmt.Errorf("failed to get default branch %q: %w", defaultBranch, err)
	}

	if _, err := gh.CreateBranch(ctx, g, repo, branchName, base.GetCommit().GetSHA()); err != nil && !gh.IsHTTPUnprocessableEntity(err) {
		return fmt.Errorf("failed to create branch %q: %w", branchName, err)
	}

	branch := branchName
	if _, err := gh.CreateRepositoryFile(ctx, g, repo, path, &gh.RepositoryContentFileOptions{
		Message: commitMessage,
		Content: content,
		Branch:  &branch,
	}); err != nil {
		// The create-file endpoint returns 422 when the file already exists on
		// the branch (it needs the current blob SHA to update). Treat that as a
		// successful reuse only if the file is really present on the branch;
		// otherwise the 422 signals a genuine failure and must be surfaced.
		if !gh.IsHTTPUnprocessableEntity(err) {
			return fmt.Errorf("failed to create %s on branch %q: %w", path, branchName, err)
		}
		if _, getErr := gh.GetRepositoryFileContent(ctx, g, repo, path, &branch); getErr != nil {
			return fmt.Errorf("failed to create %s on branch %q: %w", path, branchName, err)
		}
	}

	if _, err := gh.CreatePullRequest(ctx, g, repo, gh.NewPullRequest{
		Title: prTitle,
		Head:  branchName,
		Base:  defaultBranch,
		Body:  &prBody,
	}); err != nil && !gh.IsHTTPUnprocessableEntity(err) {
		return fmt.Errorf("failed to open pull request from %q: %w", branchName, err)
	}
	return nil
}
