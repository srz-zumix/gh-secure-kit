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
	// A previous run may already have committed the file to this branch; reuse it.
	_, err = gh.GetRepositoryFileContent(ctx, g, repo, path, &branch)
	if err != nil {
		if !gh.IsHTTPNotFound(err) {
			return fmt.Errorf("failed to check whether %s exists on branch %q: %w", path, branchName, err)
		}
		head, err := gh.GetBranch(ctx, g, repo, branchName)
		if err != nil {
			return fmt.Errorf("failed to get branch %q: %w", branchName, err)
		}
		// The Contents API leaves commits unsigned; createCommitOnBranch makes GitHub sign them (verified).
		if _, err := gh.CreateCommitOnBranch(ctx, g, repo, branchName, head.GetCommit().GetSHA(), commitMessage, map[string][]byte{path: content}); err != nil {
			return fmt.Errorf("failed to commit %s to branch %q: %w", path, branchName, err)
		}
	}

	if _, err := gh.CreatePullRequest(ctx, g, repo, gh.NewPullRequest{
		Title: prTitle,
		Head:  branchName,
		Base:  defaultBranch,
		Body:  &prBody,
	}); err != nil {
		// The create-PR endpoint returns 422 both when an open PR from this
		// branch already exists (the idempotent reuse case) and for genuine
		// validation errors (e.g. no commits between base and head). Only treat
		// it as success when an open PR from the branch really exists.
		if !gh.IsHTTPUnprocessableEntity(err) {
			return fmt.Errorf("failed to open pull request from %q: %w", branchName, err)
		}
		if _, findErr := gh.FindPullRequest(ctx, g, repo,
			&gh.ListPullRequestsOptionHead{Head: repo.Owner + ":" + branchName},
			&gh.ListPullRequestsOptionBase{Base: defaultBranch},
			gh.ListPullRequestsOptionStateOpen(),
		); findErr != nil {
			return fmt.Errorf("opening a pull request from %q returned %v; verifying whether an open pull request already exists failed: %w", branchName, err, findErr)
		}
	}
	return nil
}
