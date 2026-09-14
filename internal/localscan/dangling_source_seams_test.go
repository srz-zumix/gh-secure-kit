package localscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	cligit "github.com/cli/cli/v2/git"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/gh-diet-kit/pkg/dangling"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// TestDanglingSourcePullRequestsUsesExplicitNumbers verifies that explicit pull
// request numbers are looked up directly and the closed-PR listing is skipped.
func TestDanglingSourcePullRequestsUsesExplicitNumbers(t *testing.T) {
	var gotNumbers []int
	s := &DanglingSource{
		ctx:  context.Background(),
		opts: DanglingSourceOptions{PRNumbers: []int{7, 9}},
		getPRsByNumbers: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, numbers []int) ([]*github.PullRequest, error) {
			gotNumbers = numbers
			return []*github.PullRequest{{}}, nil
		},
		listClosedPRs: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ int) ([]*github.PullRequest, error) {
			t.Fatal("listClosedPRs must not be called when PR numbers are given")
			return nil, nil
		},
	}

	if _, err := s.pullRequests(); err != nil {
		t.Fatalf("pullRequests() error = %v", err)
	}
	if len(gotNumbers) != 2 || gotNumbers[0] != 7 || gotNumbers[1] != 9 {
		t.Errorf("getPRsByNumbers numbers = %v, want [7 9]", gotNumbers)
	}
}

// TestDanglingSourcePullRequestsListsClosedWithLimit verifies that without
// explicit numbers the closed pull requests are listed and the configured
// limit is propagated.
func TestDanglingSourcePullRequestsListsClosedWithLimit(t *testing.T) {
	gotLimit := -1
	s := &DanglingSource{
		ctx:  context.Background(),
		opts: DanglingSourceOptions{Limit: 42},
		getPRsByNumbers: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ []int) ([]*github.PullRequest, error) {
			t.Fatal("getPRsByNumbers must not be called without PR numbers")
			return nil, nil
		},
		listClosedPRs: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, maxPRs int) ([]*github.PullRequest, error) {
			gotLimit = maxPRs
			return []*github.PullRequest{{}}, nil
		},
	}

	if _, err := s.pullRequests(); err != nil {
		t.Fatalf("pullRequests() error = %v", err)
	}
	if gotLimit != 42 {
		t.Errorf("listClosedPRs maxPRs = %d, want 42", gotLimit)
	}
}

// TestDanglingSourcePullRequestDanglingCommitsPropagatesOptions verifies that
// the scan-specific DanglingOptions, including the NoBlobSize optimisation that
// keeps a secret scan cheap, are passed through to the discovery call.
func TestDanglingSourcePullRequestDanglingCommitsPropagatesOptions(t *testing.T) {
	var got dangling.DanglingOptions
	s := &DanglingSource{
		ctx: context.Background(),
		opts: DanglingSourceOptions{
			NoSquashMerge: true,
			NoForcePush:   true,
			NoClosed:      true,
			StrictErrors:  true,
		},
		listClosedPRs: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ int) ([]*github.PullRequest, error) {
			return []*github.PullRequest{{}}, nil
		},
		findDangling: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ []*github.PullRequest, opts dangling.DanglingOptions) ([]*dangling.DanglingCommit, error) {
			got = opts
			return nil, nil
		},
	}

	if _, err := s.pullRequestDanglingCommits(); err != nil {
		t.Fatalf("pullRequestDanglingCommits() error = %v", err)
	}
	if !got.NoBlobSize {
		t.Error("DanglingOptions.NoBlobSize = false, want true")
	}
	if !got.DisableSquashRebase || !got.DisableForcePush || !got.DisableClosed || !got.StrictErrors {
		t.Errorf("DanglingOptions did not propagate the scan flags: %+v", got)
	}
}

// TestDanglingSourceFetchCommitsOnlyFetchesMissing verifies that commits
// already present in the fetch repository are skipped and only the missing
// SHAs reach the git fetch.
func TestDanglingSourceFetchCommitsOnlyFetchesMissing(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("failed to initialize a repository: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("failed to open worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("present"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	if _, err := wt.Add("a.txt"); err != nil {
		t.Fatalf("failed to add file: %v", err)
	}
	present, err := wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("failed to commit: %v", err)
	}
	const missing = "1111111111111111111111111111111111111111"

	var fetched []string
	s := &DanglingSource{
		ctx:      context.Background(),
		fetchDir: dir,
		fetchBatchFn: func(_ *cligit.Client, batch []string) error {
			fetched = append(fetched, batch...)
			return nil
		},
	}

	if err := s.fetchCommits([]string{present.String(), missing}); err != nil {
		t.Fatalf("fetchCommits() error = %v", err)
	}
	if len(fetched) != 1 || fetched[0] != missing {
		t.Errorf("fetched = %v, want [%s]", fetched, missing)
	}
}

// TestDanglingSourceFragmentsNoFetchUsesAPI verifies the no-fetch orchestration:
// dangling commits are discovered, read through the GitHub API seam, and turned
// into fragments without touching git objects on disk.
func TestDanglingSourceFragmentsNoFetchUsesAPI(t *testing.T) {
	const sha = "abcabcabcabcabcabcabcabcabcabcabcabcabca"
	var gotSHA string
	s := &DanglingSource{
		ctx:  context.Background(),
		opts: DanglingSourceOptions{NoFetch: true},
		listClosedPRs: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ int) ([]*github.PullRequest, error) {
			return []*github.PullRequest{{}}, nil
		},
		findDangling: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ []*github.PullRequest, _ dangling.DanglingOptions) ([]*dangling.DanglingCommit, error) {
			return []*dangling.DanglingCommit{{SHA: sha}}, nil
		},
		getCommit: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, s string) (*github.RepositoryCommit, error) {
			gotSHA = s
			return &github.RepositoryCommit{
				SHA: github.Ptr(sha),
				Files: []*github.CommitFile{{
					Filename:  github.Ptr("config.txt"),
					Additions: github.Ptr(1),
					Patch:     github.Ptr("@@ -0,0 +1 @@\n+leaked-secret-value"),
				}},
			}, nil
		},
	}

	frags, err := s.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if gotSHA != sha {
		t.Errorf("getCommit sha = %q, want %q", gotSHA, sha)
	}
	if len(frags) != 1 {
		t.Fatalf("Fragments() returned %d fragments, want 1", len(frags))
	}
	if frags[0].Content != "leaked-secret-value\n" {
		t.Errorf("fragment content = %q, want %q", frags[0].Content, "leaked-secret-value\n")
	}
}
