package localscan

import (
	"context"
	"errors"
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

// TestDanglingSourceStreamFragmentsIsCommitIncremental verifies that
// StreamFragments processes one commit at a time: when the yield callback stops
// after the first commit's fragment, the second commit is never read and the
// callback's error is returned unchanged.
func TestDanglingSourceStreamFragmentsIsCommitIncremental(t *testing.T) {
	const sha1 = "1111111111111111111111111111111111111111"
	const sha2 = "2222222222222222222222222222222222222222"
	var requested []string
	s := &DanglingSource{
		ctx:  context.Background(),
		opts: DanglingSourceOptions{NoFetch: true},
		listClosedPRs: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ int) ([]*github.PullRequest, error) {
			return []*github.PullRequest{{}}, nil
		},
		findDangling: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ []*github.PullRequest, _ dangling.DanglingOptions) ([]*dangling.DanglingCommit, error) {
			return []*dangling.DanglingCommit{{SHA: sha1}, {SHA: sha2}}, nil
		},
		getCommit: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, sha string) (*github.RepositoryCommit, error) {
			requested = append(requested, sha)
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

	errStop := errors.New("stop after first fragment")
	var seen int
	err := s.StreamFragments(func(Fragment) error {
		seen++
		return errStop
	})

	if !errors.Is(err, errStop) {
		t.Fatalf("StreamFragments() error = %v, want errStop", err)
	}
	if seen != 1 {
		t.Errorf("yield called %d times, want 1", seen)
	}
	if len(requested) != 1 || requested[0] != sha1 {
		t.Errorf("getCommit requested = %v, want only [%s] (second commit must not be read)", requested, sha1)
	}
}

// TestDanglingSourceStreamFragmentsYieldsAllCommits verifies that, absent an
// early stop, StreamFragments yields every commit's fragments in order.
func TestDanglingSourceStreamFragmentsYieldsAllCommits(t *testing.T) {
	const sha1 = "1111111111111111111111111111111111111111"
	const sha2 = "2222222222222222222222222222222222222222"
	s := &DanglingSource{
		ctx:  context.Background(),
		opts: DanglingSourceOptions{NoFetch: true},
		listClosedPRs: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ int) ([]*github.PullRequest, error) {
			return []*github.PullRequest{{}}, nil
		},
		findDangling: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ []*github.PullRequest, _ dangling.DanglingOptions) ([]*dangling.DanglingCommit, error) {
			return []*dangling.DanglingCommit{{SHA: sha1}, {SHA: sha2}}, nil
		},
		getCommit: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, sha string) (*github.RepositoryCommit, error) {
			return &github.RepositoryCommit{
				SHA: github.Ptr(sha),
				Files: []*github.CommitFile{{
					Filename:  github.Ptr("config.txt"),
					Additions: github.Ptr(1),
					Patch:     github.Ptr("@@ -0,0 +1 @@\n+secret-" + sha[0:4]),
				}},
			}, nil
		},
	}

	var order []string
	if err := s.StreamFragments(func(f Fragment) error {
		order = append(order, f.CommitSHA)
		return nil
	}); err != nil {
		t.Fatalf("StreamFragments() error = %v", err)
	}
	if len(order) != 2 || order[0] != sha1 || order[1] != sha2 {
		t.Errorf("yielded commit order = %v, want [%s %s]", order, sha1, sha2)
	}
}

// newEmptyFetchRepo initializes an empty git repository so that fetchCommits
// treats every candidate SHA as missing from the local objects.
func newEmptyFetchRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := git.PlainInit(dir, false); err != nil {
		t.Fatalf("failed to initialize a repository: %v", err)
	}
	return dir
}

// TestDanglingSourceFetchCommitsFallsBackToAPIOnFetchFailure verifies that,
// outside strict mode, a failed batch fetch is non-fatal: the whole batch is
// left missing for the GitHub API fallback and the open repository handle is
// dropped so a partially written fetch is not reused.
func TestDanglingSourceFetchCommitsFallsBackToAPIOnFetchFailure(t *testing.T) {
	dir := newEmptyFetchRepo(t)
	const sha1 = "1111111111111111111111111111111111111111"
	const sha2 = "2222222222222222222222222222222222222222"

	var calls [][]string
	s := &DanglingSource{
		ctx:      context.Background(),
		fetchDir: dir,
		fetchBatchFn: func(_ *cligit.Client, batch []string) error {
			calls = append(calls, append([]string(nil), batch...))
			return errors.New("git fetch failed")
		},
	}

	if err := s.fetchCommits([]string{sha1, sha2}); err != nil {
		t.Fatalf("fetchCommits() error = %v, want nil", err)
	}
	if len(calls) != 1 {
		t.Fatalf("fetchBatchFn called %d times, want 1 (no per-SHA retry)", len(calls))
	}
	if len(calls[0]) != 2 || calls[0][0] != sha1 || calls[0][1] != sha2 {
		t.Errorf("fetched batch = %v, want [%s %s]", calls[0], sha1, sha2)
	}
	if s.localRepo != nil {
		t.Error("localRepo must be reset after a fetch attempt, even on failure")
	}
}

// TestDanglingSourceFetchCommitsStrictErrorsIsFatal verifies that strict mode
// keeps a batch fetch failure fatal so partial results are not returned.
func TestDanglingSourceFetchCommitsStrictErrorsIsFatal(t *testing.T) {
	dir := newEmptyFetchRepo(t)
	const sha = "1111111111111111111111111111111111111111"

	var calls int
	s := &DanglingSource{
		ctx:      context.Background(),
		fetchDir: dir,
		opts:     DanglingSourceOptions{StrictErrors: true},
		fetchBatchFn: func(_ *cligit.Client, _ []string) error {
			calls++
			return errors.New("git fetch failed")
		},
	}

	err := s.fetchCommits([]string{sha})
	if err == nil {
		t.Fatal("fetchCommits() error = nil, want a fatal error in strict mode")
	}
	if calls != 1 {
		t.Errorf("fetchBatchFn called %d times, want 1", calls)
	}
}

// TestDanglingSourceFetchCommitsCanceledContextIsFatal verifies that a canceled
// context stays fatal and is not masked by the git failure it caused.
func TestDanglingSourceFetchCommitsCanceledContextIsFatal(t *testing.T) {
	dir := newEmptyFetchRepo(t)
	const sha = "1111111111111111111111111111111111111111"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &DanglingSource{
		ctx:      ctx,
		fetchDir: dir,
		fetchBatchFn: func(_ *cligit.Client, _ []string) error {
			return errors.New("git fetch failed")
		},
	}

	err := s.fetchCommits([]string{sha})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("fetchCommits() error = %v, want context.Canceled", err)
	}
}

// TestDanglingSourceStreamFragmentsFallsBackToAPIWhenFetchFails verifies the
// end-to-end degradation: when git fetch fails outside strict mode, every
// dangling commit is still read through the GitHub API and yielded in order.
func TestDanglingSourceStreamFragmentsFallsBackToAPIWhenFetchFails(t *testing.T) {
	dir := newEmptyFetchRepo(t)
	const sha1 = "1111111111111111111111111111111111111111"
	const sha2 = "2222222222222222222222222222222222222222"

	var requested []string
	s := &DanglingSource{
		ctx:      context.Background(),
		fetchDir: dir,
		listClosedPRs: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ int) ([]*github.PullRequest, error) {
			return []*github.PullRequest{{}}, nil
		},
		findDangling: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, _ []*github.PullRequest, _ dangling.DanglingOptions) ([]*dangling.DanglingCommit, error) {
			return []*dangling.DanglingCommit{{SHA: sha1}, {SHA: sha2}}, nil
		},
		fetchBatchFn: func(_ *cligit.Client, _ []string) error {
			return errors.New("git fetch failed")
		},
		getCommit: func(_ context.Context, _ *gh.GitHubClient, _ repository.Repository, sha string) (*github.RepositoryCommit, error) {
			requested = append(requested, sha)
			return &github.RepositoryCommit{
				SHA: github.Ptr(sha),
				Files: []*github.CommitFile{{
					Filename:  github.Ptr("config.txt"),
					Additions: github.Ptr(1),
					Patch:     github.Ptr("@@ -0,0 +1 @@\n+secret-" + sha[0:4]),
				}},
			}, nil
		},
	}

	var order []string
	if err := s.StreamFragments(func(f Fragment) error {
		order = append(order, f.Content)
		return nil
	}); err != nil {
		t.Fatalf("StreamFragments() error = %v", err)
	}
	if len(requested) != 2 || requested[0] != sha1 || requested[1] != sha2 {
		t.Errorf("getCommit requested = %v, want [%s %s]", requested, sha1, sha2)
	}
	if len(order) != 2 || order[0] != "secret-1111\n" || order[1] != "secret-2222\n" {
		t.Errorf("yielded fragments = %v, want [secret-1111 secret-2222]", order)
	}
}
