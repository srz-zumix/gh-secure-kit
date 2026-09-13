package localscan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	cligit "github.com/cli/cli/v2/git"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/gh-diet-kit/pkg/dangling"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/gitutil"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
)

// DanglingReachabilityCheckValues lists the accepted reachability check modes,
// so command flags can offer them without importing the detection package.
var DanglingReachabilityCheckValues = dangling.ReachabilityCheckModeValues

// DanglingReachabilityCheckNone is the default reachability check mode, which
// reports candidate commits without any extra verification.
var DanglingReachabilityCheckNone = string(dangling.ReachabilityCheckNone)

// DanglingSourceOptions selects which dangling commits are scanned and how
// they are discovered.
type DanglingSourceOptions struct {
	// Local discovers commits that are unreachable in the local clone and
	// still exist on the remote, instead of inspecting pull requests.
	Local bool
	// NoReflogs ignores reflog entries when determining local reachability.
	// It only applies to Local.
	NoReflogs bool
	// PRNumbers restricts the inspected pull requests. When empty, every
	// closed pull request is inspected, up to Limit.
	PRNumbers []int
	// Limit caps the number of closed pull requests to inspect. A negative
	// value means unlimited.
	Limit int
	// NoSquashMerge disables detection of commits left behind by squash or
	// rebase merges.
	NoSquashMerge bool
	// NoForcePush disables detection of commits dropped by a force-push on a
	// pull request head branch.
	NoForcePush bool
	// NoClosed disables detection of commits from closed unmerged pull
	// requests.
	NoClosed bool
	// ReachabilityCheck verifies that a candidate commit really is unreachable
	// before it is scanned. An empty value skips the check.
	ReachabilityCheck string
	// StrictErrors fails on the first API or git error instead of logging it
	// and continuing with partial results.
	StrictErrors bool
	// NoCache disables the per-pull-request detection cache.
	NoCache bool
	// ClearCache clears the detection cache before discovering commits.
	ClearCache bool
	// NoFetch reads the commit contents through the GitHub API instead of
	// fetching the commits into a local git repository.
	NoFetch bool
	// PRConcurrency caps how many pull requests are inspected concurrently.
	// A value <= 0 uses the package default.
	PRConcurrency int
}

// fetchBatchSize caps how many commits a single git fetch asks for, to keep
// the command line within the limits of the platform.
const fetchBatchSize = 50

// fetchAttempts and fetchRetryDelay control how a failed git fetch is retried;
// the delay grows with each attempt.
const (
	fetchAttempts   = 3
	fetchRetryDelay = 2 * time.Second
)

// DanglingSource produces fragments from commits that are no longer reachable
// from any branch or tag ref but are still served by the GitHub API, such as
// the commits left behind by a squash merge or a force-push.
type DanglingSource struct {
	ctx    context.Context
	client *gh.GitHubClient
	repo   repository.Repository
	opts   DanglingSourceOptions
	// fetchDir is the git repository commits are fetched into, and tempDir is
	// set when that repository is a throwaway one this source created.
	fetchDir  string
	tempDir   string
	localRepo *git.Repository
}

// NewDanglingSource creates a DanglingSource for the given repository.
func NewDanglingSource(ctx context.Context, client *gh.GitHubClient, repo repository.Repository, opts DanglingSourceOptions) *DanglingSource {
	return &DanglingSource{ctx: ctx, client: client, repo: repo, opts: opts}
}

// Fragments implements Source.
func (s *DanglingSource) Fragments() ([]Fragment, error) {
	shas, err := s.commitSHAs()
	if err != nil {
		return nil, err
	}
	logger.Debug("scanning dangling commits", "repository", s.repo.Owner+"/"+s.repo.Name, "local", s.opts.Local, "commits", len(shas))
	defer s.cleanup()

	if !s.opts.NoFetch {
		if err := s.fetchCommits(shas); err != nil {
			return nil, err
		}
	}

	var frags []Fragment
	for _, sha := range shas {
		if err := s.ctx.Err(); err != nil {
			return nil, err
		}
		f, err := s.commitFragments(sha)
		if err != nil {
			return nil, err
		}
		frags = append(frags, f...)
	}
	return frags, nil
}

// commitFragments reads a commit from the fetched git objects, falling back to
// the GitHub API when the local repository does not hold it.
func (s *DanglingSource) commitFragments(sha string) ([]Fragment, error) {
	if !s.opts.NoFetch {
		frags, err := s.localCommitFragments(sha)
		if errors.Is(err, dotgit.ErrPackfileNotFound) {
			// Another process repacked the repository, so the open one lists
			// packfiles that no longer exist; reopen it and read the commit again.
			logger.Debug("the git repository was repacked while scanning, reopening it", "commit", sha, "dir", s.fetchDir)
			s.localRepo = nil
			frags, err = s.localCommitFragments(sha)
		}
		if err == nil {
			return frags, nil
		}
		if !errors.Is(err, ErrLocalContentMissing) {
			return nil, err
		}
		logger.Debug("the fetched repository does not hold the dangling commit, reading it through the GitHub API", "commit", sha, "reason", err)
	}

	commit, err := gh.GetCommit(s.ctx, s.client, s.repo, sha)
	if err != nil {
		return nil, fmt.Errorf("failed to read dangling commit %s through the GitHub API: %w", sha, err)
	}
	return fragmentsForAPICommit(commit)
}

// localCommitFragments reads a commit from the git objects of the fetch
// repository.
func (s *DanglingSource) localCommitFragments(sha string) ([]Fragment, error) {
	commit, err := s.localCommit(sha)
	if err != nil {
		return nil, err
	}
	return fragmentsForCommit(commit)
}

// localCommit returns a commit from the fetch repository. It reports
// ErrLocalContentMissing when the commit, or the parent its diff is computed
// against, was not fetched.
func (s *DanglingSource) localCommit(sha string) (*object.Commit, error) {
	repo, err := s.openLocalRepo()
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(plumbing.NewHash(sha))
	if err != nil {
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			return nil, fmt.Errorf("%w: commit %s is not in %q", ErrLocalContentMissing, sha, s.fetchDir)
		}
		return nil, fmt.Errorf("failed to read commit %s from %q: %w", sha, s.fetchDir, err)
	}
	if commit.NumParents() > 0 {
		if _, err := commit.Parent(0); err != nil {
			return nil, fmt.Errorf("%w: the parent of commit %s is not in %q", ErrLocalContentMissing, sha, s.fetchDir)
		}
	}
	return commit, nil
}

// fetchCommits downloads the commits that the fetch repository does not hold
// yet, so they can be scanned from git objects instead of the GitHub API.
func (s *DanglingSource) fetchCommits(shas []string) error {
	if len(shas) == 0 {
		return nil
	}
	if _, err := s.localRepoDir(); err != nil {
		return err
	}

	missing := make([]string, 0, len(shas))
	for _, sha := range shas {
		if _, err := s.localCommit(sha); err != nil {
			if !errors.Is(err, ErrLocalContentMissing) {
				return err
			}
			missing = append(missing, sha)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	logger.Debug("fetching dangling commits", "dir", s.fetchDir, "commits", len(missing))
	client := gitutil.NewClientWithDir(s.fetchDir)
	for start := 0; start < len(missing); start += fetchBatchSize {
		end := min(start+fetchBatchSize, len(missing))
		batch := missing[start:end]
		if err := s.fetchBatch(client, batch); err != nil {
			return fmt.Errorf("failed to fetch %d dangling commit(s) into %q: %w; pass --no-fetch to read them through the GitHub API instead", len(batch), s.fetchDir, err)
		}
	}
	// The fetch added objects the already opened repository may not see.
	s.localRepo = nil
	return nil
}

// fetchBatch fetches one batch of commits, retrying because the GitHub git
// endpoint intermittently drops large fetches.
func (s *DanglingSource) fetchBatch(client *cligit.Client, batch []string) error {
	// Auto gc runs detached and would repack the objects out from under the
	// scan, so it is disabled for the fetch.
	args := append([]string{"-c", "gc.auto=0", "-c", "maintenance.auto=false", "fetch", "--no-tags", "--quiet", s.cloneURL()}, batch...)
	var err error
	for attempt := 1; ; attempt++ {
		var cmd *cligit.Command
		cmd, err = client.AuthenticatedCommand(s.ctx, cligit.AllMatchingCredentialsPattern, args...)
		if err == nil {
			_, err = cmd.Output()
		}
		if err == nil || attempt >= fetchAttempts {
			return err
		}
		logger.Debug("retrying the git fetch of dangling commits", "attempt", attempt, "commits", len(batch), "error", err)
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(time.Duration(attempt) * fetchRetryDelay):
		}
	}
}

// openLocalRepo opens the fetch repository, creating it if needed.
func (s *DanglingSource) openLocalRepo() (*git.Repository, error) {
	if s.localRepo != nil {
		return s.localRepo, nil
	}
	dir, err := s.localRepoDir()
	if err != nil {
		return nil, err
	}
	// The directory is either a checkout toplevel or a bare repository this
	// source created, so parent directories must not be searched.
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open the git repository at %q: %w", dir, err)
	}
	s.localRepo = repo
	return repo, nil
}

// localRepoDir returns the git repository to fetch commits into: the current
// checkout when it is a clone of the scanned repository, otherwise a temporary
// repository.
func (s *DanglingSource) localRepoDir() (string, error) {
	if s.fetchDir != "" {
		return s.fetchDir, nil
	}
	if dir, err := gitutil.NewClient().ToplevelDir(s.ctx); err == nil {
		if s.checkoutMatchesRepo() {
			s.fetchDir = dir
			return dir, nil
		}
		// Fetching into an unrelated checkout would grow it by the whole
		// history of the scanned repository.
		logger.Debug("the current checkout is not a clone of the scanned repository, using a temporary one", "dir", dir, "repository", s.repo.Owner+"/"+s.repo.Name)
	}

	dir, err := os.MkdirTemp("", "gh-secure-kit-dangling-")
	if err != nil {
		return "", fmt.Errorf("failed to create a temporary directory to fetch dangling commits into: %w", err)
	}
	cmd, err := gitutil.NewClientWithDir(dir).Command(s.ctx, "init", "--bare", "--quiet")
	if err == nil {
		_, err = cmd.Output()
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("failed to initialize a temporary git repository to fetch dangling commits into: %w", err)
	}
	s.tempDir = dir
	s.fetchDir = dir
	logger.Debug("fetching dangling commits into a temporary repository", "dir", dir)
	return dir, nil
}

// checkoutMatchesRepo reports whether a remote of the current checkout points
// at the scanned repository.
func (s *DanglingSource) checkoutMatchesRepo() bool {
	remotes, err := gitutil.NewClient().Remotes(s.ctx)
	if err != nil {
		return false
	}
	for _, remote := range remotes {
		for _, u := range []*url.URL{remote.FetchURL, remote.PushURL} {
			if u == nil {
				continue
			}
			parsed, err := repository.Parse(u.String())
			if err != nil {
				continue
			}
			if !strings.EqualFold(parsed.Owner, s.repo.Owner) || !strings.EqualFold(parsed.Name, s.repo.Name) {
				continue
			}
			if s.repo.Host == "" || strings.EqualFold(parsed.Host, s.repo.Host) {
				return true
			}
		}
	}
	return false
}

// cloneURL is the git URL commits are fetched from.
func (s *DanglingSource) cloneURL() string {
	host := s.repo.Host
	if host == "" {
		host = "github.com"
	}
	return fmt.Sprintf("https://%s/%s/%s.git", host, s.repo.Owner, s.repo.Name)
}

// cleanup removes the temporary repository, if one was created.
func (s *DanglingSource) cleanup() {
	if s.tempDir == "" {
		return
	}
	if err := os.RemoveAll(s.tempDir); err != nil {
		logger.Debug("failed to remove the temporary repository", "dir", s.tempDir, "error", err)
	}
	s.tempDir = ""
	s.fetchDir = ""
	s.localRepo = nil
}

// commitSHAs discovers the dangling commits to scan, oldest first and without
// duplicates.
func (s *DanglingSource) commitSHAs() ([]string, error) {
	var commits []*dangling.DanglingCommit
	var err error
	if s.opts.Local {
		commits, err = s.localDanglingCommits()
	} else {
		commits, err = s.pullRequestDanglingCommits()
	}
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(commits))
	shas := make([]string, 0, len(commits))
	for _, c := range commits {
		if c.SHA == "" || seen[c.SHA] {
			continue
		}
		seen[c.SHA] = true
		shas = append(shas, c.SHA)
	}
	return shas, nil
}

// localDanglingCommits returns the commits that no local ref reaches but that
// the remote repository still serves.
func (s *DanglingSource) localDanglingCommits() ([]*dangling.DanglingCommit, error) {
	unreachable, err := gitutil.ListUnreachableCommits(s.ctx, s.opts.NoReflogs)
	if err != nil {
		return nil, fmt.Errorf("failed to list the commits that are unreachable in the local repository: %w", err)
	}
	commits, err := dangling.FindLocalDanglingCommitsOnRemote(s.ctx, s.client, s.repo, unreachable)
	if err != nil {
		return nil, fmt.Errorf("failed to check the locally unreachable commits against the remote: %w", err)
	}
	return commits, nil
}

// pullRequestDanglingCommits returns the commits that pull request history
// left behind, e.g. by a squash merge, a force-push, or a closed pull request.
func (s *DanglingSource) pullRequestDanglingCommits() ([]*dangling.DanglingCommit, error) {
	prs, err := s.pullRequests()
	if err != nil {
		return nil, err
	}
	logger.Debug("inspecting pull requests for dangling commits", "pull_requests", len(prs))

	opts := dangling.DanglingOptions{
		DisableSquashRebase: s.opts.NoSquashMerge,
		DisableForcePush:    s.opts.NoForcePush,
		DisableClosed:       s.opts.NoClosed,
		ReachabilityCheck:   dangling.ReachabilityCheckMode(s.opts.ReachabilityCheck),
		StrictErrors:        s.opts.StrictErrors,
		NoCache:             s.opts.NoCache,
		ClearCache:          s.opts.ClearCache,
		PRConcurrency:       s.opts.PRConcurrency,
		// Blob sizes are irrelevant to a secret scan and cost extra API calls.
		NoBlobSize: true,
	}
	commits, err := dangling.FindDanglingCommits(s.ctx, s.client, s.repo, prs, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to find dangling commits: %w", err)
	}
	return commits, nil
}

// pullRequests returns the pull requests to inspect: the explicitly requested
// ones, or every closed pull request up to the configured limit.
func (s *DanglingSource) pullRequests() ([]*github.PullRequest, error) {
	if len(s.opts.PRNumbers) > 0 {
		prs, err := dangling.GetPRsByNumbers(s.ctx, s.client, s.repo, s.opts.PRNumbers)
		if err != nil {
			return nil, fmt.Errorf("failed to get the requested pull requests: %w", err)
		}
		return prs, nil
	}
	prs, err := dangling.ListClosedPRs(s.ctx, s.client, s.repo, s.opts.Limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list the closed pull requests: %w", err)
	}
	return prs, nil
}
