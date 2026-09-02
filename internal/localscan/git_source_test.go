package localscan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// newTestRepo creates a bare "remote" repository and a local working
// repository with "origin" pointing to it.
func newTestRepo(t *testing.T) (*git.Repository, string) {
	t.Helper()
	remoteDir := t.TempDir()
	if _, err := git.PlainInit(remoteDir, true); err != nil {
		t.Fatalf("failed to init bare remote: %v", err)
	}

	localDir := t.TempDir()
	repo, err := git.PlainInit(localDir, false)
	if err != nil {
		t.Fatalf("failed to init local repo: %v", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteDir},
	}); err != nil {
		t.Fatalf("failed to create remote: %v", err)
	}
	return repo, localDir
}

func commitFile(t *testing.T, repo *git.Repository, dir, name, content, message string) {
	t.Helper()
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("failed to open worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	if _, err := wt.Add(name); err != nil {
		t.Fatalf("failed to add file: %v", err)
	}
	_, err = wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "test@example.com"},
	})
	if err != nil {
		t.Fatalf("failed to commit: %v", err)
	}
}

func TestGitSourceUnpushedOnlyScansUnpushedCommits(t *testing.T) {
	repo, dir := newTestRepo(t)

	commitFile(t, repo, dir, "README.md", "hello, pushed content\n", "initial commit")
	if err := repo.Push(&git.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("failed to push initial commit: %v", err)
	}

	commitFile(t, repo, dir, "secret.txt", "ghp_"+repeatChar("a1B2c3", 6)+"\n", "add secret")

	src := NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir, MaxCommits: 100})
	frags, err := src.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}

	foundSecretFile := false
	for _, f := range frags {
		if f.FilePath == "README.md" {
			t.Errorf("pushed commit content should not be scanned, got fragment for %q", f.FilePath)
		}
		if f.FilePath == "secret.txt" {
			foundSecretFile = true
		}
	}
	if !foundSecretFile {
		t.Fatalf("expected fragment for unpushed secret.txt, got %+v", frags)
	}

	scanner, err := NewScanner(nil, true)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	var findings []Finding
	for _, f := range frags {
		findings = append(findings, scanner.ScanFragment(f)...)
	}
	if len(findings) != 1 || findings[0].PatternID != "github_personal_access_token" {
		t.Fatalf("expected exactly one github_personal_access_token finding, got %+v", findings)
	}
}

func TestGitSourceRevRangeSingleCommit(t *testing.T) {
	repo, dir := newTestRepo(t)

	commitFile(t, repo, dir, "README.md", "hello\n", "initial commit")
	commitFile(t, repo, dir, "file2.txt", "second\n", "second commit")

	src := NewGitSource(Target{Mode: TargetRevRange, RepoPath: dir, RevRange: "HEAD"})
	frags, err := src.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	for _, f := range frags {
		if f.FilePath != "file2.txt" {
			t.Errorf("expected only file2.txt from HEAD commit, got %q", f.FilePath)
		}
	}
}

func TestGitSourceStagedAndUncommitted(t *testing.T) {
	repo, dir := newTestRepo(t)
	commitFile(t, repo, dir, "README.md", "hello\n", "initial commit")

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("failed to open worktree: %v", err)
	}

	// Staged change.
	if err := os.WriteFile(filepath.Join(dir, "staged.txt"), []byte("staged content\n"), 0o600); err != nil {
		t.Fatalf("failed to write staged file: %v", err)
	}
	if _, err := wt.Add("staged.txt"); err != nil {
		t.Fatalf("failed to stage file: %v", err)
	}

	// Uncommitted (untracked) change.
	if err := os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("untracked content\n"), 0o600); err != nil {
		t.Fatalf("failed to write untracked file: %v", err)
	}

	stagedSrc := NewGitSource(Target{Mode: TargetStaged, RepoPath: dir})
	stagedFrags, err := stagedSrc.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if !hasFile(stagedFrags, "staged.txt") {
		t.Errorf("expected staged.txt in staged fragments, got %+v", stagedFrags)
	}

	uncommittedSrc := NewGitSource(Target{Mode: TargetUncommitted, RepoPath: dir})
	uncommittedFrags, err := uncommittedSrc.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if !hasFile(uncommittedFrags, "untracked.txt") {
		t.Errorf("expected untracked.txt in uncommitted fragments, got %+v", uncommittedFrags)
	}
}

func hasFile(frags []Fragment, path string) bool {
	for _, f := range frags {
		if f.FilePath == path {
			return true
		}
	}
	return false
}

func TestGitSourceCommitReportsCorrectLineNumbers(t *testing.T) {
	repo, dir := newTestRepo(t)

	// Base file with several lines, all pushed so only the later change is
	// considered unpushed.
	base := "line1\nline2\nline3\nline4\nline5\n"
	commitFile(t, repo, dir, "app.txt", base, "base")
	if err := repo.Push(&git.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("failed to push: %v", err)
	}

	// Append a secret on line 6, keeping earlier lines unchanged so the diff
	// hunk starts partway through the file.
	secret := "ghp_" + repeatChar("a1B2c3", 6)
	commitFile(t, repo, dir, "app.txt", base+secret+"\n", "add secret at line 6")

	src := NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir, MaxCommits: 100})
	frags, err := src.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}

	scanner, err := NewScanner(nil, true)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	var findings []Finding
	for _, f := range frags {
		findings = append(findings, scanner.ScanFragment(f)...)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].StartLine != 6 {
		t.Errorf("StartLine = %d, want 6 (secret added on line 6)", findings[0].StartLine)
	}
}

func TestGitSourceStagedUnbornHead(t *testing.T) {
	repo, dir := newTestRepo(t)

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("failed to open worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "staged.txt"), []byte("staged content\n"), 0o600); err != nil {
		t.Fatalf("failed to write staged file: %v", err)
	}
	if _, err := wt.Add("staged.txt"); err != nil {
		t.Fatalf("failed to stage file: %v", err)
	}

	// No commit exists yet (unborn HEAD); staged scan must still succeed.
	src := NewGitSource(Target{Mode: TargetStaged, RepoPath: dir})
	frags, err := src.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if !hasFile(frags, "staged.txt") {
		t.Errorf("expected staged.txt in fragments, got %+v", frags)
	}
}

func TestGitSourceMaxCommitsTruncationErrors(t *testing.T) {
	repo, dir := newTestRepo(t)
	commitFile(t, repo, dir, "a.txt", "one\n", "c1")
	commitFile(t, repo, dir, "b.txt", "two\n", "c2")
	commitFile(t, repo, dir, "c.txt", "three\n", "c3")

	// Three unpushed commits but a cap of 2 must fail rather than silently
	// scanning an incomplete history.
	src := NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir, MaxCommits: 2})
	if _, err := src.Fragments(); err == nil {
		t.Fatal("expected an error when the commit cap is exceeded, got nil")
	}

	// At exactly the number of commits, the scan must succeed.
	src = NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir, MaxCommits: 3})
	if _, err := src.Fragments(); err != nil {
		t.Fatalf("expected success at exactly the cap, got %v", err)
	}
}

func TestGitSourceUnbornHeadUnpushed(t *testing.T) {
	_, dir := newTestRepo(t)
	// Fresh repo, no commits: the default unpushed scan should succeed empty.
	src := NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir})
	frags, err := src.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if len(frags) != 0 {
		t.Errorf("expected no fragments for an unborn HEAD, got %+v", frags)
	}
}

func TestGitSourceRevOverridesUnpushedStart(t *testing.T) {
	repo, dir := newTestRepo(t)
	commitFile(t, repo, dir, "base.txt", "base\n", "base")
	if err := repo.Push(&git.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("failed to push: %v", err)
	}
	commitFile(t, repo, dir, "new.txt", "brand new\n", "new commit")
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("Head() error = %v", err)
	}

	// Scan reachable-from-HEAD-not-remote using an explicit rev instead of HEAD.
	src := NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir, Rev: head.Hash().String()})
	frags, err := src.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if !hasFile(frags, "new.txt") || hasFile(frags, "base.txt") {
		t.Errorf("expected only new.txt, got %+v", frags)
	}
}

func TestSplitRevRangeRejectsTripleDot(t *testing.T) {
	if _, _, _, err := splitRevRange("main...HEAD"); err == nil {
		t.Error("expected an error for a three-dot range, got nil")
	}
}

// TestGitSourceRemoteScopesExclusionToDestination verifies that a commit
// present only on a different remote is still scanned when pushing to a new
// destination: --remote must exclude only that destination's tracking refs,
// not every remote.
func TestGitSourceRemoteScopesExclusionToDestination(t *testing.T) {
	repo, dir := newTestRepo(t)

	// Base commit is on origin (the push destination).
	commitFile(t, repo, dir, "base.txt", "base\n", "base")
	if err := repo.Push(&git.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("failed to push to origin: %v", err)
	}

	// A second commit carrying a secret lives only on a different remote.
	privateDir := t.TempDir()
	if _, err := git.PlainInit(privateDir, true); err != nil {
		t.Fatalf("failed to init private remote: %v", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{
		Name: "private",
		URLs: []string{privateDir},
	}); err != nil {
		t.Fatalf("failed to create private remote: %v", err)
	}
	commitFile(t, repo, dir, "secret.txt", "ghp_"+repeatChar("a1B2c3", 6)+"\n", "add secret")
	if err := repo.Push(&git.PushOptions{RemoteName: "private"}); err != nil {
		t.Fatalf("failed to push to private: %v", err)
	}

	// Excluding every remote hides the secret (it is on "private").
	allRemotes := NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir, MaxCommits: 100})
	if frags, err := allRemotes.Fragments(); err != nil {
		t.Fatalf("Fragments() error = %v", err)
	} else if hasFile(frags, "secret.txt") {
		t.Fatalf("all-remotes exclusion should not scan the private commit, got %+v", frags)
	}

	// Scoping to the "origin" destination still scans the commit that only
	// exists on "private" before it reaches origin.
	scoped := NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir, Remote: "origin", MaxCommits: 100})
	frags, err := scoped.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if !hasFile(frags, "secret.txt") {
		t.Fatalf("expected the private-only commit to be scanned for destination origin, got %+v", frags)
	}
	if hasFile(frags, "base.txt") {
		t.Errorf("origin content should be excluded, got %+v", frags)
	}
}

// TestGitSourceReportsLocalContentMissing verifies that GitSource wraps
// ErrLocalContentMissing whenever the local repository cannot answer the
// request, so FallbackSource can switch to the GitHub API.
func TestGitSourceReportsLocalContentMissing(t *testing.T) {
	t.Run("no repository", func(t *testing.T) {
		dir := t.TempDir()
		src := NewGitSource(Target{Mode: TargetUnpushed, RepoPath: dir, MaxCommits: 100})
		_, err := src.Fragments()
		if !errors.Is(err, ErrLocalContentMissing) {
			t.Fatalf("expected ErrLocalContentMissing, got %v", err)
		}
	})

	repo, dir := newTestRepo(t)
	commitFile(t, repo, dir, "README.md", "hello\n", "initial commit")

	revRangeCases := []struct {
		name     string
		revRange string
	}{
		{name: "missing range end", revRange: "HEAD..does-not-exist"},
		{name: "missing explicit range start", revRange: "does-not-exist..HEAD"},
	}
	for _, tc := range revRangeCases {
		t.Run(tc.name, func(t *testing.T) {
			src := NewGitSource(Target{Mode: TargetRevRange, RepoPath: dir, RevRange: tc.revRange, MaxCommits: 100})
			_, err := src.Fragments()
			if !errors.Is(err, ErrLocalContentMissing) {
				t.Fatalf("expected ErrLocalContentMissing, got %v", err)
			}
		})
	}
}

// TestGitSourceShallowCheckoutReportsLocalContentMissing verifies that a
// commit whose parent is absent in a shallow checkout is reported as missing
// local content rather than surfacing as an unrelated error.
func TestGitSourceShallowCheckoutReportsLocalContentMissing(t *testing.T) {
	repo, dir := newTestRepo(t)
	commitFile(t, repo, dir, "base.txt", "base\n", "base commit")
	commitFile(t, repo, dir, "top.txt", "top\n", "top commit")
	if err := repo.Push(&git.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("failed to push commits: %v", err)
	}

	remoteURL := ""
	remotes, err := repo.Remotes()
	if err != nil {
		t.Fatalf("failed to list remotes: %v", err)
	}
	for _, r := range remotes {
		if r.Config().Name == "origin" {
			remoteURL = r.Config().URLs[0]
		}
	}

	shallowDir := t.TempDir()
	if _, err := git.PlainClone(shallowDir, false, &git.CloneOptions{
		URL:   remoteURL,
		Depth: 1,
	}); err != nil {
		t.Fatalf("failed to shallow clone: %v", err)
	}

	// Scanning "HEAD" needs "HEAD^", which is beyond the shallow boundary.
	src := NewGitSource(Target{Mode: TargetRevRange, RepoPath: shallowDir, RevRange: "HEAD", MaxCommits: 100})
	if _, err := src.Fragments(); !errors.Is(err, ErrLocalContentMissing) {
		t.Fatalf("expected ErrLocalContentMissing, got %v", err)
	}
}
