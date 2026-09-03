package localscan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/google/go-github/v90/github"
)

func TestFragmentsFromPatchKeepsNewFileLineNumbers(t *testing.T) {
	patch := "@@ -1,3 +1,5 @@\n context\n+added one\n+added two\n-removed\n context\n@@ -20,2 +22,3 @@\n keep\n+later addition\n"

	frags := fragmentsFromPatch(patch, "config.yml", "abc123", "Test", time.Time{})

	if len(frags) != 2 {
		t.Fatalf("fragments = %d, want 2", len(frags))
	}
	if frags[0].Content != "added one\nadded two\n" {
		t.Errorf("frags[0].Content = %q", frags[0].Content)
	}
	if frags[0].BaseLine != 2 {
		t.Errorf("frags[0].BaseLine = %d, want 2", frags[0].BaseLine)
	}
	if frags[1].Content != "later addition\n" {
		t.Errorf("frags[1].Content = %q", frags[1].Content)
	}
	if frags[1].BaseLine != 23 {
		t.Errorf("frags[1].BaseLine = %d, want 23", frags[1].BaseLine)
	}
	if frags[0].FilePath != "config.yml" || frags[0].CommitSHA != "abc123" {
		t.Errorf("unexpected fragment metadata: %+v", frags[0])
	}
}

func TestFragmentsForAPICommitFailsOnTruncatedDiff(t *testing.T) {
	commit := &github.RepositoryCommit{
		SHA: github.Ptr("abc123"),
		Files: []*github.CommitFile{
			{Filename: github.Ptr("huge.json"), Additions: github.Ptr(5000)},
		},
	}

	_, err := fragmentsForAPICommit(commit)
	if err == nil {
		t.Fatal("expected an error when the API omits the diff of a changed file")
	}
}

func TestFragmentsForAPICommitSkipsBinaryFile(t *testing.T) {
	commit := &github.RepositoryCommit{
		SHA: github.Ptr("abc123"),
		Files: []*github.CommitFile{
			{Filename: github.Ptr("logo.png"), Additions: github.Ptr(0)},
		},
	}

	frags, err := fragmentsForAPICommit(commit)
	if err != nil {
		t.Fatalf("fragmentsForAPICommit() error = %v", err)
	}
	if len(frags) != 0 {
		t.Errorf("fragments = %d, want 0", len(frags))
	}
}

func TestAPISourceRejectsUnsupportedTarget(t *testing.T) {
	source := NewAPISource(t.Context(), Target{Mode: TargetUncommitted}, "")

	if _, err := source.Fragments(); err == nil {
		t.Fatal("expected an error for a target the GitHub API cannot scan")
	}
}

// repoWithRemote creates a git repository at a temp dir with a single "origin"
// remote pointing at remoteURL, and returns the repository path.
func repoWithRemote(t *testing.T, remoteURL string) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}
	if remoteURL != "" {
		if _, err := repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}}); err != nil {
			t.Fatalf("failed to create remote: %v", err)
		}
	}
	return dir
}

func TestAPISourceResolveRepository(t *testing.T) {
	t.Run("repo flag wins over path remote", func(t *testing.T) {
		dir := repoWithRemote(t, "https://github.com/octocat/Hello-World.git")
		s := NewAPISource(t.Context(), Target{Mode: TargetRevRange, RepoPath: dir}, "me/mine")
		repo, err := s.resolveRepository()
		if err != nil {
			t.Fatalf("resolveRepository() error = %v", err)
		}
		if repo.Owner != "me" || repo.Name != "mine" {
			t.Fatalf("got %s/%s, want me/mine", repo.Owner, repo.Name)
		}
	})

	t.Run("inferred from https path remote", func(t *testing.T) {
		dir := repoWithRemote(t, "https://github.com/octocat/Hello-World.git")
		s := NewAPISource(t.Context(), Target{Mode: TargetRevRange, RepoPath: dir}, "")
		repo, err := s.resolveRepository()
		if err != nil {
			t.Fatalf("resolveRepository() error = %v", err)
		}
		if repo.Host != "github.com" || repo.Owner != "octocat" || repo.Name != "Hello-World" {
			t.Fatalf("got %s/%s/%s, want github.com/octocat/Hello-World", repo.Host, repo.Owner, repo.Name)
		}
	})

	t.Run("inferred from ssh path remote", func(t *testing.T) {
		dir := repoWithRemote(t, "git@github.com:octocat/Hello-World.git")
		s := NewAPISource(t.Context(), Target{Mode: TargetRevRange, RepoPath: dir}, "")
		repo, err := s.resolveRepository()
		if err != nil {
			t.Fatalf("resolveRepository() error = %v", err)
		}
		if repo.Host != "github.com" || repo.Owner != "octocat" || repo.Name != "Hello-World" {
			t.Fatalf("got %s/%s/%s, want github.com/octocat/Hello-World", repo.Host, repo.Owner, repo.Name)
		}
	})

	t.Run("inferred from a subdirectory of the repository", func(t *testing.T) {
		dir := repoWithRemote(t, "https://github.com/octocat/Hello-World.git")
		sub := filepath.Join(dir, "nested", "deeper")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}
		s := NewAPISource(t.Context(), Target{Mode: TargetRevRange, RepoPath: sub}, "")
		repo, err := s.resolveRepository()
		if err != nil {
			t.Fatalf("resolveRepository() error = %v", err)
		}
		if repo.Owner != "octocat" || repo.Name != "Hello-World" {
			t.Fatalf("got %s/%s, want octocat/Hello-World", repo.Owner, repo.Name)
		}
	})

	t.Run("no remote fails instead of guessing", func(t *testing.T) {
		dir := repoWithRemote(t, "")
		s := NewAPISource(t.Context(), Target{Mode: TargetRevRange, RepoPath: dir}, "")
		if _, err := s.resolveRepository(); err == nil {
			t.Fatal("expected an error when the path has no remote")
		}
	})

	t.Run("non-git path fails instead of using CWD", func(t *testing.T) {
		dir := t.TempDir()
		s := NewAPISource(t.Context(), Target{Mode: TargetRevRange, RepoPath: dir}, "")
		if _, err := s.resolveRepository(); err == nil {
			t.Fatal("expected an error when the path is not a git repository")
		}
	})
}

func TestAPISourceAPIRef(t *testing.T) {
	repo, dir := newTestRepo(t)
	commitFile(t, repo, dir, "a.txt", "a\n", "first")
	commitFile(t, repo, dir, "b.txt", "b\n", "second")
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("failed to resolve HEAD: %v", err)
	}
	headSHA := head.Hash().String()

	s := NewAPISource(t.Context(), Target{Mode: TargetRevRange, RepoPath: dir}, "")

	t.Run("resolves HEAD to the local checkout SHA", func(t *testing.T) {
		got, err := s.apiRef("HEAD")
		if err != nil {
			t.Fatalf("apiRef(HEAD) error = %v", err)
		}
		if got != headSHA {
			t.Fatalf("apiRef(HEAD) = %q, want %q", got, headSHA)
		}
	})

	t.Run("resolves HEAD^ to a local SHA", func(t *testing.T) {
		got, err := s.apiRef("HEAD^")
		if err != nil {
			t.Fatalf("apiRef(HEAD^) error = %v", err)
		}
		if got == headSHA || len(got) != 40 {
			t.Fatalf("apiRef(HEAD^) = %q, want the parent SHA", got)
		}
	})

	t.Run("rejects an unresolvable git-only revspec", func(t *testing.T) {
		// A repository with no such ref cannot resolve "HEAD~5" locally, and
		// the API cannot address it either.
		if _, err := s.apiRef("HEAD~5"); err == nil {
			t.Fatal("expected an error for an unresolvable git-only revspec")
		}
	})

	t.Run("passes through an API-addressable ref", func(t *testing.T) {
		// A full SHA that is not present locally is left for the API to resolve.
		const remoteSHA = "0123456789abcdef0123456789abcdef01234567"
		got, err := s.apiRef(remoteSHA)
		if err != nil {
			t.Fatalf("apiRef(remoteSHA) error = %v", err)
		}
		if got != remoteSHA {
			t.Fatalf("apiRef(remoteSHA) = %q, want %q", got, remoteSHA)
		}
	})
}

func TestAPISourceCommitSHAsBareRevisionResolvesLocally(t *testing.T) {
	repo, dir := newTestRepo(t)
	commitFile(t, repo, dir, "a.txt", "a\n", "first")
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("failed to resolve HEAD: %v", err)
	}

	// A bare revision returns a single ref without any network call, so a nil
	// client is fine here.
	s := NewAPISource(t.Context(), Target{Mode: TargetRevRange, RepoPath: dir, RevRange: "HEAD"}, "")
	shas, err := s.commitSHAs(nil, repository.Repository{})
	if err != nil {
		t.Fatalf("commitSHAs() error = %v", err)
	}
	if len(shas) != 1 || shas[0] != head.Hash().String() {
		t.Fatalf("commitSHAs() = %v, want [%s]", shas, head.Hash().String())
	}
}

type stubSource struct {
	frags []Fragment
	err   error
}

func (s stubSource) Fragments() ([]Fragment, error) { return s.frags, s.err }

func TestFallbackSourceUsesFallbackOnlyWhenLocalContentIsMissing(t *testing.T) {
	fallback := stubSource{frags: []Fragment{{Content: "from fallback\n"}}}

	missing := NewFallbackSource(stubSource{err: ErrLocalContentMissing}, fallback)
	frags, err := missing.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if len(frags) != 1 || frags[0].Content != "from fallback\n" {
		t.Errorf("fragments = %+v, want the fallback result", frags)
	}

	other := errors.New("boom")
	broken := NewFallbackSource(stubSource{err: other}, fallback)
	if _, err := broken.Fragments(); !errors.Is(err, other) {
		t.Errorf("Fragments() error = %v, want the primary error", err)
	}
}
