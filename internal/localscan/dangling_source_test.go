package localscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

func TestDanglingSourceOpenLocalRepoBare(t *testing.T) {
	dir := t.TempDir()
	if _, err := git.PlainInit(dir, true); err != nil {
		t.Fatalf("failed to initialize a bare repository: %v", err)
	}

	s := &DanglingSource{ctx: context.Background(), fetchDir: dir}
	if _, err := s.openLocalRepo(); err != nil {
		t.Fatalf("openLocalRepo() error = %v", err)
	}
}

// TestDanglingSourceOpenLocalRepoLinkedWorktree verifies that a commit stored
// in a linked worktree, whose objects live in the shared common dir, can be
// read back. A linked worktree keeps its ".git" as a file, so opening it
// without following the commondir metadata would fail to find the objects.
func TestDanglingSourceOpenLocalRepoLinkedWorktree(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not available")
	}

	base := t.TempDir()
	mainDir := filepath.Join(base, "main")
	wtDir := filepath.Join(base, "worktree")

	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}

	run(base, "init", "--quiet", mainDir)
	run(mainDir, "config", "user.email", "test@example.com")
	run(mainDir, "config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(mainDir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	run(mainDir, "add", "a.txt")
	run(mainDir, "commit", "--quiet", "-m", "init")
	sha := run(mainDir, "rev-parse", "HEAD")
	run(mainDir, "worktree", "add", "--quiet", wtDir)

	s := &DanglingSource{ctx: context.Background(), fetchDir: wtDir}
	repo, err := s.openLocalRepo()
	if err != nil {
		t.Fatalf("openLocalRepo() error = %v", err)
	}
	if _, err := repo.CommitObject(plumbing.NewHash(sha)); err != nil {
		t.Fatalf("CommitObject(%s) error = %v", sha, err)
	}
}
