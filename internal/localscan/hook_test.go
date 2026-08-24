package localscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
)

func TestResolveHookNames(t *testing.T) {
	all, err := ResolveHookNames(nil)
	if err != nil {
		t.Fatalf("ResolveHookNames(nil) error = %v", err)
	}
	if len(all) != len(HookNames) {
		t.Errorf("expected %d hooks, got %v", len(HookNames), all)
	}

	if _, err := ResolveHookNames([]string{"pre-push"}); err != nil {
		t.Errorf("ResolveHookNames([pre-push]) error = %v", err)
	}
	if _, err := ResolveHookNames([]string{"post-merge"}); err == nil {
		t.Error("expected an error for an unsupported hook name")
	}
}

func TestHooksDirDefaultAndConfigured(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit() error = %v", err)
	}
	// go-git reports the worktree root with symlinks resolved (e.g. /var -> /private/var on macOS).
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}

	got, err := HooksDir(dir)
	if err != nil {
		t.Fatalf("HooksDir() error = %v", err)
	}
	if want := filepath.Join(resolved, ".git", "hooks"); got != want {
		t.Errorf("HooksDir() = %q, want %q", got, want)
	}

	cfg, err := repo.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	cfg.Raw.Section("core").SetOption("hooksPath", ".githooks")
	if err := repo.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig() error = %v", err)
	}

	got, err = HooksDir(dir)
	if err != nil {
		t.Fatalf("HooksDir() error = %v", err)
	}
	if want := filepath.Join(resolved, ".githooks"); got != want {
		t.Errorf("HooksDir() with core.hooksPath = %q, want %q", got, want)
	}
}

func TestInstallHookWritesExecutableScript(t *testing.T) {
	dir := t.TempDir()

	path, err := InstallHook(dir, "pre-commit", InstallHookOptions{})
	if err != nil {
		t.Fatalf("InstallHook() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("hook %q is not executable, mode = %v", path, info.Mode())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)
	if !strings.Contains(content, hookMarker) {
		t.Errorf("hook script does not contain the marker: %q", content)
	}
	if !strings.Contains(content, "--staged") {
		t.Errorf("pre-commit hook does not scan staged changes: %q", content)
	}

	statuses, err := HookStatuses(dir, HookNames)
	if err != nil {
		t.Fatalf("HookStatuses() error = %v", err)
	}
	want := map[string]HookState{"pre-commit": HookStateInstalled, "pre-push": HookStateNotInstalled}
	for _, s := range statuses {
		if s.State != want[s.Name] {
			t.Errorf("hook %q state = %q, want %q", s.Name, s.State, want[s.Name])
		}
	}
}

func TestInstallHookExistingUnmanaged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pre-push")
	original := "#!/bin/sh\necho custom\n"
	if err := os.WriteFile(path, []byte(original), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := InstallHook(dir, "pre-push", InstallHookOptions{}); err == nil {
		t.Fatal("expected an error when an unmanaged hook exists")
	}

	if _, err := InstallHook(dir, "pre-push", InstallHookOptions{Backup: true}); err != nil {
		t.Fatalf("InstallHook(Backup) error = %v", err)
	}
	backup, err := os.ReadFile(path + hookBackupSuffix)
	if err != nil {
		t.Fatalf("ReadFile(backup) error = %v", err)
	}
	if string(backup) != original {
		t.Errorf("backup content = %q, want %q", backup, original)
	}

	if err := os.WriteFile(path, []byte(original), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := InstallHook(dir, "pre-push", InstallHookOptions{Force: true}); err != nil {
		t.Fatalf("InstallHook(Force) error = %v", err)
	}
	state, err := hookStateAt(path)
	if err != nil {
		t.Fatalf("hookStateAt() error = %v", err)
	}
	if state != HookStateInstalled {
		t.Errorf("state after --force = %q, want %q", state, HookStateInstalled)
	}
}

func TestUninstallHook(t *testing.T) {
	dir := t.TempDir()

	removed, err := UninstallHook(dir, "pre-commit", false)
	if err != nil {
		t.Fatalf("UninstallHook() error = %v", err)
	}
	if removed {
		t.Error("expected no hook to be removed when none is installed")
	}

	if _, err := InstallHook(dir, "pre-commit", InstallHookOptions{}); err != nil {
		t.Fatalf("InstallHook() error = %v", err)
	}
	removed, err = UninstallHook(dir, "pre-commit", false)
	if err != nil {
		t.Fatalf("UninstallHook() error = %v", err)
	}
	if !removed {
		t.Error("expected the managed hook to be removed")
	}

	path := filepath.Join(dir, "pre-push")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho custom\n"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := UninstallHook(dir, "pre-push", false); err == nil {
		t.Error("expected an error when removing an unmanaged hook without --force")
	}
	if _, err := UninstallHook(dir, "pre-push", true); err != nil {
		t.Errorf("UninstallHook(force) error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected the unmanaged hook to be removed with --force")
	}
}

func TestHookStateUnmanagedForMarkerMention(t *testing.T) {
	dir := t.TempDir()
	// An unrelated hook that merely mentions the marker text (not as the
	// generated header line) must not be treated as managed.
	path := filepath.Join(dir, "pre-push")
	body := "#!/bin/sh\necho 'see gh-secure-kit:secret-scanning-local for details'\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	statuses, err := HookStatuses(dir, []string{"pre-push"})
	if err != nil {
		t.Fatalf("HookStatuses() error = %v", err)
	}
	if statuses[0].State != HookStateUnmanaged {
		t.Errorf("State = %q, want %q", statuses[0].State, HookStateUnmanaged)
	}
}

func TestInstallHookDoesNotFollowSymlink(t *testing.T) {
	hooksDir := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	// A pre-existing symlink hook pointing outside the hooks dir.
	link := filepath.Join(hooksDir, "pre-push")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Without --force the symlink is unmanaged and must be preserved.
	if _, err := InstallHook(hooksDir, "pre-push", InstallHookOptions{}); err == nil {
		t.Fatal("expected an error installing over an unmanaged symlink")
	}

	// With --force the install must replace the link, not write through it.
	if _, err := InstallHook(hooksDir, "pre-push", InstallHookOptions{Force: true}); err != nil {
		t.Fatalf("InstallHook(force) error = %v", err)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(data) != "original\n" {
		t.Errorf("symlink target was overwritten: %q", data)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Errorf("expected a regular file at the hook path, got mode %v (err %v)", info.Mode(), err)
	}
}

func TestPrePushHookScansPushedRefs(t *testing.T) {
	script, err := hookScript("pre-push")
	if err != nil {
		t.Fatalf("hookScript() error = %v", err)
	}
	if !strings.Contains(script, "read -r local_ref local_sha remote_ref remote_sha") {
		t.Error("pre-push hook does not read pushed refs from stdin")
	}
	if !strings.Contains(script, "--rev-range \"$remote_sha..$local_sha\"") {
		t.Error("pre-push hook does not scan the pushed commit range")
	}
	if !strings.Contains(script, "--rev \"$local_sha\"") {
		t.Error("pre-push hook does not handle new branches")
	}
	if !strings.Contains(script, "--remote \"$remote_name\"") {
		t.Error("pre-push hook does not scope new-branch exclusion to the destination remote")
	}
	if !strings.Contains(script, `remote_name="$1"`) {
		t.Error("pre-push hook does not capture the destination remote name")
	}
}

func TestResolveGitDirLinkedWorktreeUsesCommondir(t *testing.T) {
	base := t.TempDir()
	commonGitDir := filepath.Join(base, "maindotgit")
	worktreeAdmin := filepath.Join(commonGitDir, "worktrees", "wt1")
	if err := os.MkdirAll(worktreeAdmin, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// The per-worktree admin dir points back to the common git dir.
	if err := os.WriteFile(filepath.Join(worktreeAdmin, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatalf("write commondir: %v", err)
	}
	// The linked worktree root has a .git file pointing at its admin dir.
	wtRoot := filepath.Join(base, "wt1")
	if err := os.MkdirAll(wtRoot, 0o755); err != nil {
		t.Fatalf("mkdir wt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wtRoot, ".git"), []byte("gitdir: "+worktreeAdmin+"\n"), 0o644); err != nil {
		t.Fatalf("write .git: %v", err)
	}

	got, err := resolveGitDir(wtRoot)
	if err != nil {
		t.Fatalf("resolveGitDir() error = %v", err)
	}
	want, _ := filepath.EvalSymlinks(commonGitDir)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != want {
		t.Errorf("resolveGitDir() = %q, want common git dir %q", got, commonGitDir)
	}
}
