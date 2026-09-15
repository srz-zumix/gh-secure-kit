package localscan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureRelPathRejectsEscapes(t *testing.T) {
	tests := []struct {
		name   string
		elems  []string
		reject bool // true when the path escapes and must be rejected
	}{
		{"normal path", []string{"deadbeef", "src/main.go"}, false},
		{"nested path", []string{"deadbeef", "a/b/c.txt"}, false},
		{"parent traversal", []string{"deadbeef", "../../etc/passwd"}, true},
		{"absolute path", []string{"deadbeef", "/etc/passwd"}, false},
		{"parent traversal to root", []string{"..", ".."}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, err := secureRelPath(tt.elems...)
			if tt.reject {
				if !errors.Is(err, errPathEscapesRoot) {
					t.Fatalf("secureRelPath(%v) error = %v, want errPathEscapesRoot", tt.elems, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("secureRelPath(%v) unexpected error = %v", tt.elems, err)
			}
			if filepath.IsAbs(rel) {
				t.Fatalf("secureRelPath(%v) = %q, want a relative path", tt.elems, rel)
			}
		})
	}
}

type stubReader struct {
	contents map[string][]byte
	calls    int
}

func (r *stubReader) FileContent(commit, path string) ([]byte, error) {
	r.calls++
	if b, ok := r.contents[commit+"\x00"+path]; ok {
		return b, nil
	}
	return nil, errors.New("not found")
}

func TestDownloadFindingsWritesDedupedFiles(t *testing.T) {
	dir := t.TempDir()
	reader := &stubReader{contents: map[string][]byte{
		"abc\x00src/a.txt": []byte("secret-a"),
		"abc\x00b.txt":     []byte("secret-b"),
	}}
	findings := []Finding{
		{Commit: "abc", File: "src/a.txt"},
		{Commit: "abc", File: "src/a.txt"}, // duplicate, downloaded once
		{Commit: "abc", File: "b.txt"},
		{Commit: "", File: "skip.txt"}, // missing commit, skipped
	}

	if err := DownloadFindings(reader, findings, dir); err != nil {
		t.Fatalf("DownloadFindings() error = %v", err)
	}
	if reader.calls != 2 {
		t.Errorf("reader called %d times, want 2 (deduplicated, skips empty commit)", reader.calls)
	}

	got, err := os.ReadFile(filepath.Join(dir, "abc", "src", "a.txt"))
	if err != nil || string(got) != "secret-a" {
		t.Errorf("src/a.txt = %q, err = %v; want %q", got, err, "secret-a")
	}
	got, err = os.ReadFile(filepath.Join(dir, "abc", "b.txt"))
	if err != nil || string(got) != "secret-b" {
		t.Errorf("b.txt = %q, err = %v; want %q", got, err, "secret-b")
	}
}

func TestDownloadFindingsRejectsPathEscape(t *testing.T) {
	dir := t.TempDir()
	reader := &stubReader{contents: map[string][]byte{
		"abc\x00../../escape.txt": []byte("nope"),
	}}
	findings := []Finding{{Commit: "abc", File: "../../escape.txt"}}

	err := DownloadFindings(reader, findings, dir)
	if !errors.Is(err, errPathEscapesRoot) {
		t.Fatalf("DownloadFindings() error = %v, want errPathEscapesRoot", err)
	}
}

// TestDownloadFindingsTightensExistingFileMode verifies that overwriting a
// pre-existing world-readable file replaces it with a 0o600 file so the secret
// content does not inherit the permissive mode.
func TestDownloadFindingsTightensExistingFileMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "abc"), 0o700); err != nil {
		t.Fatalf("failed to create commit dir: %v", err)
	}
	target := filepath.Join(dir, "abc", "secret.txt")
	if err := os.WriteFile(target, []byte("stale"), 0o644); err != nil {
		t.Fatalf("failed to pre-create target: %v", err)
	}

	reader := &stubReader{contents: map[string][]byte{"abc\x00secret.txt": []byte("secret-value")}}
	if err := DownloadFindings(reader, []Finding{{Commit: "abc", File: "secret.txt"}}, dir); err != nil {
		t.Fatalf("DownloadFindings() error = %v", err)
	}

	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("failed to stat target: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("target is a symlink, want a regular file")
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("target mode = %o, want 600", perm)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "secret-value" {
		t.Errorf("target = %q, err = %v; want %q", got, err, "secret-value")
	}
}

// TestDownloadFindingsDoesNotFollowExistingSymlink verifies that a pre-existing
// symlink at the target path is replaced rather than written through, so a
// planted symlink cannot redirect the secret content to another file.
func TestDownloadFindingsDoesNotFollowExistingSymlink(t *testing.T) {
	dir := t.TempDir()
	commitDir := filepath.Join(dir, "abc")
	if err := os.MkdirAll(commitDir, 0o700); err != nil {
		t.Fatalf("failed to create commit dir: %v", err)
	}
	decoy := filepath.Join(commitDir, "decoy.txt")
	if err := os.WriteFile(decoy, []byte("decoy"), 0o644); err != nil {
		t.Fatalf("failed to create decoy: %v", err)
	}
	target := filepath.Join(commitDir, "secret.txt")
	if err := os.Symlink("decoy.txt", target); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	reader := &stubReader{contents: map[string][]byte{"abc\x00secret.txt": []byte("secret-value")}}
	if err := DownloadFindings(reader, []Finding{{Commit: "abc", File: "secret.txt"}}, dir); err != nil {
		t.Fatalf("DownloadFindings() error = %v", err)
	}

	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("failed to stat target: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("target is still a symlink, want it replaced by a regular file")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "secret-value" {
		t.Errorf("target = %q, err = %v; want %q", got, err, "secret-value")
	}
	if decoyContent, _ := os.ReadFile(decoy); string(decoyContent) != "decoy" {
		t.Errorf("decoy was modified = %q, want %q", decoyContent, "decoy")
	}
}
