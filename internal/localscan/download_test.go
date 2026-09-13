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
