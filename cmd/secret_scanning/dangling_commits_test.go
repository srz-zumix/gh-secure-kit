package secretscanning

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSecureRelPathRejectsEscapes(t *testing.T) {
	tests := []struct {
		name  string
		elems []string
		want  bool // true when the path escapes and must be rejected
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
			if tt.want {
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
