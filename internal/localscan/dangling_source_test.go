package localscan

import (
	"context"
	"testing"

	"github.com/go-git/go-git/v5"
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
