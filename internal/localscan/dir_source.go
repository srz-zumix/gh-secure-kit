package localscan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DirSource scans plain files under a directory without using git.
type DirSource struct {
	Target Target
}

// NewDirSource creates a DirSource for the given target.
func NewDirSource(t Target) *DirSource {
	return &DirSource{Target: t}
}

// Fragments implements Source.
func (s *DirSource) Fragments() ([]Fragment, error) {
	root := s.Target.RepoPath
	var frags []Fragment
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		if isBinaryString(string(data)) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		frags = append(frags, Fragment{
			Content:  string(data),
			FilePath: rel,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %q: %w", root, err)
	}
	return frags, nil
}
