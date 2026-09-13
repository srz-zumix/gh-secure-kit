package localscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/srz-zumix/go-gh-extension/pkg/logger"
)

// FileContentReader reads the contents of a repository file at a specific
// commit. DanglingSource implements it by reading from the fetched git objects
// first and falling back to the GitHub API.
type FileContentReader interface {
	FileContent(commit, path string) ([]byte, error)
}

// errPathEscapesRoot reports that a repository path would be written outside
// the download directory.
var errPathEscapesRoot = errors.New("the path escapes the download directory")

// DownloadFindings writes each file that contains a detected secret to
// <dir>/<commit>/<path>, reading it at the dangling commit that introduced it
// through reader. A file is downloaded once even when it holds several
// findings.
func DownloadFindings(reader FileContentReader, findings []Finding, dir string) error {
	root, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve download directory %q: %w", dir, err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("failed to create download directory %q: %w", root, err)
	}
	// Confine every write to the download directory: os.Root refuses paths that
	// leave the root through "..", an absolute path, or a symlinked component,
	// so a crafted repository path cannot overwrite unrelated files even when a
	// parent directory is a symlink.
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("failed to open download directory %q: %w", root, err)
	}
	defer func() { _ = rootFS.Close() }()

	downloaded := make(map[string]bool, len(findings))
	for _, finding := range findings {
		if finding.Commit == "" || finding.File == "" {
			continue
		}
		key := finding.Commit + "\x00" + finding.File
		if downloaded[key] {
			continue
		}
		downloaded[key] = true

		rel, err := secureRelPath(finding.Commit, finding.File)
		if err != nil {
			return err
		}
		content, err := reader.FileContent(finding.Commit, finding.File)
		if err != nil {
			return fmt.Errorf("failed to read %q at commit %s: %w", finding.File, finding.Commit, err)
		}
		if parent := filepath.Dir(rel); parent != "." {
			if err := rootFS.MkdirAll(parent, 0o700); err != nil {
				return fmt.Errorf("failed to create directory for %q: %w", rel, err)
			}
		}
		if err := rootFS.WriteFile(rel, content, 0o600); err != nil {
			return fmt.Errorf("failed to write %q: %w", rel, err)
		}
		logger.Info("downloaded a file that contains a secret", "commit", finding.Commit, "file", finding.File, "path", filepath.Join(root, rel))
	}
	return nil
}

// secureRelPath joins repository-controlled path elements into a path relative
// to the download root and rejects any result that leaves it, so a crafted
// path cannot target files outside the download directory.
func secureRelPath(elems ...string) (string, error) {
	rel := filepath.Join(elems...)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("refusing to write %q: %w", filepath.Join(elems...), errPathEscapesRoot)
	}
	return rel, nil
}
