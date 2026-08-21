package localscan

import (
	"fmt"
	"io"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// GitSource produces fragments from a local git repository according to the
// selected Target mode.
type GitSource struct {
	Target Target
}

// NewGitSource creates a GitSource for the given target.
func NewGitSource(t Target) *GitSource {
	return &GitSource{Target: t}
}

// Fragments implements Source.
func (s *GitSource) Fragments() ([]Fragment, error) {
	repo, err := git.PlainOpenWithOptions(s.Target.RepoPath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open git repository at %q: %w", s.Target.RepoPath, err)
	}

	switch s.Target.Mode {
	case TargetUnpushed:
		return s.scanCommits(repo, "")
	case TargetRevRange:
		return s.scanCommits(repo, s.Target.RevRange)
	case TargetStaged:
		return s.scanStaged(repo)
	case TargetUncommitted:
		return s.scanUncommitted(repo)
	default:
		return nil, fmt.Errorf("unsupported git scan target mode %q", s.Target.Mode)
	}
}

// scanCommits collects the commits to scan (either unpushed commits when
// revRange is empty, or the given rev-range) and returns their added content.
func (s *GitSource) scanCommits(repo *git.Repository, revRange string) ([]Fragment, error) {
	startHash, excludeSet, err := s.resolveCommitRange(repo, revRange)
	if err != nil {
		return nil, err
	}

	commits, err := collectCommits(repo, startHash, excludeSet, s.Target.MaxCommits)
	if err != nil {
		return nil, err
	}

	var frags []Fragment
	for _, c := range commits {
		f, err := fragmentsForCommit(c)
		if err != nil {
			return nil, err
		}
		frags = append(frags, f...)
	}
	return frags, nil
}

// resolveCommitRange resolves the starting commit and the set of ancestor
// commits to exclude from the walk.
func (s *GitSource) resolveCommitRange(repo *git.Repository, revRange string) (plumbing.Hash, map[plumbing.Hash]bool, error) {
	if revRange == "" {
		head, err := repo.Head()
		if err != nil {
			return plumbing.ZeroHash, nil, fmt.Errorf("failed to resolve HEAD: %w", err)
		}

		var remoteTips []plumbing.Hash
		refs, err := repo.References()
		if err != nil {
			return plumbing.ZeroHash, nil, fmt.Errorf("failed to list references: %w", err)
		}
		err = refs.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().IsRemote() {
				remoteTips = append(remoteTips, ref.Hash())
			}
			return nil
		})
		if err != nil {
			return plumbing.ZeroHash, nil, fmt.Errorf("failed to iterate references: %w", err)
		}

		exclude, err := reachableSet(repo, remoteTips)
		if err != nil {
			return plumbing.ZeroHash, nil, err
		}
		return head.Hash(), exclude, nil
	}

	fromRev, toRev, err := splitRevRange(revRange)
	if err != nil {
		return plumbing.ZeroHash, nil, err
	}

	toHash, err := repo.ResolveRevision(plumbing.Revision(toRev))
	if err != nil {
		return plumbing.ZeroHash, nil, fmt.Errorf("failed to resolve revision %q: %w", toRev, err)
	}

	var exclude map[plumbing.Hash]bool
	if fromHash, err := repo.ResolveRevision(plumbing.Revision(fromRev)); err == nil {
		exclude, err = reachableSet(repo, []plumbing.Hash{*fromHash})
		if err != nil {
			return plumbing.ZeroHash, nil, err
		}
	}
	return *toHash, exclude, nil
}

// splitRevRange splits a "A..B" range into its endpoints. A bare revision
// "B" is treated as the single-commit range "B^..B".
func splitRevRange(revRange string) (from, to string, err error) {
	if idx := strings.Index(revRange, ".."); idx >= 0 {
		from = strings.TrimSuffix(revRange[:idx], ".")
		to = strings.TrimPrefix(revRange[idx+2:], ".")
		if from == "" {
			return "", "", fmt.Errorf("invalid rev-range %q: missing start revision", revRange)
		}
		if to == "" {
			to = "HEAD"
		}
		return from, to, nil
	}
	return revRange + "^", revRange, nil
}

// reachableSet returns the set of commit hashes reachable from tips
// (inclusive), used as the exclusion boundary for a commit walk.
func reachableSet(repo *git.Repository, tips []plumbing.Hash) (map[plumbing.Hash]bool, error) {
	seen := make(map[plumbing.Hash]bool)
	queue := append([]plumbing.Hash{}, tips...)
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		if seen[h] {
			continue
		}
		seen[h] = true
		c, err := repo.CommitObject(h)
		if err != nil {
			continue
		}
		for _, p := range c.ParentHashes {
			if !seen[p] {
				queue = append(queue, p)
			}
		}
	}
	return seen, nil
}

// collectCommits walks ancestors of start, stopping at commits present in
// exclude, up to maxCommits results (0 means unlimited).
func collectCommits(repo *git.Repository, start plumbing.Hash, exclude map[plumbing.Hash]bool, maxCommits int) ([]*object.Commit, error) {
	var result []*object.Commit
	visited := make(map[plumbing.Hash]bool)
	queue := []plumbing.Hash{start}
	for len(queue) > 0 {
		if maxCommits > 0 && len(result) >= maxCommits {
			break
		}
		h := queue[0]
		queue = queue[1:]
		if visited[h] || exclude[h] {
			continue
		}
		visited[h] = true
		c, err := repo.CommitObject(h)
		if err != nil {
			return nil, fmt.Errorf("failed to load commit %s: %w", h, err)
		}
		result = append(result, c)
		queue = append(queue, c.ParentHashes...)
	}
	return result, nil
}

// fragmentsForCommit returns the added content of a commit: the full tree
// for a root commit, or the added diff hunks against its first parent.
func fragmentsForCommit(c *object.Commit) ([]Fragment, error) {
	if c.NumParents() == 0 {
		return fragmentsFromTree(c)
	}

	parent, err := c.Parent(0)
	if err != nil {
		return nil, fmt.Errorf("failed to load parent of commit %s: %w", c.Hash, err)
	}
	patch, err := parent.Patch(c)
	if err != nil {
		return nil, fmt.Errorf("failed to compute diff for commit %s: %w", c.Hash, err)
	}

	var frags []Fragment
	for _, fp := range patch.FilePatches() {
		_, to := fp.Files()
		if to == nil {
			continue // file deleted, nothing added
		}
		var added strings.Builder
		for _, chunk := range fp.Chunks() {
			if chunk.Type() == diff.Add {
				added.WriteString(chunk.Content())
			}
		}
		if added.Len() == 0 || isBinaryString(added.String()) {
			continue
		}
		frags = append(frags, Fragment{
			Content:   added.String(),
			FilePath:  to.Path(),
			CommitSHA: c.Hash.String(),
			Author:    c.Author.Name,
			Date:      c.Author.When,
		})
	}
	return frags, nil
}

// fragmentsFromTree scans every file in a commit's tree, used for root
// commits which have no parent to diff against.
func fragmentsFromTree(c *object.Commit) ([]Fragment, error) {
	tree, err := c.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to load tree for commit %s: %w", c.Hash, err)
	}

	var frags []Fragment
	iter := tree.Files()
	defer iter.Close()
	err = iter.ForEach(func(f *object.File) error {
		content, err := f.Contents()
		if err != nil {
			return fmt.Errorf("failed to read file %q at commit %s: %w", f.Name, c.Hash, err)
		}
		if isBinaryString(content) {
			return nil
		}
		frags = append(frags, Fragment{
			Content:   content,
			FilePath:  f.Name,
			CommitSHA: c.Hash.String(),
			Author:    c.Author.Name,
			Date:      c.Author.When,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return frags, nil
}

// scanStaged compares the index against HEAD's tree and returns the full
// content of every staged blob that differs.
func (s *GitSource) scanStaged(repo *git.Repository) ([]Fragment, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve HEAD: %w", err)
	}
	headCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to load HEAD commit: %w", err)
	}
	headTree, err := headCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to load HEAD tree: %w", err)
	}

	idx, err := repo.Storer.Index()
	if err != nil {
		return nil, fmt.Errorf("failed to read git index: %w", err)
	}

	var frags []Fragment
	for _, entry := range idx.Entries {
		if headEntry, err := headTree.FindEntry(entry.Name); err == nil && headEntry.Hash == entry.Hash {
			continue // unchanged since HEAD
		}
		content, err := readBlob(repo, entry.Hash)
		if err != nil || isBinaryString(content) {
			continue
		}
		frags = append(frags, Fragment{
			Content:  content,
			FilePath: entry.Name,
		})
	}
	return frags, nil
}

// scanUncommitted returns the current on-disk content of every modified or
// untracked file in the worktree.
func (s *GitSource) scanUncommitted(repo *git.Repository) ([]Fragment, error) {
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to open worktree: %w", err)
	}
	status, err := wt.Status()
	if err != nil {
		return nil, fmt.Errorf("failed to get worktree status: %w", err)
	}

	var frags []Fragment
	for file, st := range status {
		if st.Worktree != git.Modified && st.Worktree != git.Untracked {
			continue
		}
		f, err := wt.Filesystem.Open(file)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil || isBinaryString(string(data)) {
			continue
		}
		frags = append(frags, Fragment{
			Content:  string(data),
			FilePath: file,
		})
	}
	return frags, nil
}

// readBlob returns the full text content of a blob object.
func readBlob(repo *git.Repository, hash plumbing.Hash) (string, error) {
	blob, err := repo.BlobObject(hash)
	if err != nil {
		return "", err
	}
	reader, err := blob.Reader()
	if err != nil {
		return "", err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
