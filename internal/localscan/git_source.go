package localscan

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
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
	if s.Target.MaxCommits < 0 {
		return nil, fmt.Errorf("max-commits must be zero or positive, got %d", s.Target.MaxCommits)
	}
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
	// A zero start hash means there is nothing to scan (e.g. an unborn HEAD).
	if startHash.IsZero() {
		return nil, nil
	}

	commits, truncated, err := collectCommits(repo, startHash, excludeSet, s.Target.MaxCommits)
	if err != nil {
		return nil, err
	}
	if truncated {
		// Fail rather than silently scanning an incomplete history: otherwise a
		// pre-push hook could let a secret in a later commit reach the remote.
		return nil, fmt.Errorf("scan aborted: more than %d commits to scan; raise --max-commits or set it to 0 to scan without a limit", s.Target.MaxCommits)
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
		// The scan start is HEAD by default, or an explicit revision (used by
		// the pre-push hook to scan the exact commits being pushed).
		var start plumbing.Hash
		if s.Target.Rev != "" {
			h, err := repo.ResolveRevision(plumbing.Revision(s.Target.Rev))
			if err != nil {
				return plumbing.ZeroHash, nil, fmt.Errorf("failed to resolve revision %q: %w", s.Target.Rev, err)
			}
			start = *h
		} else {
			head, err := repo.Head()
			if err != nil {
				// An unborn HEAD (a repository with no commits yet) has nothing
				// to scan; report an empty result rather than an error.
				if errors.Is(err, plumbing.ErrReferenceNotFound) {
					return plumbing.ZeroHash, nil, nil
				}
				return plumbing.ZeroHash, nil, fmt.Errorf("failed to resolve HEAD: %w", err)
			}
			start = head.Hash()
		}

		var remoteTips []plumbing.Hash
		refs, err := repo.References()
		if err != nil {
			return plumbing.ZeroHash, nil, fmt.Errorf("failed to list references: %w", err)
		}
		// When a destination remote is given (pre-push hook), exclude only that
		// remote's tracking branches so a commit present only on a different
		// remote is still scanned before it reaches this destination.
		var remotePrefix string
		if s.Target.Remote != "" {
			remotePrefix = "refs/remotes/" + s.Target.Remote + "/"
		}
		err = refs.ForEach(func(ref *plumbing.Reference) error {
			if !ref.Name().IsRemote() {
				return nil
			}
			if remotePrefix != "" && !strings.HasPrefix(ref.Name().String(), remotePrefix) {
				return nil
			}
			remoteTips = append(remoteTips, ref.Hash())
			return nil
		})
		if err != nil {
			return plumbing.ZeroHash, nil, fmt.Errorf("failed to iterate references: %w", err)
		}

		exclude, err := reachableSet(repo, remoteTips)
		if err != nil {
			return plumbing.ZeroHash, nil, err
		}
		return start, exclude, nil
	}

	fromRev, toRev, explicit, err := splitRevRange(revRange)
	if err != nil {
		return plumbing.ZeroHash, nil, err
	}

	toHash, err := repo.ResolveRevision(plumbing.Revision(toRev))
	if err != nil {
		return plumbing.ZeroHash, nil, fmt.Errorf("failed to resolve revision %q: %w", toRev, err)
	}

	fromHash, err := repo.ResolveRevision(plumbing.Revision(fromRev))
	if err != nil {
		// An explicit "A..B" range with an unresolvable start is a user error
		// and must fail rather than silently scanning all reachable history.
		if explicit {
			return plumbing.ZeroHash, nil, fmt.Errorf("failed to resolve revision %q: %w", fromRev, err)
		}
		// For a single revision "B", the derived start "B^" only legitimately
		// fails to resolve when B is a root commit; in that case there is
		// nothing to exclude. Any other failure is unexpected and surfaced.
		toCommit, cerr := repo.CommitObject(*toHash)
		if cerr != nil {
			return plumbing.ZeroHash, nil, fmt.Errorf("failed to load commit %s: %w", toHash, cerr)
		}
		if toCommit.NumParents() != 0 {
			return plumbing.ZeroHash, nil, fmt.Errorf("failed to resolve revision %q: %w", fromRev, err)
		}
		return *toHash, nil, nil
	}

	exclude, err := reachableSet(repo, []plumbing.Hash{*fromHash})
	if err != nil {
		return plumbing.ZeroHash, nil, err
	}
	return *toHash, exclude, nil
}

// splitRevRange splits a "A..B" range into its endpoints. A bare revision
// "B" is treated as the single-commit range "B^..B". The explicit result
// reports whether the caller supplied an explicit ".." range (versus a bare
// revision), so a missing start can be rejected only for explicit ranges.
func splitRevRange(revRange string) (from, to string, explicit bool, err error) {
	if strings.Contains(revRange, "...") {
		return "", "", false, fmt.Errorf("invalid rev-range %q: only the \"A..B\" form is supported, not \"A...B\"", revRange)
	}
	if idx := strings.Index(revRange, ".."); idx >= 0 {
		from = strings.TrimSuffix(revRange[:idx], ".")
		to = strings.TrimPrefix(revRange[idx+2:], ".")
		if from == "" {
			return "", "", false, fmt.Errorf("invalid rev-range %q: missing start revision", revRange)
		}
		if to == "" {
			to = "HEAD"
		}
		return from, to, true, nil
	}
	return revRange + "^", revRange, false, nil
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
func collectCommits(repo *git.Repository, start plumbing.Hash, exclude map[plumbing.Hash]bool, maxCommits int) ([]*object.Commit, bool, error) {
	var result []*object.Commit
	visited := make(map[plumbing.Hash]bool)
	queue := []plumbing.Hash{start}
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		if visited[h] || exclude[h] {
			continue
		}
		visited[h] = true
		// Only signal truncation once a genuinely includable commit beyond the
		// cap is found, so an exactly-at-limit walk is not falsely rejected.
		if maxCommits > 0 && len(result) >= maxCommits {
			return result, true, nil
		}
		c, err := repo.CommitObject(h)
		if err != nil {
			return nil, false, fmt.Errorf("failed to load commit %s: %w", h, err)
		}
		result = append(result, c)
		queue = append(queue, c.ParentHashes...)
	}
	return result, false, nil
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
		// Track the destination-file line as we walk the hunks so each added
		// block records the real line where it starts. Equal and Add chunks
		// advance the destination line; Delete chunks do not.
		toLine := 1
		for _, chunk := range fp.Chunks() {
			content := chunk.Content()
			switch chunk.Type() {
			case diff.Equal:
				toLine += countLines(content)
			case diff.Delete:
				// Deleted lines exist only in the source; skip them.
			case diff.Add:
				if content != "" && !isBinaryString(content) {
					frags = append(frags, Fragment{
						Content:   content,
						FilePath:  to.Path(),
						CommitSHA: c.Hash.String(),
						Author:    c.Author.Name,
						Date:      c.Author.When,
						BaseLine:  toLine,
					})
				}
				toLine += countLines(content)
			}
		}
	}
	return frags, nil
}

// countLines returns the number of lines spanned by s, counting a trailing
// line that is not newline-terminated.
func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
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
	// headTree is nil when HEAD is unborn (a repository with no commits); in
	// that case every staged entry is treated as new against an empty tree.
	var headTree *object.Tree
	head, err := repo.Head()
	if err != nil {
		if !errors.Is(err, plumbing.ErrReferenceNotFound) {
			return nil, fmt.Errorf("failed to resolve HEAD: %w", err)
		}
	} else {
		headCommit, err := repo.CommitObject(head.Hash())
		if err != nil {
			return nil, fmt.Errorf("failed to load HEAD commit: %w", err)
		}
		headTree, err = headCommit.Tree()
		if err != nil {
			return nil, fmt.Errorf("failed to load HEAD tree: %w", err)
		}
	}

	idx, err := repo.Storer.Index()
	if err != nil {
		return nil, fmt.Errorf("failed to read git index: %w", err)
	}

	var frags []Fragment
	for _, entry := range idx.Entries {
		// Submodule entries point to a commit object, and intent-to-add entries
		// carry a zero hash; neither refers to a readable blob.
		if entry.Mode == filemode.Submodule || entry.Hash.IsZero() {
			continue
		}
		if headTree != nil {
			if headEntry, err := headTree.FindEntry(entry.Name); err == nil && headEntry.Hash == entry.Hash {
				continue // unchanged since HEAD
			}
		}
		content, err := readBlob(repo, entry.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to read staged blob %q: %w", entry.Name, err)
		}
		if isBinaryString(content) {
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
		// Skip symlinks, FIFOs, devices and other non-regular files: opening a
		// symlink can read outside the worktree and a FIFO can block the scan.
		if info, err := wt.Filesystem.Lstat(file); err != nil || !info.Mode().IsRegular() {
			continue
		}
		f, err := wt.Filesystem.Open(file)
		if err != nil {
			return nil, fmt.Errorf("failed to open worktree file %q: %w", file, err)
		}
		data, err := io.ReadAll(f)
		closeErr := f.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read worktree file %q: %w", file, err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("failed to close worktree file %q: %w", file, closeErr)
		}
		if isBinaryString(string(data)) {
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
func readBlob(repo *git.Repository, hash plumbing.Hash) (content string, err error) {
	blob, err := repo.BlobObject(hash)
	if err != nil {
		return "", err
	}
	reader, err := blob.Reader()
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := reader.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
