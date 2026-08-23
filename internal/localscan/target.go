package localscan

// TargetMode selects which part of a git working copy (or plain directory)
// is scanned for secrets.
type TargetMode string

const (
	// TargetUnpushed scans commits reachable from HEAD but not from any
	// remote-tracking branch.
	TargetUnpushed TargetMode = "unpushed"
	// TargetStaged scans changes currently staged in the index.
	TargetStaged TargetMode = "staged"
	// TargetUncommitted scans modified and untracked files in the worktree.
	TargetUncommitted TargetMode = "uncommitted"
	// TargetRevRange scans an explicit "A..B" (or single "B") revision range.
	TargetRevRange TargetMode = "rev-range"
	// TargetNoGit scans plain files under Path without using git at all.
	TargetNoGit TargetMode = "no-git"
)

// Target describes what content a Source should scan.
type Target struct {
	Mode TargetMode
	// RepoPath is the git repository (or plain directory, for TargetNoGit)
	// to scan, resolved to the current working directory by default.
	RepoPath string
	// RevRange is required for TargetRevRange, in "A..B" or "B" form.
	RevRange string
	// Rev, when set for TargetUnpushed, overrides the scan start (HEAD by
	// default) so the pre-push hook can scan the exact commits being pushed:
	// commits reachable from Rev but not from the destination's remote-tracking
	// branches.
	Rev string
	// Remote, when set for TargetUnpushed, restricts the excluded commits to
	// those reachable from that remote's tracking branches only (instead of
	// every remote). The pre-push hook sets it to the push destination so a
	// commit that exists only on a different remote is still scanned before it
	// reaches a new destination.
	Remote string
	// MaxCommits caps the number of commits walked for TargetUnpushed and
	// TargetRevRange. Zero means unlimited.
	MaxCommits int
}
