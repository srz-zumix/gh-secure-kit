package localscan

import "time"

// Fragment is a unit of content to scan for secrets, e.g. a diff chunk, a
// whole file, or a git blob.
type Fragment struct {
	Content   string
	FilePath  string
	CommitSHA string
	Author    string
	Date      time.Time
}

// Source produces the fragments to be scanned for a given target selection
// (unpushed commits, staged changes, uncommitted changes, a rev range, or
// plain files on disk).
type Source interface {
	Fragments() ([]Fragment, error)
}
