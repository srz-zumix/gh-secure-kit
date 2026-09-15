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
	// BaseLine is the file line number of Content's first line. It is used
	// for commit diff fragments that hold only an added hunk; zero means the
	// content starts at file line 1.
	BaseLine int
}

// Source produces the fragments to be scanned for a given target selection
// (unpushed commits, staged changes, uncommitted changes, a rev range, or
// plain files on disk).
type Source interface {
	Fragments() ([]Fragment, error)
}

// FragmentStreamer is an optional Source capability that yields fragments one
// at a time instead of returning them all at once, so a large scan does not
// retain every fragment in memory. yield is called synchronously for each
// fragment; the producer must not keep a fragment after yield returns, and it
// stops and returns yield's error unchanged as soon as yield reports one.
type FragmentStreamer interface {
	StreamFragments(yield func(Fragment) error) error
}
