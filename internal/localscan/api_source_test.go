package localscan

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-github/v90/github"
)

func TestFragmentsFromPatchKeepsNewFileLineNumbers(t *testing.T) {
	patch := "@@ -1,3 +1,5 @@\n context\n+added one\n+added two\n-removed\n context\n@@ -20,2 +22,3 @@\n keep\n+later addition\n"

	frags := fragmentsFromPatch(patch, "config.yml", "abc123", "Test", time.Time{})

	if len(frags) != 2 {
		t.Fatalf("fragments = %d, want 2", len(frags))
	}
	if frags[0].Content != "added one\nadded two\n" {
		t.Errorf("frags[0].Content = %q", frags[0].Content)
	}
	if frags[0].BaseLine != 2 {
		t.Errorf("frags[0].BaseLine = %d, want 2", frags[0].BaseLine)
	}
	if frags[1].Content != "later addition\n" {
		t.Errorf("frags[1].Content = %q", frags[1].Content)
	}
	if frags[1].BaseLine != 23 {
		t.Errorf("frags[1].BaseLine = %d, want 23", frags[1].BaseLine)
	}
	if frags[0].FilePath != "config.yml" || frags[0].CommitSHA != "abc123" {
		t.Errorf("unexpected fragment metadata: %+v", frags[0])
	}
}

func TestFragmentsForAPICommitFailsOnTruncatedDiff(t *testing.T) {
	commit := &github.RepositoryCommit{
		SHA: github.Ptr("abc123"),
		Files: []*github.CommitFile{
			{Filename: github.Ptr("huge.json"), Additions: github.Ptr(5000)},
		},
	}

	_, err := fragmentsForAPICommit(commit)
	if err == nil {
		t.Fatal("expected an error when the API omits the diff of a changed file")
	}
}

func TestFragmentsForAPICommitSkipsBinaryFile(t *testing.T) {
	commit := &github.RepositoryCommit{
		SHA: github.Ptr("abc123"),
		Files: []*github.CommitFile{
			{Filename: github.Ptr("logo.png"), Additions: github.Ptr(0)},
		},
	}

	frags, err := fragmentsForAPICommit(commit)
	if err != nil {
		t.Fatalf("fragmentsForAPICommit() error = %v", err)
	}
	if len(frags) != 0 {
		t.Errorf("fragments = %d, want 0", len(frags))
	}
}

func TestAPISourceRejectsUnsupportedTarget(t *testing.T) {
	source := NewAPISource(t.Context(), Target{Mode: TargetUncommitted}, "")

	if _, err := source.Fragments(); err == nil {
		t.Fatal("expected an error for a target the GitHub API cannot scan")
	}
}

type stubSource struct {
	frags []Fragment
	err   error
}

func (s stubSource) Fragments() ([]Fragment, error) { return s.frags, s.err }

func TestFallbackSourceUsesFallbackOnlyWhenLocalContentIsMissing(t *testing.T) {
	fallback := stubSource{frags: []Fragment{{Content: "from fallback\n"}}}

	missing := NewFallbackSource(stubSource{err: ErrLocalContentMissing}, fallback)
	frags, err := missing.Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}
	if len(frags) != 1 || frags[0].Content != "from fallback\n" {
		t.Errorf("fragments = %+v, want the fallback result", frags)
	}

	other := errors.New("boom")
	broken := NewFallbackSource(stubSource{err: other}, fallback)
	if _, err := broken.Fragments(); !errors.Is(err, other) {
		t.Errorf("Fragments() error = %v, want the primary error", err)
	}
}
