package localscan

import (
	"testing"

	"github.com/srz-zumix/go-gh-extension/pkg/logger"
)

func TestNewScannerRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
	}{
		{"missing id", &Config{Patterns: []ConfigPattern{{Regex: `x`}}}},
		{"missing regex", &Config{Patterns: []ConfigPattern{{ID: "p"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewScanner(tt.cfg, false); err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestNewScannerDefaultsDisplayNameToID(t *testing.T) {
	cfg := &Config{Patterns: []ConfigPattern{{ID: "my_pattern", Regex: `x`}}}
	s, err := NewScanner(cfg, false)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	var found bool
	for _, p := range s.Patterns {
		if p.ID == "my_pattern" {
			found = true
			if p.DisplayName != "my_pattern" {
				t.Errorf("DisplayName = %q, want %q", p.DisplayName, "my_pattern")
			}
		}
	}
	if !found {
		t.Fatal("configured pattern not found")
	}
}

func TestScanFragmentRedactsMatchWhenSecretHidden(t *testing.T) {
	cfg := &Config{Patterns: []ConfigPattern{{ID: "tok", Regex: `secret_[0-9a-f]{10}`}}}
	s, err := NewScanner(cfg, false)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	raw := "secret_0123456789"
	findings := s.ScanFragment(Fragment{Content: raw + "\n"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Match == raw || findings[0].Secret == raw {
		t.Errorf("raw secret leaked: match=%q secret=%q", findings[0].Match, findings[0].Secret)
	}
}

func TestScanFragmentUsesBaseLineOffset(t *testing.T) {
	cfg := &Config{Patterns: []ConfigPattern{{ID: "tok", Regex: `secret_[0-9a-f]{10}`}}}
	s, err := NewScanner(cfg, true)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	// The secret is on the first line of Content, but Content begins at file
	// line 42, so the finding must report line 42 (not 1).
	findings := s.ScanFragment(Fragment{Content: "secret_0123456789\n", BaseLine: 42})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].StartLine != 42 {
		t.Errorf("StartLine = %d, want 42", findings[0].StartLine)
	}
}

func TestScanReturnsFindingsRegardlessOfDebugLevel(t *testing.T) {
	// Scan gates its debug-only bookkeeping behind the log level; verify the
	// findings it returns are identical whether or not debug is enabled.
	cfg := &Config{Patterns: []ConfigPattern{{ID: "tok", Regex: `secret_[0-9a-f]{10}`}}}
	s, err := NewScanner(cfg, false)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	src := stubSource{frags: []Fragment{
		{CommitSHA: "abc", FilePath: "a.txt", Content: "secret_0123456789\n"},
		{CommitSHA: "abc", FilePath: "b.txt", Content: "nothing here\n"},
	}}
	// Restore the default level even if an assertion below aborts the test,
	// so a leaked debug level cannot contaminate later tests.
	t.Cleanup(func() { logger.SetLogLevel("info") })
	for _, level := range []string{"info", "debug"} {
		logger.SetLogLevel(level)
		findings, err := Scan(src, s)
		if err != nil {
			t.Fatalf("Scan(%s) error = %v", level, err)
		}
		if len(findings) != 1 {
			t.Fatalf("Scan(%s) findings = %d, want 1", level, len(findings))
		}
	}
}

func TestScanFragmentUsesFixedLineAndPropagatesMetadata(t *testing.T) {
	cfg := &Config{Patterns: []ConfigPattern{{ID: "tok", Regex: `secret_[0-9a-f]{10}`}}}
	s, err := NewScanner(cfg, true)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	findings := s.ScanFragment(Fragment{
		Content:   "x\nsecret_0123456789\n",
		Line:      7,
		BaseLine:  100,
		Source:    "cli-logs",
		SessionID: "sid",
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].StartLine != 7 {
		t.Errorf("StartLine = %d, want 7 (Line takes precedence)", findings[0].StartLine)
	}
	if findings[0].Source != "cli-logs" || findings[0].SessionID != "sid" {
		t.Errorf("metadata not propagated: %+v", findings[0])
	}
}

func TestScanDeduplicatesSameKeyPerFileAndCommit(t *testing.T) {
	for _, showSecret := range []bool{false, true} {
		scanner, err := NewScanner(&Config{Patterns: []ConfigPattern{{ID: "tok", Regex: `secret_[0-9a-f]{10}`}}}, showSecret)
		if err != nil {
			t.Fatal(err)
		}
		source := stubSource{frags: []Fragment{
			{FilePath: "a.jsonl", Line: 2, Content: "secret_0123456789 secret_0123456789"},
			{FilePath: "a.jsonl", Line: 9, Content: "secret_0123456789"},
			{FilePath: "a.jsonl", Line: 10, Content: "secret_abcdef6789"},
			{FilePath: "b.jsonl", Line: 1, Content: "secret_0123456789"},
			{FilePath: "a.jsonl", CommitSHA: "commit-a", Content: "secret_0123456789"},
			{FilePath: "a.jsonl", CommitSHA: "commit-b", Content: "secret_0123456789"},
		}}
		findings, err := Scan(source, scanner)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 5 {
			t.Fatalf("show-secret=%v: got %d findings, want 5", showSecret, len(findings))
		}
		if findings[0].StartLine != 2 {
			t.Errorf("first occurrence line = %d, want 2", findings[0].StartLine)
		}
		if !showSecret && findings[0].Secret != findings[1].Secret {
			t.Error("test requires different keys with identical redacted output")
		}
	}
}
