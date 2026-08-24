package localscan

import "testing"

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
