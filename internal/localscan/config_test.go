package localscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryConfigExcludesOnlyExactFixtures(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "..", ConfigFileName))
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := NewScanner(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewScanner(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []string{
		testGitHubToken,
		"ghp_" + strings.Repeat("a1B2c3", 6),
		"AKIA" + strings.Repeat("A", 16),
		"AKIAIVRN52PLDBP55LBQ",
		"AKIA123456789EXAMPLE",
		"AIza" + strings.Repeat("A", 35),
		"xoxb-1234567890-abcdefghij",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("MIIEow", 12),
		"-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("A", 64),
	}
	for index, fixture := range fixtures {
		fragment := Fragment{Content: fixture, FilePath: "session/main.jsonl"}
		matches := baseline.ScanFragment(fragment)
		if len(matches) != 1 {
			t.Fatalf("fixture %d: expected one baseline finding, got %d", index, len(matches))
		}
		if findings := scanner.ScanFragment(fragment); len(findings) != 0 {
			t.Errorf("fixture %d: expected exclusion, got %d findings", index, len(findings))
		}
		changed := fixture[:len(fixture)-1] + "Z"
		fragment.Content = changed
		if findings := scanner.ScanFragment(fragment); len(findings) != 1 {
			t.Errorf("fixture %d: changed value must remain detectable, got %d findings", index, len(findings))
		}
	}
}

func TestLoadConfigMergesPatternsAndAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	content := `
patterns:
  - id: custom_token
    token_type: custom_token
    display_name: Custom Token
    regex: "custom_[0-9a-f]{16}"
    keywords: ["custom_"]
allowlist:
  regexes:
    - "^EXAMPLE_.*"
  paths:
    - "testdata"
  stopwords:
    - "example"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(cfg.Patterns) != 1 || cfg.Patterns[0].ID != "custom_token" {
		t.Fatalf("unexpected patterns: %+v", cfg.Patterns)
	}
	if len(cfg.Allowlist.Regexes) != 1 || len(cfg.Allowlist.Paths) != 1 || len(cfg.Allowlist.StopWords) != 1 {
		t.Fatalf("unexpected allowlist: %+v", cfg.Allowlist)
	}

	scanner, err := NewScanner(cfg, true)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}

	found := false
	for _, p := range scanner.Patterns {
		if p.ID == "custom_token" {
			found = true
			if p.Source != "config" {
				t.Errorf("expected source config, got %q", p.Source)
			}
		}
	}
	if !found {
		t.Fatal("custom_token pattern not merged into scanner")
	}

	// The custom pattern should match, but be excluded by the stopword allowlist.
	findings := scanner.ScanFragment(Fragment{
		Content:  "token custom_0123456789abcdef in an example config",
		FilePath: "config.yml",
	})
	if len(findings) != 0 {
		t.Errorf("expected finding to be allowlisted, got %+v", findings)
	}
}

func TestDiscoverConfig(t *testing.T) {
	dir := t.TempDir()
	if got := DiscoverConfig(dir); got != "" {
		t.Errorf("expected no config found, got %q", got)
	}

	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte("patterns: []\n"), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	if got := DiscoverConfig(dir); got != path {
		t.Errorf("DiscoverConfig() = %q, want %q", got, path)
	}
}
