package localscan

import (
	"testing"

	"github.com/google/go-github/v90/github"
)

func TestBuiltinPatternsMatch(t *testing.T) {
	tests := []struct {
		id      string
		content string
	}{
		{"github_personal_access_token", "token=ghp_" + repeatChar("a1B2c3", 6)},
		{"aws_access_key_id", "AKIA" + repeatChar("A", 16)},
		{"google_api_key", "AIza" + repeatChar("A", 35)},
		{"slack_token", "xoxb-1234567890-abcdefghij"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{"rsa_private_key", "-----BEGIN RSA PRIVATE KEY-----\n" + repeatChar("MIIEow", 12) + "\n-----END RSA PRIVATE KEY-----"},
	}

	patterns := BuiltinPatterns()
	byID := make(map[string]Pattern)
	for _, p := range patterns {
		byID[p.ID] = p
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			p, ok := byID[tt.id]
			if !ok {
				t.Fatalf("pattern %q not found", tt.id)
			}
			if !p.Regex.MatchString(tt.content) {
				t.Errorf("pattern %q did not match %q", tt.id, tt.content)
			}
		})
	}
}

func TestBuiltinPatternsNoFalsePositive(t *testing.T) {
	scanner, err := NewScanner(nil, true)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	findings := scanner.ScanFragment(Fragment{
		Content:  "this is just a normal go source file with no secrets in it.\nfunc main() {}\n",
		FilePath: "main.go",
	})
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d: %+v", len(findings), findings)
	}
}

func repeatChar(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestBuiltinClassicPATHonorsGithubTokenOverride(t *testing.T) {
	// The org pattern configuration keys the classic PAT detector by the
	// "github_token" token type, so BuiltinPatterns() must use that value for
	// --pattern-config to be able to disable it.
	patterns := BuiltinPatterns()
	var byID = make(map[string]Pattern)
	for _, p := range patterns {
		byID[p.ID] = p
	}
	p, ok := byID["github_personal_access_token"]
	if !ok {
		t.Fatal("github_personal_access_token builtin not found")
	}
	if p.TokenType != "github_token" {
		t.Errorf("TokenType = %q, want %q", p.TokenType, "github_token")
	}

	configs := &github.SecretScanningPatternConfigs{
		ProviderPatternOverrides: []*github.SecretScanningPatternOverride{
			{
				TokenType:      github.Ptr("github_token"),
				Setting:        github.Ptr("disabled"),
				DefaultSetting: github.Ptr("enabled"),
			},
		},
	}
	for _, rp := range ApplyPatternConfigs(patterns, configs) {
		if rp.ID == "github_personal_access_token" && rp.Enabled {
			t.Error("github_token=disabled did not disable the builtin classic PAT detector")
		}
	}
}
