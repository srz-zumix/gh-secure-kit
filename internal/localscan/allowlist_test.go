package localscan

import (
	"strings"
	"testing"
)

func TestAllowlistAllowed(t *testing.T) {
	dir := "vendor/third_party"
	al := &Allowlist{
		Paths:     []string{dir},
		Commits:   []string{"deadbeef"},
		StopWords: []string{"example"},
	}

	tests := []struct {
		name    string
		finding Finding
		match   string
		line    string
		want    bool
	}{
		{"path match", Finding{File: "vendor/third_party/lib.go"}, "secret", "secret", true},
		{"commit match", Finding{Commit: "deadbeef"}, "secret", "secret", true},
		{"stopword match", Finding{}, "secret", "this is an example secret", true},
		{"no match", Finding{File: "src/main.go", Commit: "cafef00d"}, "secret", "secret", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := al.Allowed(tt.finding, tt.match, tt.line, strings.Index(tt.line, tt.match)); got != tt.want {
				t.Errorf("Allowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllowlistNilIsNeverAllowed(t *testing.T) {
	var al *Allowlist
	if al.Allowed(Finding{}, "anything", "anything", 0) {
		t.Error("nil allowlist should never allow")
	}
}

func TestAllowlistDefaultsAllowKnownDummyCredentials(t *testing.T) {
	al := &Allowlist{}

	tests := []struct {
		name      string
		patternID string
		match     string
		want      bool
	}{
		{"canonical aws access key id sample", "aws_access_key_id", "AKIAIOSFODNN7EXAMPLE", true},
		{"canonical aws secret access key sample", "aws_secret_access_key", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, true},
		{"second documented access key sample", "aws_access_key_id", "AKIAI44QH8DHBEXAMPLE", true},
		{"real-looking access key id", "aws_access_key_id", "AKIAIVRN52PLDBP55LBQ", false},
		{"noncanonical valid access key ending in EXAMPLE is a finding", "aws_access_key_id", "AKIA123456789EXAMPLE", false},
		{"noncanonical valid secret ending in EXAMPLEKEY is a finding", "aws_secret_access_key", `aws_secret_access_key = "0000000000000000000000000000000EXAMPLEKEY"`, false},
		{"custom pattern ending in EXAMPLE is not suppressed", "custom_token", "SECRET_EXAMPLE", false},
		{"other provider ending in EXAMPLE is not suppressed", "github_personal_access_token", "ghp_EXAMPLE", false},
		{"agent placeholder github token", "github_personal_access_token", "ghp_invalidinvalidinvalidinvalidinvalid00", true},
		{"agent placeholder github token in assignment", "github_personal_access_token", "GH_TOKEN=ghp_invalidinvalidinvalidinvalidinvalid00", true},
		{"similar github token is a finding", "github_personal_access_token", "ghp_invalidinvalidinvalidinvalidinvalid01", false},
		{"agent placeholder under another pattern is not suppressed", "custom_token", "ghp_invalidinvalidinvalidinvalidinvalid00", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Finding{PatternID: tt.patternID}
			if got := al.Allowed(f, tt.match, tt.match, 0); got != tt.want {
				t.Errorf("Allowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllowlistDefaultsMatchPrefixOfOverlongSample(t *testing.T) {
	al := &Allowlist{}
	f := Finding{PatternID: "github_personal_access_token"}
	prefix := "ghp_invalidinvalidinvalidinvalidinvalid0"

	tests := []struct {
		name string
		line string
		want bool
	}{
		{"complete placeholder on line", "GH_TOKEN=ghp_invalidinvalidinvalidinvalidinvalid00", true},
		{"different trailing character", "GH_TOKEN=ghp_invalidinvalidinvalidinvalidinvalid01", false},
		{"truncated placeholder", "GH_TOKEN=" + prefix, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := al.Allowed(f, prefix, tt.line, len("GH_TOKEN=")); got != tt.want {
				t.Errorf("Allowed() = %v, want %v", got, tt.want)
			}
		})
	}
	if al.Allowed(f, "", "GH_TOKEN=ghp_invalidinvalidinvalidinvalidinvalid00", len("GH_TOKEN=")) {
		t.Error("empty match should not be allowed")
	}
}

func TestAllowlistDefaultsPrefixRequiresPlaceholderAtMatch(t *testing.T) {
	al := &Allowlist{}
	f := Finding{PatternID: "github_personal_access_token"}
	prefix := "ghp_invalidinvalidinvalidinvalidinvalid0"
	line := "A=ghp_invalidinvalidinvalidinvalidinvalid01 B=ghp_invalidinvalidinvalidinvalidinvalid00"
	first := strings.Index(line, prefix)
	second := strings.LastIndex(line, prefix)
	if al.Allowed(f, prefix, line, first) {
		t.Error("non-placeholder token sharing a line with the placeholder should not be allowed")
	}
	if !al.Allowed(f, prefix, line, second) {
		t.Error("placeholder token should be allowed")
	}
	if al.Allowed(f, prefix, line, -1) {
		t.Error("unknown offset should not allow a prefix match")
	}
}
