package localscan

import "testing"

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
			if got := al.Allowed(tt.finding, tt.match, tt.line); got != tt.want {
				t.Errorf("Allowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllowlistNilIsNeverAllowed(t *testing.T) {
	var al *Allowlist
	if al.Allowed(Finding{}, "anything", "anything") {
		t.Error("nil allowlist should never allow")
	}
}

func TestAllowlistDefaultsAllowAWSDocumentationExamples(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Finding{PatternID: tt.patternID}
			if got := al.Allowed(f, tt.match, tt.match); got != tt.want {
				t.Errorf("Allowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
