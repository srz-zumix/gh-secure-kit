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
