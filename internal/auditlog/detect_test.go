package auditlog

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-github/v90/github"
)

func entry(action string, ts time.Time, extra map[string]any) *github.AuditEntry {
	return &github.AuditEntry{
		Action:           github.Ptr(action),
		Timestamp:        &github.Timestamp{Time: ts},
		AdditionalFields: extra,
	}
}

func TestClassify(t *testing.T) {
	tests := map[string]string{
		"public_key.create":                    CategorySSH,
		"ssh_certificate_authority.create":     CategorySSH,
		"personal_access_token.access_granted": CategoryPAT,
		"org_credential_authorization.grant":   CategorySSOCredential,
		"oauth_application.create":             CategoryOAuthApp,
		"org.oauth_app_access_approved":        CategoryOAuthApp,
		"integration.create":                   CategoryGitHubApp,
		"integration_installation.create":      CategoryGitHubApp,
		"org.integration_manager_added":        CategoryGitHubApp,
		"org.create":                           "",
		"repo.create":                          "",
		"integrationx.create":                  "",
	}
	for action, want := range tests {
		if got := Classify(action); got != want {
			t.Errorf("Classify(%q) = %q, want %q", action, got, want)
		}
	}
}

func TestQueries(t *testing.T) {
	got := Queries([]string{CategorySSOCredential, CategoryOAuthApp})
	want := []string{
		"action:org_credential_authorization",
		"action:oauth_application",
		"action:org.oauth_app_access_approved",
		"action:org.oauth_app_access_denied",
		"action:org.oauth_app_access_requested",
		"action:org.enable_oauth_app_restrictions",
		"action:org.disable_oauth_app_restrictions",
	}
	if len(got) != len(want) {
		t.Fatalf("Queries() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Queries()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if len(Queries(nil)) <= len(got) {
		t.Errorf("Queries(nil) should cover every category")
	}
}

func TestBuildPhrase(t *testing.T) {
	s := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	u := time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC)
	tests := []struct {
		since, until time.Time
		want         string
	}{
		{time.Time{}, time.Time{}, "action:x"},
		{s, time.Time{}, "action:x created:>=2026-01-02"},
		{time.Time{}, u, "action:x created:<=2026-02-03"},
		{s, u, "action:x created:2026-01-02..2026-02-03"},
	}
	for _, tt := range tests {
		if got := BuildPhrase("action:x", tt.since, tt.until); got != tt.want {
			t.Errorf("BuildPhrase() = %q, want %q", got, tt.want)
		}
	}
}

func TestParseTimeRange(t *testing.T) {
	if _, _, err := ParseTimeRange("", ""); err != nil {
		t.Errorf("empty range: %v", err)
	}
	if _, _, err := ParseTimeRange("2026-01-01", "2025-01-01"); err == nil {
		t.Error("expected error when since is after until")
	}
	if _, _, err := ParseTimeRange("bogus", ""); err == nil {
		t.Error("expected error for invalid --since")
	}
	if _, u, err := ParseTimeRange("", "2026-02-03"); err != nil {
		t.Fatal(err)
	} else if want := time.Date(2026, 2, 3, 23, 59, 59, 999999999, time.Local); !u.Equal(want) {
		t.Errorf("date-only until = %v, want %v", u, want)
	}
	if _, _, err := ParseTimeRange("2026-02-03", "2026-02-03"); err != nil {
		t.Errorf("same-day range should be valid: %v", err)
	}
	if _, _, err := ParseTimeRange("", "bogus"); err == nil {
		t.Error("expected error for invalid --until")
	}
}

func TestFilter(t *testing.T) {
	base := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
	entries := []*github.AuditEntry{
		entry("public_key.create", base, map[string]any{"title": "example-key"}),
		entry("repo.create", base.Add(time.Hour), nil),
		entry("personal_access_token.access_granted", base.Add(2*time.Hour), nil),
		entry("public_key.delete", base.Add(-48*time.Hour), nil),
	}

	got := Filter(entries, nil, time.Time{}, time.Time{})
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if *got[0].Entry.Action != "personal_access_token.access_granted" || *got[2].Entry.Action != "public_key.delete" {
		t.Errorf("entries are not sorted newest first: %v", got)
	}
	if got[1].Target != "example-key" {
		t.Errorf("Target = %q, want example-key", got[1].Target)
	}

	got = Filter(entries, []string{CategorySSH}, base.Add(-time.Hour), time.Time{})
	if len(got) != 1 || *got[0].Entry.Action != "public_key.create" {
		t.Errorf("unexpected result: %v", got)
	}

	got = Filter(entries, nil, time.Time{}, base.Add(30*time.Minute))
	if len(got) != 2 {
		t.Errorf("until filter len = %d, want 2", len(got))
	}
}

func TestDetectionJSONIncludesCategory(t *testing.T) {
	d := Detection{Category: CategorySSH, Entry: entry("public_key.create", time.Now(), nil)}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["category"] != CategorySSH {
		t.Errorf("category missing in JSON: %s", b)
	}
}

func TestNormalizeCategories(t *testing.T) {
	got := NormalizeCategories([]string{"SSH", "pat", "ssh", "Pat", "unknown"})
	want := []string{CategorySSH, CategoryPAT}
	if len(got) != len(want) {
		t.Fatalf("NormalizeCategories() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("NormalizeCategories()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
