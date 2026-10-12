package recommended

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/go-gh/v2/pkg/repository"
)

func TestRenderSettingsLinks(t *testing.T) {
	rule, ok := RuleByID("GSK501")
	if !ok {
		t.Fatal("rule GSK501 not found")
	}
	repo := repository.Repository{Host: "github.example.com", Owner: "example-org"}
	result := Result{Rule: rule, Target: repo.Owner, Status: StatusFail, SettingsURL: rule.settingsURL(repo)}
	unknown := Result{Rule: Rule{ID: "GSK104"}, Status: StatusFail}
	tests := []struct {
		name   string
		render func(cmdutil.Exporter) error
	}{
		{"check", func(exporter cmdutil.Exporter) error {
			return RenderResults(exporter, []Result{result, unknown})
		}},
		{"apply", func(exporter cmdutil.Exporter) error {
			return RenderApplyResults(exporter, []ApplyResult{
				{Result: result, Error: os.ErrPermission},
				{Result: unknown, Error: os.ErrPermission},
			}, false)
		}},
	}
	for _, tt := range tests {
		for _, format := range []string{"table", "json"} {
			t.Run(tt.name+"/"+format, func(t *testing.T) {
				output, err := os.CreateTemp(t.TempDir(), "output")
				if err != nil {
					t.Fatal(err)
				}
				stdout := os.Stdout
				os.Stdout = output
				t.Cleanup(func() {
					os.Stdout = stdout
					_ = output.Close()
				})
				var exporter cmdutil.Exporter
				if format == "json" {
					exporter = cmdutil.NewJSONExporter()
				}
				if err := tt.render(exporter); err != nil {
					t.Fatal(err)
				}
				os.Stdout = stdout
				data, err := os.ReadFile(output.Name())
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), result.SettingsURL) {
					t.Fatalf("settings URL missing from output: %s", data)
				}
				if format == "json" {
					var entries []map[string]any
					if err := json.Unmarshal(data, &entries); err != nil {
						t.Fatal(err)
					}
					if len(entries) != 2 || entries[0]["settings_url"] != result.SettingsURL {
						t.Fatalf("unexpected JSON output: %s", data)
					}
					if _, exists := entries[1]["settings_url"]; exists {
						t.Fatalf("unknown settings URL should be omitted: %s", data)
					}
				} else if !strings.Contains(string(data), "SETTINGS URL") {
					t.Errorf("settings URL column missing: %s", data)
				}
			})
		}
	}
}

func TestSettingsURL(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		repo repository.Repository
		want string
	}{
		{"organization", Rule{Scope: ScopeOrganization, SettingsPath: "security"}, repository.Repository{Host: "github.com", Owner: "example-org"}, "https://github.com/organizations/example-org/settings/security"},
		{"enterprise repository", Rule{Scope: ScopeRepository, SettingsPath: "actions"}, repository.Repository{Host: "github.example.com", Owner: "example-org", Name: "example-repo"}, "https://github.example.com/example-org/example-repo/settings/actions"},
		{"default host", Rule{Scope: ScopeRepository, SettingsPath: "branches"}, repository.Repository{Owner: "example-org", Name: "example-repo"}, "https://github.com/example-org/example-repo/settings/branches"},
		{"unknown location", Rule{Scope: ScopeRepository}, repository.Repository{Host: "github.com", Owner: "example-org", Name: "example-repo"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.settingsURL(tt.repo); got != tt.want {
				t.Errorf("settingsURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResultJSONSettingsURL(t *testing.T) {
	for _, settingsURL := range []string{"", "https://github.com/organizations/example-org/settings/security"} {
		data, err := json.Marshal(newResultJSON(Result{SettingsURL: settingsURL}))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "settings_url") != (settingsURL != "") {
			t.Errorf("unexpected settings_url presence in %s", data)
		}
		if got := newResultJSON(Result{SettingsURL: settingsURL}).SettingsURL; got != settingsURL {
			t.Errorf("SettingsURL = %q, want %q", got, settingsURL)
		}
	}
}

func TestRuleSettingsLinks(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"GSK501", "https://github.example.com/organizations/example-org/settings/security"},
		{"GSK101", "https://github.example.com/example-org/example-repo/settings/security_analysis"},
		{"GSK125", "https://github.example.com/example-org/example-repo/settings"},
		{"GSK132", "https://github.example.com/example-org/example-repo/settings/actions"},
		{"GSK135", "https://github.example.com/example-org/example-repo/settings/environments"},
		{"GSK140", "https://github.example.com/example-org/example-repo/settings/rules"},
		{"GSK503", "https://github.example.com/organizations/example-org/settings/member_privileges"},
		{"GSK523", "https://github.example.com/organizations/example-org/settings/actions/runner-groups"},
		{"GSK144", "https://github.example.com/example-org/example-repo/settings/hooks"},
		{"GSK524", "https://github.example.com/organizations/example-org/settings/hooks"},
		{"GSK104", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			rule, ok := RuleByID(tt.id)
			if !ok {
				t.Fatalf("rule %s not found", tt.id)
			}
			repo := repository.Repository{Host: "github.example.com", Owner: "example-org", Name: "example-repo"}
			if got := rule.settingsURL(repo); got != tt.want {
				t.Errorf("settingsURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		want  string
	}{
		{"empty", "", 10, ""},
		{"short", "hello world", 20, "hello world"},
		{"wrap", "aaa bbb ccc ddd", 7, "aaa bbb\nccc ddd"},
		{"long word", "abcdefghij kl", 5, "abcdefghij\nkl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wrapText(tt.in, tt.width); got != tt.want {
				t.Errorf("wrapText(%q, %d) = %q, want %q", tt.in, tt.width, got, tt.want)
			}
		})
	}
}
