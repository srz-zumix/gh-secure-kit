package recommended

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want []string
		err  string
	}{
		{"normalize", "ignore: [gsk101, GSK102, GSK101]\n", []string{"GSK101", "GSK102"}, ""},
		{"empty", "ignore: []\n", []string{}, ""},
		{"missing key", "{}\n", []string{}, ""},
		{"unknown", "ignore: [GSK99999]\n", nil, "unknown rule ID"},
		{"malformed", "ignore: [\n", nil, "failed to parse"},
		{"wrong type", "ignore: invalid\n", nil, "failed to parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.Ignore, tc.want) {
				t.Fatalf("ignore = %v, want %v", cfg.Ignore, tc.want)
			}
		})
	}
}

func TestResolveConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg, err := ResolveConfig("")
	if err != nil || len(cfg.Ignore) != 0 {
		t.Fatalf("missing default: cfg = %v, err = %v", cfg, err)
	}
	if _, err := ResolveConfig("missing.yml"); err == nil {
		t.Fatal("explicit missing file must fail")
	}
	if err := os.WriteFile(ConfigFileName, []byte("ignore: [GSK101]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = ResolveConfig("")
	if err != nil || !reflect.DeepEqual(cfg.Ignore, []string{"GSK101"}) {
		t.Fatalf("discovery: cfg = %v, err = %v", cfg, err)
	}
	if err := os.WriteFile("explicit.yml", []byte("ignore: [GSK102]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = ResolveConfig("explicit.yml")
	if err != nil || !reflect.DeepEqual(cfg.Ignore, []string{"GSK102"}) {
		t.Fatalf("explicit override: cfg = %v, err = %v", cfg, err)
	}
	if err := os.WriteFile(ConfigFileName, []byte("ignore: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveConfig(""); err == nil {
		t.Fatal("invalid discovered config must fail")
	}
}

func TestGoldenConfig(t *testing.T) {
	base := &Config{Ignore: []string{"gsk101", "GSK102", "GSK103", "GSK104", "GSK501", "GSK101"}}
	results := []Result{
		{Rule: Rule{ID: "GSK101"}, Status: StatusPass},
		{Rule: Rule{ID: "GSK102"}, Status: StatusFail},
		{Rule: Rule{ID: "GSK103"}, Status: StatusSkip},
		{Rule: Rule{ID: "gsk105"}, Status: StatusFail},
		{Rule: Rule{ID: "GSK106"}, Status: StatusSkip},
	}
	for _, prune := range []bool{false, true} {
		want := []string{"GSK101", "GSK102", "GSK103", "GSK104", "GSK105", "GSK501"}
		if prune {
			want = want[1:]
		}
		cfg := GoldenConfig(base, results, prune)
		if !reflect.DeepEqual(cfg.Ignore, want) {
			t.Fatalf("prune=%v: ignore = %v, want %v", prune, cfg.Ignore, want)
		}
		if !reflect.DeepEqual(GoldenConfig(cfg, results, prune), cfg) {
			t.Fatal("regeneration must be idempotent")
		}
	}
	if base.Ignore[0] != "gsk101" || len(base.Ignore) != 6 {
		t.Fatal("input config was mutated")
	}
}

func TestGoldenRules(t *testing.T) {
	rule, ok := RuleByID("GSK101")
	if !ok {
		t.Fatal("missing GSK101")
	}
	cfg := &Config{Ignore: []string{rule.ID}}
	for _, tc := range []struct {
		name   string
		filter Filter
		prune  bool
		count  int
	}{
		{"default ignores config", Filter{IDs: []string{rule.ID}}, false, 0},
		{"prune reevaluates config", Filter{IDs: []string{rule.ID}}, true, 1},
		{"explicit ignore retained", Filter{IDs: []string{rule.ID}, IgnoreIDs: []string{"gsk101"}}, true, 0},
		{"other scope", Filter{IDs: []string{rule.ID}, Scope: ScopeOrganization}, true, 0},
		{"severity", Filter{IDs: []string{rule.ID}, MinSeverity: SeverityCritical}, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := GoldenRules(cfg, tc.filter, tc.prune)
			if err != nil || len(rules) != tc.count {
				t.Fatalf("rules = %v, err = %v, want count %d", rules, err, tc.count)
			}
		})
	}
	filter := Filter{Scope: ScopeRepository, IDs: []string{"GSK101", "GSK102"}, OnlyFixable: true}
	want := filter.Apply(AllRules())
	got, err := GoldenRules(cfg, filter, true)
	if err != nil || len(got) != len(want) {
		t.Fatalf("fixable/rule filters: got %d, want %d, err = %v", len(got), len(want), err)
	}
	for index, rule := range got {
		if rule.ID != want[index].ID || !rule.Fixable {
			t.Fatalf("unexpected selected rule %s", rule.ID)
		}
	}
	for _, filter := range []Filter{{IDs: []string{"invalid"}}, {IgnoreIDs: []string{"invalid"}}} {
		if _, err := GoldenRules(cfg, filter, true); err == nil {
			t.Fatal("unknown flag ID must fail")
		}
	}
}

func TestWriteConfig(t *testing.T) {
	for _, cfg := range []*Config{{Ignore: []string{}}, {Ignore: []string{"GSK101", "GSK102"}}} {
		var buf bytes.Buffer
		if err := WriteConfig(&buf, cfg); err != nil {
			t.Fatal(err)
		}
		if len(cfg.Ignore) == 0 && buf.String() != "ignore: []\n" {
			t.Fatalf("empty output = %q", buf.String())
		}
		path := filepath.Join(t.TempDir(), "config.yml")
		if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadConfig(path)
		if err != nil || !reflect.DeepEqual(loaded, cfg) {
			t.Fatalf("roundtrip: cfg = %v, err = %v", loaded, err)
		}
	}
}
