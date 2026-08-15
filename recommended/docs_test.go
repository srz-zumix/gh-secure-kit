package recommended
package recommended

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRuleDocsExist verifies that every registered rule has a corresponding
// docs/rules/<ID>.md file, and that every doc file corresponds to a
// registered rule, keeping the documentation catalog and the rule catalog
// in sync (similar in spirit to shellcheck's wiki-per-rule convention).
func TestRuleDocsExist(t *testing.T) {
	docsDir := filepath.Join("..", "docs", "rules")
	entries, err := os.ReadDir(docsDir)
	if err != nil {
		t.Fatalf("failed to read docs directory %q: %v", docsDir, err)
	}

	docIDs := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		docIDs[strings.TrimSuffix(name, ".md")] = true
	}

	rules := AllRules()
	ruleIDs := make(map[string]bool, len(rules))
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
		if !docIDs[rule.ID] {
			t.Errorf("rule %s has no docs/rules/%s.md file", rule.ID, rule.ID)
		}
	}

	for id := range docIDs {
		if !ruleIDs[id] {
			t.Errorf("docs/rules/%s.md does not correspond to any registered rule", id)
		}
	}
}
