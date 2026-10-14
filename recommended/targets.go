package recommended

import (
	"fmt"
	"regexp"
	"strings"
)

// TargetIgnores maps an upper-case rule ID to patterns of the targets (for
// example ruleset or environment names) that are excluded from that rule.
type TargetIgnores map[string][]*regexp.Regexp

// CompileTargetPattern compiles a target pattern so that it must match the
// whole target, not a substring of it.
func CompileTargetPattern(pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return nil, fmt.Errorf("invalid target pattern %q: %w", pattern, err)
	}
	return re, nil
}

// Match reports whether target of the given rule is ignored. It is safe to call on a nil map.
func (t TargetIgnores) Match(ruleID, target string) bool {
	for _, re := range t[strings.ToUpper(ruleID)] {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

// splitIgnoredTargets partitions targets into those still evaluated and those
// ignored by the configuration. Both results keep the order of targets.
func splitIgnoredTargets(ignores TargetIgnores, ruleID string, targets []string) (kept, ignored []string) {
	for _, target := range targets {
		if ignores.Match(ruleID, target) {
			ignored = append(ignored, target)
		} else {
			kept = append(kept, target)
		}
	}
	return kept, ignored
}

// failTargets builds a failing Outcome that lists the individual targets so that
// they can be ignored one by one.
func failTargets(detail string, targets []string) Outcome {
	return Outcome{Status: StatusFail, Detail: detail, Targets: targets}
}

// skipIgnored reports that every finding of the rule was ignored by the configuration.
func skipIgnored(kind string, ignored []string) Outcome {
	return Skip(fmt.Sprintf("all findings are ignored by the configuration (%s: %s)", kind, strings.Join(ignored, ", ")))
}
