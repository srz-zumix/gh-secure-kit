package recommended

import "sort"

// registry holds every rule known to gh-secure-kit, keyed by ID.
var registry = map[string]*Rule{}

// order preserves rule registration order for stable, deterministic listings.
var order []string

// register adds a rule to the catalog. It panics on duplicate IDs since that
// indicates a programming error in this package, not a runtime condition.
func register(r Rule) {
	if _, exists := registry[r.ID]; exists {
		panic("recommended: duplicate rule ID " + r.ID)
	}
	registry[r.ID] = &r
	order = append(order, r.ID)
}

// AllRules returns every registered rule sorted by ID.
func AllRules() []Rule {
	ids := append([]string(nil), order...)
	sort.Strings(ids)
	rules := make([]Rule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, *registry[id])
	}
	return rules
}

// RuleByID returns the rule with the given ID, or false if it does not exist.
func RuleByID(id string) (Rule, bool) {
	r, ok := registry[id]
	if !ok {
		return Rule{}, false
	}
	return *r, true
}

// Filter narrows down the rule catalog by scope, minimum severity, explicit
// rule IDs, and ignored rule IDs. An empty ids slice means "no filter".
type Filter struct {
	Scope       Scope
	MinSeverity Severity
	IDs         []string
	IgnoreIDs   []string
	OnlyFixable bool
}

// Apply returns the rules matching the filter, sorted by ID.
func (fl Filter) Apply(rules []Rule) []Rule {
	include := toSet(fl.IDs)
	ignore := toSet(fl.IgnoreIDs)

	var out []Rule
	for _, r := range rules {
		if fl.Scope != "" && r.Scope != fl.Scope {
			continue
		}
		if fl.MinSeverity != "" && r.Severity.Rank() < fl.MinSeverity.Rank() {
			continue
		}
		if len(include) > 0 && !include[r.ID] {
			continue
		}
		if ignore[r.ID] {
			continue
		}
		if fl.OnlyFixable && !r.Fixable {
			continue
		}
		out = append(out, r)
	}
	return out
}

func toSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}
