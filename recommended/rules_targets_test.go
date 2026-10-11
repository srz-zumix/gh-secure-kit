package recommended

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-github/v90/github"
)

func mustIgnores(t *testing.T, entries ...IgnoreEntry) TargetIgnores {
	t.Helper()
	ignores, err := (&Config{Ignore: entries}).TargetIgnores()
	if err != nil {
		t.Fatal(err)
	}
	return ignores
}

func repoOutcome(t *testing.T, id string, f *RepositoryFacts) Outcome {
	t.Helper()
	rule, ok := RuleByID(id)
	if !ok || rule.CheckRepo == nil {
		t.Fatalf("rule %s not found", id)
	}
	return rule.CheckRepo(f)
}

func TestTargetIgnoresMatchWholeTarget(t *testing.T) {
	ignores := mustIgnores(t, IgnoreEntry{ID: "gsk131", Targets: []string{"release-.*", "a|b"}})
	for target, want := range map[string]bool{
		"release-1":      true,
		"my-release-1":   false,
		"a":              true,
		"b":              true,
		"ab":             false,
		"unrelated-rule": false,
	} {
		if got := ignores.Match("GSK131", target); got != want {
			t.Errorf("Match(%q) = %v, want %v", target, got, want)
		}
	}
	var none TargetIgnores
	if none.Match("GSK131", "a") {
		t.Error("nil TargetIgnores must not match")
	}
}

func TestGSK131IgnoresRulesetsByName(t *testing.T) {
	newFacts := func(names ...string) *RepositoryFacts {
		var rulesets []*github.RepositoryRuleset
		for _, name := range names {
			rs := branchRuleset([]string{"~DEFAULT_BRANCH"}, nil, false)
			rs.Name = name
			rs.BypassActors = []*github.BypassActor{{
				ActorType:  github.Ptr(github.BypassActorTypeIntegration),
				BypassMode: github.Ptr(github.BypassModeAlways),
			}}
			rulesets = append(rulesets, rs)
		}
		return factsWithRulesets(rulesets...)
	}

	f := newFacts("one", "two")
	got := repoOutcome(t, "GSK131", f)
	if got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"one", "two"}) {
		t.Fatalf("no ignores: got %+v", got)
	}

	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK131", Targets: []string{"one"}})
	got = repoOutcome(t, "GSK131", f)
	if got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"two"}) || strings.Contains(got.Detail, "one") {
		t.Fatalf("one ignored: got %+v", got)
	}

	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK131", Targets: []string{"one", "t.*"}})
	got = repoOutcome(t, "GSK131", f)
	if got.Status != StatusSkip || got.Targets != nil || !strings.Contains(got.Detail, "one, two") {
		t.Fatalf("all ignored: got %+v", got)
	}
}

func TestGSK131LegacyFindingIsNotTargeted(t *testing.T) {
	f := factsWithRulesets()
	f.Protection = &github.Protection{EnforceAdmins: &github.AdminEnforcement{Enabled: false}}
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK131", Targets: []string{".*"}})
	got := repoOutcome(t, "GSK131", f)
	if got.Status != StatusFail || got.Targets != nil {
		t.Fatalf("got %+v, want untargeted failure", got)
	}
}

func TestEnvironmentRulesIgnoreEnvironmentsByName(t *testing.T) {
	reviewer := []*github.ProtectionRule{{Type: github.Ptr("required_reviewers"), Reviewers: []*github.RequiredReviewer{{Type: github.Ptr("User")}}}}
	f := &RepositoryFacts{
		EnvironmentsKnown:       true,
		EnvironmentSecretsKnown: map[string]bool{"prod": true, "stage": true},
		Environments: []*github.Environment{
			{Name: github.Ptr("prod"), ProtectionRules: reviewer},
			{Name: github.Ptr("stage"), ProtectionRules: reviewer},
		},
		EnvironmentSecrets: map[string][]*github.Secret{"prod": {{Name: "T"}}, "stage": {{Name: "T"}}},
	}
	got := repoOutcome(t, "GSK136", f)
	if got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"prod", "stage"}) {
		t.Fatalf("no ignores: got %+v", got)
	}
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK136", Targets: []string{"prod"}})
	got = repoOutcome(t, "GSK136", f)
	if got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"stage"}) {
		t.Fatalf("prod ignored: got %+v", got)
	}
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK136", Targets: []string{"prod", "stage"}})
	if got = repoOutcome(t, "GSK136", f); got.Status != StatusSkip {
		t.Fatalf("all ignored: got %+v", got)
	}
	// Ignores of one rule do not affect another.
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK135", Targets: []string{".*"}})
	if got = repoOutcome(t, "GSK136", f); got.Status != StatusFail {
		t.Fatalf("other rule ignored: got %+v", got)
	}
}

func TestDeployKeyRulesListAndIgnoreKeys(t *testing.T) {
	f := &RepositoryFacts{DeployKeysKnown: true, DeployKeys: []*github.Key{
		{ID: github.Ptr(int64(10)), Title: github.Ptr("ci"), ReadOnly: github.Ptr(false), Verified: github.Ptr(true)},
		{ID: github.Ptr(int64(11)), Title: github.Ptr("bot"), ReadOnly: github.Ptr(false), Verified: github.Ptr(true)},
		{ID: github.Ptr(int64(12)), Title: github.Ptr("ro"), ReadOnly: github.Ptr(true), Verified: github.Ptr(true)},
	}}
	got := repoOutcome(t, "GSK121", f)
	if got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"10", "11"}) || !strings.Contains(got.Detail, "10 (ci)") {
		t.Fatalf("got %+v", got)
	}
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK121", Targets: []string{"10"}})
	if got = repoOutcome(t, "GSK121", f); got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"11"}) {
		t.Fatalf("one ignored: got %+v", got)
	}
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK121", Targets: []string{"1."}})
	if got = repoOutcome(t, "GSK121", f); got.Status != StatusSkip {
		t.Fatalf("all ignored: got %+v", got)
	}
	if got = repoOutcome(t, "GSK122", f); got.Status != StatusPass {
		t.Fatalf("verified keys: got %+v", got)
	}
}

func TestCollaboratorRulesIgnoreLogins(t *testing.T) {
	admin := func(login string) *github.User {
		return &github.User{Login: github.Ptr(login), Permissions: &github.RepositoryPermissions{Admin: github.Ptr(true)}}
	}
	f := &RepositoryFacts{CollaboratorsKnown: true, Collaborators: []*github.User{admin("a"), admin("b"), admin("c"), admin("bot-d")}}
	if got := repoOutcome(t, "GSK119", f); got.Status != StatusFail {
		t.Fatalf("GSK119 no ignores: got %+v", got)
	}
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK119", Targets: []string{"bot-.*"}})
	if got := repoOutcome(t, "GSK119", f); got.Status != StatusSkip {
		t.Fatalf("GSK119 ignored: got %+v", got)
	}

	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK120", Targets: []string{"a", "b"}})
	got := repoOutcome(t, "GSK120", f)
	if got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"c", "bot-d"}) {
		t.Fatalf("GSK120 partially ignored: got %+v", got)
	}
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK120", Targets: []string{".*"}})
	if got = repoOutcome(t, "GSK120", f); got.Status != StatusSkip {
		t.Fatalf("GSK120 all ignored: got %+v", got)
	}
}

func TestOrganizationRulesIgnoreTargets(t *testing.T) {
	f := &OrganizationFacts{
		RunnerGroupsKnown: true,
		RunnerGroups: []*github.RunnerGroup{
			{Name: github.Ptr("legacy"), AllowsPublicRepositories: github.Ptr(true)},
			{Name: github.Ptr("other"), AllowsPublicRepositories: github.Ptr(true)},
		},
		SuspendedMembersKnown: true,
		SuspendedMembers:      []*github.User{{Login: github.Ptr("zed")}, {Login: github.Ptr("amy")}},
	}
	check := func(id string) Outcome {
		rule, _ := RuleByID(id)
		return rule.CheckOrg(f)
	}

	if got := check("GSK523"); got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"legacy", "other"}) {
		t.Fatalf("GSK523: got %+v", got)
	}
	if got := check("GSK522"); got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"amy", "zed"}) {
		t.Fatalf("GSK522: got %+v", got)
	}

	f.ignores = mustIgnores(t,
		IgnoreEntry{ID: "GSK523", Targets: []string{"legacy"}},
		IgnoreEntry{ID: "GSK522", Targets: []string{"amy", "zed"}},
	)
	if got := check("GSK523"); got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"other"}) {
		t.Fatalf("GSK523 partially ignored: got %+v", got)
	}
	if got := check("GSK522"); got.Status != StatusSkip {
		t.Fatalf("GSK522 all ignored: got %+v", got)
	}
}

func TestWebhookRulesIgnoreHookIDs(t *testing.T) {
	hook := func(id int64) *github.Hook {
		return &github.Hook{ID: github.Ptr(id), Active: github.Ptr(true), Config: &github.HookConfig{URL: github.Ptr("https://example.com"), InsecureSSL: github.Ptr("0")}}
	}
	f := &RepositoryFacts{HooksKnown: true, Hooks: []*github.Hook{hook(9), hook(10)}}
	got := repoOutcome(t, "GSK145", f)
	if got.Status != StatusFail || !reflect.DeepEqual(got.Targets, []string{"9", "10"}) {
		t.Fatalf("got %+v", got)
	}
	f.ignores = mustIgnores(t, IgnoreEntry{ID: "GSK145", Targets: []string{"9", "10"}})
	if got = repoOutcome(t, "GSK145", f); got.Status != StatusSkip {
		t.Fatalf("all ignored: got %+v", got)
	}
}

func TestTargetKindRulesAcceptTargetsInConfig(t *testing.T) {
	for _, id := range []string{"GSK119", "GSK120", "GSK121", "GSK122", "GSK131", "GSK135", "GSK136", "GSK137", "GSK144", "GSK145", "GSK521", "GSK522", "GSK523", "GSK524", "GSK525"} {
		rule, ok := RuleByID(id)
		if !ok || rule.TargetKind == "" {
			t.Errorf("%s: missing TargetKind", id)
		}
	}
}
