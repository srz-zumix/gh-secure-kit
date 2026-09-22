package recommended

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	ghclient "github.com/srz-zumix/go-gh-extension/pkg/gh/client"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func newRulesetTestClient(t *testing.T, transport http.RoundTripper) *gh.GitHubClient {
	t.Helper()
	baseURL := "https://api.github.test/"
	client, err := github.NewClient(
		github.WithHTTPClient(&http.Client{Transport: transport}),
		github.WithURLs(&baseURL, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ghclient.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func rulesetResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    request,
	}
}

func remediationFacts() *RepositoryFacts {
	return &RepositoryFacts{Repo: &github.Repository{DefaultBranch: github.Ptr("main")}}
}

func TestBranchProtectionRulesetRemediationCreatesMinimalGSK110Ruleset(t *testing.T) {
	remediation, err := newBranchProtectionRulesetRemediation(remediationFacts(), nil)
	if err != nil {
		t.Fatalf("newBranchProtectionRulesetRemediation() error = %v", err)
	}
	if err := remediation.Apply("GSK110", remediationFacts()); err != nil {
		t.Fatalf("Apply(GSK110) error = %v", err)
	}

	ruleset := remediation.Ruleset()
	if ruleset.Name != branchProtectionRulesetName {
		t.Errorf("Name = %q, want %q", ruleset.Name, branchProtectionRulesetName)
	}
	if ruleset.Target == nil || *ruleset.Target != github.RulesetTargetBranch {
		t.Errorf("Target = %v, want branch", ruleset.Target)
	}
	if ruleset.GetEnforcement() != "active" {
		t.Errorf("Enforcement = %q, want active", ruleset.GetEnforcement())
	}
	if !rulesetTargetsBranch(ruleset.Conditions, "main") {
		t.Error("Ruleset does not target the default branch")
	}
	if ruleset.Rules.PullRequest == nil {
		t.Error("PullRequest is nil")
	}
	if ruleset.Rules.NonFastForward != nil || ruleset.Rules.RequiredStatusChecks != nil || ruleset.Rules.RequiredSignatures != nil {
		t.Error("GSK110 must create only pull-request protection")
	}
}

func TestBranchProtectionRulesetRemediationPreservesExistingRules(t *testing.T) {
	target := github.RulesetTargetBranch
	ruleset := &github.RepositoryRuleset{
		ID:          github.Ptr(int64(1)),
		Name:        branchProtectionRulesetName,
		Target:      &target,
		Enforcement: "active",
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}},
		},
		BypassActors: []*github.BypassActor{{ActorID: github.Ptr(int64(2))}},
		Rules: &github.RepositoryRulesetRules{
			CommitMessagePattern: &github.PatternRuleParameters{Pattern: "ABC-*"},
			PullRequest:          &github.PullRequestRuleParameters{RequiredApprovingReviewCount: 1},
			RequiredStatusChecks: &github.RequiredStatusChecksRuleParameters{RequiredStatusChecks: []*github.RuleStatusCheck{{Context: "test"}}},
		},
	}
	remediation, err := newBranchProtectionRulesetRemediation(remediationFacts(), ruleset)
	if err != nil {
		t.Fatalf("newBranchProtectionRulesetRemediation() error = %v", err)
	}
	for _, id := range []string{"GSK112", "GSK113", "GSK114", "GSK115", "GSK117", "GSK118"} {
		if err := remediation.Apply(id, remediationFacts()); err != nil {
			t.Fatalf("Apply(%s) error = %v", id, err)
		}
	}

	got := remediation.Ruleset()
	if got.Rules.CommitMessagePattern == nil || got.Rules.CommitMessagePattern.Pattern != "ABC-*" {
		t.Error("CommitMessagePattern was not preserved")
	}
	if len(got.BypassActors) != 1 || got.BypassActors[0].GetActorID() != 2 {
		t.Error("BypassActors were not preserved")
	}
	if got.Rules.PullRequest.GetRequiredApprovingReviewCount() != 2 || !got.Rules.PullRequest.DismissStaleReviewsOnPush || !got.Rules.PullRequest.RequireCodeOwnerReview {
		t.Errorf("PullRequest = %+v, want 2 approvals with stale and CODEOWNER review requirements", got.Rules.PullRequest)
	}
	if !got.Rules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy {
		t.Error("RequiredStatusChecks is not strict")
	}
	if got.Rules.NonFastForward == nil || got.Rules.RequiredSignatures == nil {
		t.Error("NonFastForward or RequiredSignatures was not added")
	}
}

func TestBranchProtectionRulesetRemediationRejectsUnsafeRuleset(t *testing.T) {
	target := github.RulesetTargetTag
	unsafe := &github.RepositoryRuleset{Name: branchProtectionRulesetName, Target: &target}
	if _, err := newBranchProtectionRulesetRemediation(remediationFacts(), unsafe); err == nil {
		t.Error("expected a non-branch ruleset to be rejected")
	}

	unsafe.Name = "user-managed"
	if _, err := newBranchProtectionRulesetRemediation(remediationFacts(), unsafe); err == nil {
		t.Error("expected a user-managed ruleset to be rejected")
	}
}

func TestBranchProtectionRulesetRemediationUpdatePayloadStripsServerFields(t *testing.T) {
	target := github.RulesetTargetBranch
	sourceType := github.RulesetSourceTypeRepository
	existing := &github.RepositoryRuleset{
		ID:                   github.Ptr(int64(1)),
		Name:                 branchProtectionRulesetName,
		Target:               &target,
		Source:               "owner/repo",
		SourceType:           &sourceType,
		CurrentUserCanBypass: github.Ptr(github.BypassModeAlways),
		NodeID:               github.Ptr("RRS_1"),
		Links:                &github.RepositoryRulesetLinks{},
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}},
		},
		Rules: &github.RepositoryRulesetRules{NonFastForward: &github.EmptyRuleParameters{}},
	}
	remediation, err := newBranchProtectionRulesetRemediation(remediationFacts(), existing)
	if err != nil {
		t.Fatalf("newBranchProtectionRulesetRemediation() error = %v", err)
	}
	payload := remediation.UpdatePayload()
	if payload.ID != nil || payload.Source != "" || payload.SourceType != nil || payload.CurrentUserCanBypass != nil || payload.NodeID != nil || payload.Links != nil {
		t.Errorf("UpdatePayload retained server-managed fields: %+v", payload)
	}
	if payload.Rules.NonFastForward == nil || !rulesetTargetsBranch(payload.Conditions, "main") {
		t.Error("UpdatePayload did not preserve configurable ruleset fields")
	}
}

func TestBranchProtectionRulesetRemediationDoesNotFixGSK116(t *testing.T) {
	remediation, err := newBranchProtectionRulesetRemediation(remediationFacts(), nil)
	if err != nil {
		t.Fatalf("newBranchProtectionRulesetRemediation() error = %v", err)
	}
	if err := remediation.Apply("GSK116", remediationFacts()); err == nil {
		t.Error("expected GSK116 to remain non-fixable")
	}
}

func TestBranchProtectionRulesetRemediationRespectsSelectedReviewRules(t *testing.T) {
	tests := []struct {
		name    string
		ruleIDs []string
		want    int
	}{
		{name: "GSK111 only", ruleIDs: []string{"GSK110", "GSK111"}, want: 1},
		{name: "GSK111 and GSK112", ruleIDs: []string{"GSK110", "GSK111", "GSK112"}, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			remediation, err := newBranchProtectionRulesetRemediation(remediationFacts(), nil)
			if err != nil {
				t.Fatalf("newBranchProtectionRulesetRemediation() error = %v", err)
			}
			for _, id := range tc.ruleIDs {
				if err := remediation.Apply(id, remediationFacts()); err != nil {
					t.Fatalf("Apply(%s) error = %v", id, err)
				}
			}
			if got := remediation.Ruleset().Rules.PullRequest.GetRequiredApprovingReviewCount(); got != tc.want {
				t.Errorf("RequiredApprovingReviewCount = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestBranchProtectionRulesetRemediationAppliesOnlySelectedRequirements(t *testing.T) {
	remediation, err := newBranchProtectionRulesetRemediation(remediationFacts(), nil)
	if err != nil {
		t.Fatalf("newBranchProtectionRulesetRemediation() error = %v", err)
	}
	for _, id := range []string{"GSK110", "GSK111", "GSK113"} {
		if err := remediation.Apply(id, remediationFacts()); err != nil {
			t.Fatalf("Apply(%s) error = %v", id, err)
		}
	}
	rules := remediation.Ruleset().Rules
	if rules.PullRequest.GetRequiredApprovingReviewCount() != 1 || !rules.PullRequest.DismissStaleReviewsOnPush {
		t.Errorf("PullRequest = %+v, want only GSK111 and GSK113 requirements", rules.PullRequest)
	}
	if rules.PullRequest.RequireCodeOwnerReview || rules.NonFastForward != nil || rules.RequiredSignatures != nil {
		t.Errorf("Rules = %+v, want ignored requirements to remain absent", rules)
	}
}

func TestBranchProtectionRulesetRemediationAddsStrictStatusRuleWithoutChecks(t *testing.T) {
	remediation, err := newBranchProtectionRulesetRemediation(remediationFacts(), nil)
	if err != nil {
		t.Fatalf("newBranchProtectionRulesetRemediation() error = %v", err)
	}
	if err := remediation.Apply("GSK115", remediationFacts()); err != nil {
		t.Fatalf("Apply(GSK115) error = %v", err)
	}
	statusChecks := remediation.Ruleset().Rules.RequiredStatusChecks
	if statusChecks == nil || !statusChecks.StrictRequiredStatusChecksPolicy {
		t.Errorf("RequiredStatusChecks = %+v, want strict rule", statusChecks)
	}
	if statusChecks.RequiredStatusChecks == nil || len(statusChecks.RequiredStatusChecks) != 0 {
		t.Errorf("RequiredStatusChecks = %#v, want empty non-nil slice", statusChecks.RequiredStatusChecks)
	}
}

func TestAddOwnerBypassActorUsesExemptMode(t *testing.T) {
	facts := remediationFacts()
	facts.Repo.Owner = &github.User{Login: github.Ptr("owner"), ID: github.Ptr(int64(42)), Type: github.Ptr("User")}
	ruleset := &github.RepositoryRuleset{}
	if err := addOwnerBypassActor(ruleset, facts); err != nil {
		t.Fatalf("addOwnerBypassActor() error = %v", err)
	}
	if len(ruleset.BypassActors) != 1 {
		t.Fatalf("BypassActors length = %d, want 1", len(ruleset.BypassActors))
	}
	actor := ruleset.BypassActors[0]
	if actor.GetActorID() != 42 || actor.GetActorType() == nil || *actor.GetActorType() != github.BypassActorType("User") || actor.GetBypassMode() == nil || *actor.GetBypassMode() != github.BypassModeExempt {
		t.Errorf("BypassActor = %+v, want owner User with exempt mode", actor)
	}
}

func TestAddOwnerBypassActorRejectsNonUserOwner(t *testing.T) {
	facts := remediationFacts()
	facts.Repo.Owner = &github.User{Login: github.Ptr("org"), ID: github.Ptr(int64(7)), Type: github.Ptr("Organization")}
	if err := addOwnerBypassActor(&github.RepositoryRuleset{}, facts); err == nil {
		t.Fatal("addOwnerBypassActor() with organization owner: got nil error, want rejection")
	}
}

func TestReviewRulesetHasUnexpectedRules(t *testing.T) {
	if reviewRulesetHasUnexpectedRules(nil) {
		t.Error("nil rules should not be unexpected")
	}
	onlyReview := &github.RepositoryRulesetRules{PullRequest: &github.PullRequestRuleParameters{}}
	if reviewRulesetHasUnexpectedRules(onlyReview) {
		t.Error("pull-request-only rules should not be unexpected")
	}
	withForeign := &github.RepositoryRulesetRules{
		PullRequest:    &github.PullRequestRuleParameters{},
		NonFastForward: &github.EmptyRuleParameters{},
	}
	if !reviewRulesetHasUnexpectedRules(withForeign) {
		t.Error("rules other than pull request should be reported as unexpected")
	}
}

func TestApplyReviewRulesetRefusesExistingForeignRules(t *testing.T) {
	facts := remediationFacts()
	facts.Repo.Owner = &github.User{Login: github.Ptr("owner"), ID: github.Ptr(int64(42)), Type: github.Ptr("User")}
	existing := github.RepositoryRuleset{
		ID:          github.Ptr(int64(9)),
		Name:        branchProtectionReviewRulesetName,
		Target:      github.Ptr(github.RulesetTargetBranch),
		Enforcement: github.RulesetEnforcementActive,
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}},
		},
		Rules: &github.RepositoryRulesetRules{NonFastForward: &github.EmptyRuleParameters{}},
	}
	listBody, err := json.Marshal([]github.RepositoryRuleset{{ID: github.Ptr(int64(9)), Name: branchProtectionReviewRulesetName}})
	if err != nil {
		t.Fatalf("marshal list: %v", err)
	}
	detailBody, err := json.Marshal(existing)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets":
			return rulesetResponse(request, http.StatusOK, string(listBody)), nil
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets/9":
			return rulesetResponse(request, http.StatusOK, string(detailBody)), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	}))
	repo := repository.Repository{Owner: "owner", Name: "repo"}
	err = applyNamedBranchProtectionRuleset(context.Background(), client, repo, facts, branchProtectionReviewRulesetName, []string{"GSK111"}, true)
	if err == nil {
		t.Fatal("applyNamedBranchProtectionRuleset() with foreign rules: got nil error, want refusal")
	}
}

func TestApplyReviewRulesetRefusesBroaderBranchScope(t *testing.T) {
	facts := remediationFacts()
	facts.Repo.Owner = &github.User{Login: github.Ptr("owner"), ID: github.Ptr(int64(42)), Type: github.Ptr("User")}
	existing := github.RepositoryRuleset{
		ID:          github.Ptr(int64(9)),
		Name:        branchProtectionReviewRulesetName,
		Target:      github.Ptr(github.RulesetTargetBranch),
		Enforcement: github.RulesetEnforcementActive,
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH", "refs/heads/release/*"}},
		},
		Rules: &github.RepositoryRulesetRules{PullRequest: &github.PullRequestRuleParameters{}},
	}
	listBody, err := json.Marshal([]github.RepositoryRuleset{{ID: github.Ptr(int64(9)), Name: branchProtectionReviewRulesetName}})
	if err != nil {
		t.Fatalf("marshal list: %v", err)
	}
	detailBody, err := json.Marshal(existing)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets":
			return rulesetResponse(request, http.StatusOK, string(listBody)), nil
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets/9":
			return rulesetResponse(request, http.StatusOK, string(detailBody)), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	}))
	repo := repository.Repository{Owner: "owner", Name: "repo"}
	err = applyNamedBranchProtectionRuleset(context.Background(), client, repo, facts, branchProtectionReviewRulesetName, []string{"GSK111"}, true)
	if err == nil {
		t.Fatal("applyNamedBranchProtectionRuleset() with broader branch scope: got nil error, want refusal")
	}
}

func TestRulesetTargetsOnlyDefaultBranch(t *testing.T) {
	onlyDefault := &github.RepositoryRulesetConditions{
		RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}},
	}
	if !rulesetTargetsOnlyDefaultBranch(onlyDefault, "main") {
		t.Error("~DEFAULT_BRANCH only should target only the default branch")
	}
	explicit := &github.RepositoryRulesetConditions{
		RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"refs/heads/main"}},
	}
	if !rulesetTargetsOnlyDefaultBranch(explicit, "main") {
		t.Error("explicit default-branch ref should target only the default branch")
	}
	broader := &github.RepositoryRulesetConditions{
		RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH", "refs/heads/dev"}},
	}
	if rulesetTargetsOnlyDefaultBranch(broader, "main") {
		t.Error("multiple includes should not count as default-branch only")
	}
	excluded := &github.RepositoryRulesetConditions{
		RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}, Exclude: []string{"refs/heads/x"}},
	}
	if rulesetTargetsOnlyDefaultBranch(excluded, "main") {
		t.Error("a non-empty exclude should not count as default-branch only")
	}
	if rulesetTargetsOnlyDefaultBranch(nil, "main") {
		t.Error("nil conditions should not target the default branch")
	}
}

func TestDefaultBranchHasEnforcedPullRequest(t *testing.T) {
	base := func() *RepositoryFacts {
		return &RepositoryFacts{Repo: &github.Repository{DefaultBranch: github.Ptr("main")}, RulesetsKnown: true}
	}
	if defaultBranchHasEnforcedPullRequest(base()) {
		t.Error("no protection should not be treated as enforced pull request")
	}

	legacyNoAdmin := base()
	legacyNoAdmin.Protection = &github.Protection{RequiredPullRequestReviews: &github.PullRequestReviewsEnforcement{}}
	if defaultBranchHasEnforcedPullRequest(legacyNoAdmin) {
		t.Error("legacy PR reviews without admin enforcement should not count (owner can bypass)")
	}

	legacyAdmin := base()
	legacyAdmin.Protection = &github.Protection{
		RequiredPullRequestReviews: &github.PullRequestReviewsEnforcement{},
		EnforceAdmins:              &github.AdminEnforcement{Enabled: true},
	}
	if !defaultBranchHasEnforcedPullRequest(legacyAdmin) {
		t.Error("legacy PR reviews with admin enforcement should count")
	}

	rulesetNoBypass := base()
	rulesetNoBypass.Rulesets = []*github.RepositoryRuleset{{
		Target:      github.Ptr(github.RulesetTargetBranch),
		Enforcement: github.RulesetEnforcementActive,
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}},
		},
		Rules: &github.RepositoryRulesetRules{PullRequest: &github.PullRequestRuleParameters{}},
	}}
	if !defaultBranchHasEnforcedPullRequest(rulesetNoBypass) {
		t.Error("active default-branch PR ruleset without full bypass should count")
	}

	rulesetBypass := base()
	rulesetBypass.Rulesets = []*github.RepositoryRuleset{{
		Target:      github.Ptr(github.RulesetTargetBranch),
		Enforcement: github.RulesetEnforcementActive,
		Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}},
		},
		Rules:        &github.RepositoryRulesetRules{PullRequest: &github.PullRequestRuleParameters{}},
		BypassActors: []*github.BypassActor{{ActorID: github.Ptr(int64(42)), ActorType: github.Ptr(github.BypassActorType("User")), BypassMode: github.Ptr(github.BypassModeExempt)}},
	}}
	if defaultBranchHasEnforcedPullRequest(rulesetBypass) {
		t.Error("PR ruleset with a full bypass actor should not count as enforced")
	}
}

func TestApplyBranchProtectionRulesetCreatesSingleRuleset(t *testing.T) {
	var createCount int
	var payload github.RepositoryRuleset
	var rawPayload map[string]any
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets":
			return rulesetResponse(request, http.StatusOK, "[]"), nil
		case request.Method == http.MethodPost && request.URL.Path == "/repos/owner/repo/rulesets":
			createCount++
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("read request: %v", err)
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if err := json.Unmarshal(body, &rawPayload); err != nil {
				t.Fatalf("decode raw request: %v", err)
			}
			return rulesetResponse(request, http.StatusCreated, `{"id":1}`), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	}))
	repo := repository.Repository{Owner: "owner", Name: "repo"}
	if err := applyBranchProtectionRuleset(context.Background(), client, repo, remediationFacts(), []string{"GSK110"}); err != nil {
		t.Fatalf("applyBranchProtectionRuleset() error = %v", err)
	}
	if createCount != 1 {
		t.Errorf("create count = %d, want 1", createCount)
	}
	if payload.Name != branchProtectionRulesetName {
		t.Errorf("created payload = %+v, want named minimum branch-protection ruleset", payload)
	}
	if payload.Rules.PullRequest == nil || payload.Rules.NonFastForward != nil || payload.Rules.RequiredStatusChecks != nil || payload.Rules.RequiredSignatures != nil {
		t.Errorf("created payload = %+v, want only pull-request rule", payload.Rules)
	}
	refName := rawPayload["conditions"].(map[string]any)["ref_name"].(map[string]any)
	if exclude, ok := refName["exclude"].([]any); !ok || len(exclude) != 0 {
		t.Errorf("conditions.ref_name.exclude = %#v, want []", refName["exclude"])
	}
}

func TestApplyBranchProtectionRulesetCreatesOnlySelectedRequirements(t *testing.T) {
	var payload github.RepositoryRuleset
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets":
			return rulesetResponse(request, http.StatusOK, "[]"), nil
		case request.Method == http.MethodPost && request.URL.Path == "/repos/owner/repo/rulesets":
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			return rulesetResponse(request, http.StatusCreated, `{"id":1}`), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	}))
	repo := repository.Repository{Owner: "owner", Name: "repo"}
	if err := applyBranchProtectionRuleset(context.Background(), client, repo, remediationFacts(), []string{"GSK110", "GSK111", "GSK113"}); err != nil {
		t.Fatalf("applyBranchProtectionRuleset() error = %v", err)
	}
	rules := payload.Rules
	if rules.PullRequest == nil || rules.PullRequest.RequiredApprovingReviewCount != 1 || !rules.PullRequest.DismissStaleReviewsOnPush {
		t.Errorf("PullRequest = %+v, want only GSK111 and GSK113 requirements", rules.PullRequest)
	}
	if rules.PullRequest.RequireCodeOwnerReview || rules.NonFastForward != nil || rules.RequiredStatusChecks != nil || rules.RequiredSignatures != nil {
		t.Errorf("Rules = %+v, want omitted requirements to remain absent", rules)
	}
}

func TestApplyBranchProtectionRulesetUpdatesOnce(t *testing.T) {
	var updateCount int
	var payload github.RepositoryRuleset
	existing := `[{"id":1,"name":"gh-secure-kit/branch-protection","target":"branch","enforcement":"active"}]`
	details := `{"id":1,"name":"gh-secure-kit/branch-protection","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"test"}],"strict_required_status_checks_policy":false}}]}`
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets":
			return rulesetResponse(request, http.StatusOK, existing), nil
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets/1":
			return rulesetResponse(request, http.StatusOK, details), nil
		case request.Method == http.MethodPut && request.URL.Path == "/repos/owner/repo/rulesets/1":
			updateCount++
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			return rulesetResponse(request, http.StatusOK, `{"id":1}`), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	}))
	repo := repository.Repository{Owner: "owner", Name: "repo"}
	if err := applyBranchProtectionRuleset(context.Background(), client, repo, remediationFacts(), []string{"GSK112", "GSK113", "GSK114", "GSK115", "GSK117", "GSK118"}); err != nil {
		t.Fatalf("applyBranchProtectionRuleset() error = %v", err)
	}
	if updateCount != 1 {
		t.Errorf("update count = %d, want 1", updateCount)
	}
	if payload.Rules.PullRequest == nil || payload.Rules.PullRequest.RequiredApprovingReviewCount != 2 || !payload.Rules.PullRequest.DismissStaleReviewsOnPush || !payload.Rules.PullRequest.RequireCodeOwnerReview {
		t.Errorf("PullRequest = %+v, want merged review requirements", payload.Rules.PullRequest)
	}
	if payload.Rules.RequiredStatusChecks == nil || !payload.Rules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy {
		t.Errorf("RequiredStatusChecks = %+v, want strict policy", payload.Rules.RequiredStatusChecks)
	}
	if payload.Rules.NonFastForward == nil || payload.Rules.RequiredSignatures == nil {
		t.Error("NonFastForward or RequiredSignatures was not added")
	}
}

func TestApplyBranchProtectionRulesetActivatesEvaluateRuleset(t *testing.T) {
	var payload github.RepositoryRuleset
	existing := `[{"id":1,"name":"gh-secure-kit/branch-protection","target":"branch","enforcement":"evaluate"}]`
	details := `{"id":1,"name":"gh-secure-kit/branch-protection","target":"branch","enforcement":"evaluate","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[]}`
	client := newRulesetTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets":
			return rulesetResponse(request, http.StatusOK, existing), nil
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repo/rulesets/1":
			return rulesetResponse(request, http.StatusOK, details), nil
		case request.Method == http.MethodPut && request.URL.Path == "/repos/owner/repo/rulesets/1":
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			return rulesetResponse(request, http.StatusOK, `{"id":1}`), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	}))
	repo := repository.Repository{Owner: "owner", Name: "repo"}
	if err := applyBranchProtectionRuleset(context.Background(), client, repo, remediationFacts(), []string{"GSK110"}); err != nil {
		t.Fatalf("applyBranchProtectionRuleset() error = %v", err)
	}
	if payload.GetEnforcement() != github.RulesetEnforcementActive {
		t.Errorf("Enforcement = %q, want %q", payload.GetEnforcement(), github.RulesetEnforcementActive)
	}
}
