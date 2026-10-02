package recommended

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v90/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

const tagProtectionRulesetName = "gh-secure-kit/tag-protection"

func init() {
	registerRepositoryRulesetRules()
}

var (
	fullSemverTag = regexp.MustCompile(`^(v?)\d+\.\d+\.\d+(?:[-+].*)?$`)
	majorOnlyTag  = regexp.MustCompile(`^(v?)\d+$`)
	majorMinorTag = regexp.MustCompile(`^(v?)\d+\.\d+$`)
)

// abbreviatedTagExcludePatterns returns ruleset ref patterns for moving tags such
// as "v1" or "v1.2". A tag is moving when it points at the same commit as a
// full SemVer tag with the same prefix; protecting those would block the
// routine re-pointing of major/minor tags on release.
func abbreviatedTagExcludePatterns(tags []*github.RepositoryTag) []string {
	fullAt := make(map[string]bool)
	for _, t := range tags {
		sha := t.GetCommit().GetSHA()
		if m := fullSemverTag.FindStringSubmatch(t.GetName()); m != nil && sha != "" {
			fullAt[m[1]+"|"+sha] = true
		}
	}

	// Up to two digits per component keeps the patterns bounded while covering
	// the next major/minor bump of an observed tag (v9 -> v10).
	const maxDigits = 2
	digits := func(n int) string { return strings.Repeat("[0-9]", n) }

	patterns := make(map[string]struct{})
	for _, t := range tags {
		name := t.GetName()
		key := func(prefix string) string { return prefix + "|" + t.GetCommit().GetSHA() }
		if m := majorOnlyTag.FindStringSubmatch(name); m != nil && fullAt[key(m[1])] {
			for d := 1; d <= maxDigits; d++ {
				patterns["refs/tags/"+m[1]+digits(d)] = struct{}{}
			}
		}
		if m := majorMinorTag.FindStringSubmatch(name); m != nil && fullAt[key(m[1])] {
			for major := 1; major <= maxDigits; major++ {
				for minor := 1; minor <= maxDigits; minor++ {
					patterns["refs/tags/"+m[1]+digits(major)+"."+digits(minor)] = struct{}{}
				}
			}
		}
	}

	result := make([]string, 0, len(patterns))
	for p := range patterns {
		result = append(result, p)
	}
	sort.Strings(result)
	return result
}

// rulesetTargetsAllTags reports whether the ruleset conditions include every tag.
// Exclusions are ignored so that rulesets exempting moving tags still count.
func rulesetTargetsAllTags(conditions *github.RepositoryRulesetConditions) bool {
	if conditions == nil || conditions.RefName == nil {
		return false
	}
	for _, include := range conditions.RefName.Include {
		switch include {
		case "~ALL", "refs/tags/**", "refs/tags/*":
			return true
		}
	}
	return false
}

// activeRulesetsWithTarget returns active rulesets of the given target that carry rules.
func activeRulesetsWithTarget(f *RepositoryFacts, target github.RulesetTarget) []*github.RepositoryRuleset {
	var result []*github.RepositoryRuleset
	for _, rs := range f.Rulesets {
		if rs.GetEnforcement() != "active" || rs.Target == nil || *rs.Target != target || rs.Rules == nil {
			continue
		}
		result = append(result, rs)
	}
	return result
}

func registerRepositoryRulesetRules() {
	register(Rule{
		ID: "GSK140", GHQRID: "", Scope: ScopeRepository,
		Category: "security", Severity: SeverityMedium, Title: "Tags are not protected by a tag ruleset", Fixable: true,
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if f.HasTags == nil {
				return Skip("could not determine whether the repository has tags")
			}
			if !*f.HasTags {
				return Skip("repository has no tags")
			}
			if !f.RulesetsKnown {
				return Skip("could not determine the rulesets of the repository")
			}
			var deletion, update bool
			for _, rs := range activeRulesetsWithTarget(f, github.RulesetTargetTag) {
				if !rulesetTargetsAllTags(rs.Conditions) {
					continue
				}
				deletion = deletion || rs.Rules.Deletion != nil
				update = update || rs.Rules.Update != nil
			}
			var missing []string
			if !deletion {
				missing = append(missing, "deletion")
			}
			if !update {
				missing = append(missing, "update")
			}
			if len(missing) > 0 {
				return Fail(fmt.Sprintf("no active tag ruleset restricts tag %s; published tags can be moved or deleted", strings.Join(missing, " and ")))
			}
			return Pass("an active tag ruleset restricts tag deletion and updates")
		},
		ApplyRepo: func(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, f *RepositoryFacts) error {
			return applyTagProtectionRuleset(ctx, g, repo)
		},
	})

	register(Rule{
		ID: "GSK143", GHQRID: "", Scope: ScopeRepository,
		Category: "security", Severity: SeverityInfo, Title: "No push ruleset restricting pushed files",
		CheckRepo: func(f *RepositoryFacts) Outcome {
			if !isPrivateOrInternal(f.Repo) {
				return Skip("push rulesets only apply to private and internal repositories")
			}
			if !f.RulesetsKnown {
				return Skip("could not determine the rulesets of the repository")
			}
			for _, rs := range activeRulesetsWithTarget(f, github.RulesetTargetPush) {
				r := rs.Rules
				if r.FilePathRestriction != nil || r.FileExtensionRestriction != nil || r.MaxFileSize != nil || r.MaxFilePathLength != nil {
					return Pass("an active push ruleset restricts pushed files")
				}
			}
			return Fail("no active push ruleset restricts file paths, extensions, or sizes; sensitive or oversized files can be pushed")
		},
	})
}

// applyTagProtectionRuleset creates or updates the tool-owned tag ruleset that
// forbids deleting, moving, and force-pushing tags other than moving tags.
func applyTagProtectionRuleset(ctx context.Context, g *gh.GitHubClient, repo repository.Repository) error {
	tags, err := gh.ListTags(ctx, g, repo)
	if err != nil {
		return fmt.Errorf("failed to list tags: %w", err)
	}
	excludes := abbreviatedTagExcludePatterns(tags)

	existing, err := gh.FindRepositoryRulesetByName(ctx, g, repo, tagProtectionRulesetName, false)
	if err != nil {
		return fmt.Errorf("failed to find ruleset %q: %w", tagProtectionRulesetName, err)
	}
	if existing == nil {
		target := github.RulesetTargetTag
		ruleset := &github.RepositoryRuleset{
			Name:        tagProtectionRulesetName,
			Target:      &target,
			Enforcement: github.RulesetEnforcementActive,
			Conditions: &github.RepositoryRulesetConditions{
				RefName: &github.RepositoryRulesetRefConditionParameters{
					Include: []string{"~ALL"},
					Exclude: nonNilStrings(excludes),
				},
			},
			Rules: &github.RepositoryRulesetRules{
				Deletion:       &github.EmptyRuleParameters{},
				Update:         &github.UpdateRuleParameters{},
				NonFastForward: &github.EmptyRuleParameters{},
			},
		}
		if _, err := gh.CreateRepositoryRuleset(ctx, g, repo, ruleset); err != nil {
			return fmt.Errorf("failed to create ruleset %q: %w", tagProtectionRulesetName, err)
		}
		return nil
	}

	if existing.GetID() == 0 {
		return fmt.Errorf("ruleset %q has no ID", tagProtectionRulesetName)
	}
	ruleset, err := gh.GetRepositoryRuleset(ctx, g, repo, existing.GetID(), false)
	if err != nil {
		return fmt.Errorf("failed to get ruleset %q: %w", tagProtectionRulesetName, err)
	}
	if ruleset.Target == nil || *ruleset.Target != github.RulesetTargetTag {
		return fmt.Errorf("ruleset %q does not target tags", tagProtectionRulesetName)
	}
	if ruleset.Rules == nil {
		ruleset.Rules = &github.RepositoryRulesetRules{}
	}
	ruleset.Rules.Deletion = &github.EmptyRuleParameters{}
	ruleset.Rules.Update = &github.UpdateRuleParameters{}
	ruleset.Rules.NonFastForward = &github.EmptyRuleParameters{}
	ruleset.Enforcement = github.RulesetEnforcementActive
	if ruleset.Conditions == nil {
		ruleset.Conditions = &github.RepositoryRulesetConditions{}
	}
	if ruleset.Conditions.RefName == nil {
		ruleset.Conditions.RefName = &github.RepositoryRulesetRefConditionParameters{}
	}
	ref := ruleset.Conditions.RefName
	if !rulesetTargetsAllTags(ruleset.Conditions) {
		ref.Include = append(ref.Include, "~ALL")
	}
	for _, p := range excludes {
		if !slices.Contains(ref.Exclude, p) {
			ref.Exclude = append(ref.Exclude, p)
		}
	}
	ref.Exclude = nonNilStrings(ref.Exclude)

	if _, err := gh.UpdateRepositoryRuleset(ctx, g, repo, existing.GetID(), rulesetUpdatePayload(ruleset)); err != nil {
		return fmt.Errorf("failed to update ruleset %q: %w", tagProtectionRulesetName, err)
	}
	return nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
