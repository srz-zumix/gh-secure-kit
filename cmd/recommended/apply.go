package recommended

import (
	"fmt"
	"strings"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	catalog "github.com/srz-zumix/gh-secure-kit/recommended"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/gh/guardrails"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewApplyCmd returns the recommended apply command
func NewApplyCmd() *cobra.Command {
	var owner string
	var repo string
	var severity string
	var ruleIDs []string
	var ignoreIDs []string
	var dryRun bool
	var exporter cmdutil.Exporter

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply fixes for failing, fixable recommended GitHub security settings",
		Long: `Evaluate recommended GitHub security settings and apply the fix for every
failing rule that supports automated remediation.

Use --repo to fix a single repository. Use --owner to fix an organization.
--repo and --owner are mutually exclusive.
Rules without an automated fix are reported but left untouched; run
'recommended check' to see the full list of findings.
Use --dryrun to report which fixes would be applied without changing anything.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !dryRun && guardrails.IsReadonly() {
				return fmt.Errorf("cannot apply fixes: running in read-only mode (--read-only)")
			}

			if unknown := catalog.UnknownRuleIDs(append(append([]string{}, ruleIDs...), ignoreIDs...)); len(unknown) > 0 {
				return fmt.Errorf("unknown rule ID(s): %s", strings.Join(unknown, ", "))
			}

			target, err := parser.Repository(parser.RepositoryInput(repo), parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(target)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			filter := catalog.Filter{
				MinSeverity: catalog.Severity(severity),
				IDs:         ruleIDs,
				IgnoreIDs:   ignoreIDs,
			}

			ctx := cmd.Context()
			var results []catalog.ApplyResult
			if target.Name != "" {
				filter.Scope = catalog.ScopeRepository
				rules := filter.Apply(catalog.AllRules())
				results, err = catalog.ApplyRepository(ctx, client, target, rules, dryRun)
				if err != nil {
					return fmt.Errorf("failed to apply fixes for repository '%s/%s': %w", target.Owner, target.Name, err)
				}
			} else {
				filter.Scope = catalog.ScopeOrganization
				rules := filter.Apply(catalog.AllRules())
				results, err = catalog.ApplyOrganization(ctx, client, target, rules, dryRun)
				if err != nil {
					return fmt.Errorf("failed to apply fixes for organization '%s': %w", target.Owner, err)
				}
			}

			if err := catalog.RenderApplyResults(exporter, results); err != nil {
				return fmt.Errorf("failed to render results: %w", err)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name (applies organization-scoped fixes)")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo' (applies repository-scoped fixes)")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", catalog.Severities, "Only include findings at or above this severity")
	f.StringArrayVar(&ruleIDs, "rule", nil, "Only include the given rule ID (can be specified multiple times); default: all rules")
	f.StringArrayVar(&ignoreIDs, "ignore", nil, "Skip the given rule ID (can be specified multiple times)")
	f.BoolVarP(&dryRun, "dryrun", "n", false, "Report which fixes would be applied without changing anything")
	cmdutil.AddFormatFlags(cmd, &exporter)
	cmd.MarkFlagsMutuallyExclusive("owner", "repo")
	return cmd
}
