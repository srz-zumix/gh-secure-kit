package recommended

import (
	"fmt"
	"os"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/recommended"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewCheckCmd returns the recommended check command
func NewCheckCmd() *cobra.Command {
	var owner string
	var repo string
	var severity string
	var status string
	var ruleIDs []string
	var ignoreIDs []string
	var fixableOnly bool
	var exitCode bool
	var exporter cmdutil.Exporter

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check a repository or organization against recommended GitHub security settings",
		Long: `Check a repository or organization against recommended GitHub security
settings, inspired by microsoft/ghqr.

Use --repo to check a single repository against repository-scoped rules.
Use --owner to check an organization against organization-scoped rules.
--repo and --owner are mutually exclusive.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := parser.Repository(parser.RepositoryInput(repo), parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(target)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			filter := recommended.Filter{
				MinSeverity: recommended.Severity(severity),
				IDs:         ruleIDs,
				IgnoreIDs:   ignoreIDs,
				OnlyFixable: fixableOnly,
			}

			ctx := cmd.Context()
			var results []recommended.Result
			if target.Name != "" {
				filter.Scope = recommended.ScopeRepository
				rules := filter.Apply(recommended.AllRules())
				results, _, err = recommended.EvaluateRepository(ctx, client, target, rules)
				if err != nil {
					return fmt.Errorf("failed to check repository '%s/%s': %w", target.Owner, target.Name, err)
				}
			} else {
				filter.Scope = recommended.ScopeOrganization
				rules := filter.Apply(recommended.AllRules())
				results, _, err = recommended.EvaluateOrganization(ctx, client, target, rules)
				if err != nil {
					return fmt.Errorf("failed to check organization '%s': %w", target.Owner, err)
				}
			}

			if status != "" {
				filtered := make([]recommended.Result, 0, len(results))
				for _, res := range results {
					if string(res.Status) == status {
						filtered = append(filtered, res)
					}
				}
				results = filtered
			}

			if err := recommended.RenderResults(exporter, results); err != nil {
				return fmt.Errorf("failed to render results: %w", err)
			}

			if exitCode {
				for _, res := range results {
					if res.Status == recommended.StatusFail {
						os.Exit(1)
					}
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name (checks organization-scoped rules)")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo' (checks repository-scoped rules)")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", recommended.Severities, "Only show findings at or above this severity")
	cmdutil.StringEnumFlag(cmd, &status, "status", "", "", recommended.Statuses, "Only show findings with this status")
	f.StringArrayVar(&ruleIDs, "rule", nil, "Only evaluate the given rule ID (can be specified multiple times); default: all rules")
	f.StringArrayVar(&ignoreIDs, "ignore", nil, "Skip the given rule ID (can be specified multiple times)")
	f.BoolVar(&fixableOnly, "fixable-only", false, "Only show rules that can be fixed with 'recommended apply'")
	f.BoolVar(&exitCode, "exit-code", false, "Exit with status 1 if any rule fails; default: always exit 0")
	cmdutil.AddFormatFlags(cmd, &exporter)
	cmd.MarkFlagsMutuallyExclusive("owner", "repo")
	return cmd
}
