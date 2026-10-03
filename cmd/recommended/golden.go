package recommended

import (
	"fmt"
	"os"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	catalog "github.com/srz-zumix/gh-secure-kit/recommended"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

func NewGoldenCmd() *cobra.Command {
	var owner string
	var repo string
	var severity string
	var ruleIDs []string
	var ignoreIDs []string
	var fixableOnly bool
	var configFile string
	var output string
	var prune bool

	cmd := &cobra.Command{
		Use:   "golden",
		Short: "Accept current failing recommendations by generating an ignore configuration",
		Long: `Evaluate recommended GitHub security settings and output a YAML configuration
that ignores currently failing rules. Existing configured ignore IDs are retained.
Use --prune to re-evaluate existing ignored rules and remove only those that pass.
Skipped and unevaluated rules remain ignored. Explicit --ignore IDs are excluded
from evaluation and are not added to the configuration.

Use --repo for a repository or --owner for an organization; they are mutually exclusive.
If neither is given, the current repository is used.
Use --config to read an existing configuration; by default, the current directory's
.gh-secure-kit-recommended.yml is used if present.
Output goes to stdout unless --output is specified. No GitHub settings are changed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := catalog.ResolveConfig(configFile)
			if err != nil {
				return fmt.Errorf("failed to load recommended configuration: %w", err)
			}
			target, err := parser.Repository(parser.RepositoryInput(repo), parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}
			filter := catalog.Filter{
				Scope:       catalog.ScopeRepository,
				MinSeverity: catalog.Severity(severity),
				IDs:         ruleIDs,
				IgnoreIDs:   ignoreIDs,
				OnlyFixable: fixableOnly,
			}
			if target.Name == "" {
				filter.Scope = catalog.ScopeOrganization
			}
			rules, err := catalog.GoldenRules(cfg, filter, prune)
			if err != nil {
				return fmt.Errorf("failed to select recommended rules: %w", err)
			}
			client, err := gh.NewGitHubClientWithRepo(target)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}
			var results []catalog.Result
			if target.Name != "" {
				results, _, err = catalog.EvaluateRepository(cmd.Context(), client, target, rules)
				if err != nil {
					return fmt.Errorf("failed to evaluate repository '%s/%s': %w", target.Owner, target.Name, err)
				}
			} else {
				results, _, err = catalog.EvaluateOrganization(cmd.Context(), client, target, rules)
				if err != nil {
					return fmt.Errorf("failed to evaluate organization '%s': %w", target.Owner, err)
				}
			}
			golden := catalog.GoldenConfig(cfg, results, prune)
			if output == "" {
				if err := catalog.WriteConfig(cmd.OutOrStdout(), golden); err != nil {
					return fmt.Errorf("failed to write recommended configuration: %w", err)
				}
				return nil
			}
			file, err := os.Create(output)
			if err != nil {
				return fmt.Errorf("failed to create recommended configuration %q: %w", output, err)
			}
			writeErr := catalog.WriteConfig(file, golden)
			closeErr := file.Close()
			if writeErr != nil {
				return fmt.Errorf("failed to write recommended configuration %q: %w", output, writeErr)
			}
			if closeErr != nil {
				return fmt.Errorf("failed to close recommended configuration %q: %w", output, closeErr)
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVarP(&owner, "owner", "o", "", "The organization name (evaluates organization-scoped rules)")
	flags.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo' (evaluates repository-scoped rules)")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", catalog.Severities, "Only evaluate rules at or above this severity")
	flags.StringArrayVar(&ruleIDs, "rule", nil, "Only evaluate the given rule ID (can be specified multiple times); default: all rules")
	flags.StringArrayVar(&ignoreIDs, "ignore", nil, "Skip the given rule ID without adding it to the configuration (can be specified multiple times)")
	flags.BoolVar(&fixableOnly, "fixable-only", false, "Only evaluate rules that can be fixed with 'recommended apply'")
	flags.StringVar(&configFile, "config", "", "Path to a recommended configuration file (default: auto-discover .gh-secure-kit-recommended.yml in the current directory)")
	flags.StringVar(&output, "output", "", "Write the YAML configuration to this file, overwriting it (default: stdout)")
	flags.BoolVar(&prune, "prune", false, "Re-evaluate existing ignored rules and remove only those that pass")
	cmd.MarkFlagsMutuallyExclusive("owner", "repo")
	return cmd
}
