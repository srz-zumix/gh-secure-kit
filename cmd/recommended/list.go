package recommended

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/recommended"
)

// NewListCmd returns the recommended list command
func NewListCmd() *cobra.Command {
	var scope string
	var severity string
	var fixableOnly bool
	var exporter cmdutil.Exporter

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the catalog of recommended GitHub security rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			filter := recommended.Filter{
				Scope:       recommended.Scope(scope),
				MinSeverity: recommended.Severity(severity),
				OnlyFixable: fixableOnly,
			}
			rules := filter.Apply(recommended.AllRules())
			if err := recommended.RenderRules(exporter, rules); err != nil {
				return fmt.Errorf("failed to render rules: %w", err)
			}
			return nil
		},
	}
	f := cmd.Flags()
	cmdutil.StringEnumFlag(cmd, &scope, "scope", "", "", []string{string(recommended.ScopeRepository), string(recommended.ScopeOrganization)}, "Only list rules for this scope")
	cmdutil.StringEnumFlag(cmd, &severity, "severity", "", "", recommended.Severities, "Only list rules at or above this severity")
	f.BoolVar(&fixableOnly, "fixable-only", false, "Only list rules that can be fixed with 'recommended apply'")
	cmdutil.AddFormatFlags(cmd, &exporter)
	return cmd
}
