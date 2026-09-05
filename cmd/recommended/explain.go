package recommended

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/docs/rules"
	catalog "github.com/srz-zumix/gh-secure-kit/recommended"
)

// NewExplainCmd returns the recommended explain command
func NewExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <ID>",
		Short: "Show detailed documentation for a recommended rule",
		Long: `Show detailed documentation for a recommended rule, similar to
'shellcheck --wiki'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.ToUpper(args[0])
			if _, ok := catalog.RuleByID(id); !ok {
				return fmt.Errorf("unknown rule ID %q; run 'gh secure-kit recommended list' to see all rules", id)
			}
			content, err := rules.RulesFS.ReadFile(id + ".md")
			if err != nil {
				return fmt.Errorf("no documentation found for rule %q: %w", id, err)
			}
			cmd.Println(string(content))
			return nil
		},
	}
	return cmd
}
