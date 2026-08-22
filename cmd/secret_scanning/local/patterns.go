package local

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/internal/localscan"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// PatternsOptions holds the format exporter for the patterns command output.
type PatternsOptions struct {
	Exporter cmdutil.Exporter
}

// NewPatternsCmd returns the secret-scanning local patterns command
func NewPatternsCmd() *cobra.Command {
	var (
		configFile    string
		usePatternCfg bool
		owner         string
		repo          string
	)
	opts := &PatternsOptions{}

	cmd := &cobra.Command{
		Use:   "patterns",
		Short: "List the local secret scanning patterns in effect",
		Long:  "List the built-in and user-defined secret scanning patterns used by 'secret-scanning local check', including whether each is enabled.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			scanner, err := buildScanner(".", configFile, false)
			if err != nil {
				return err
			}

			if usePatternCfg || owner != "" || repo != "" {
				if err := applyPatternConfig(cmd, scanner, owner, repo); err != nil {
					return err
				}
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderPatterns(renderer, scanner.Patterns)
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to a local secret scanning config file (default: auto-discover .gh-secure-kit-secret-scanning.yml)")
	f.BoolVar(&usePatternCfg, "pattern-config", false, "Filter patterns using the organization's secret scanning pattern configuration")
	f.StringVarP(&owner, "owner", "o", "", "The organization name, used with --pattern-config")
	f.StringVarP(&repo, "repo", "R", "", "The [HOST/]OWNER/REPO repository, used with --pattern-config")
	cmd.MarkFlagsMutuallyExclusive("owner", "repo")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)

	return cmd
}

// renderPatterns renders the pattern list as a table, or via the configured
// exporter (e.g. JSON) when one is set.
func renderPatterns(r *render.Renderer, patterns []localscan.Pattern) error {
	infos := make([]localscan.PatternInfo, len(patterns))
	for i, p := range patterns {
		infos[i] = p.Info()
	}
	if r.HasExporter() {
		return r.RenderExportedData(infos)
	}
	headers := []string{"ID", "Token Type", "Display Name", "Source", "Enabled"}
	table := r.NewTableWriter(headers)
	for _, p := range infos {
		table.Append([]string{
			p.ID,
			p.TokenType,
			p.DisplayName,
			p.Source,
			fmt.Sprintf("%t", p.Enabled),
		})
	}
	return table.Render()
}
