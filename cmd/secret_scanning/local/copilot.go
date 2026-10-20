package local

import (
	"fmt"
	"os"
	"time"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/internal/localscan"
	"github.com/srz-zumix/go-gh-extension/pkg/copilotext"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// CopilotOptions holds the format exporter for the copilot command output.
type CopilotOptions struct {
	Exporter cmdutil.Exporter
}

// NewCopilotCmd returns the secret-scanning local copilot command
func NewCopilotCmd() *cobra.Command {
	var (
		sources    []string
		paths      []string
		sessions   []string
		since      string
		configFile string
		showSecret bool
	)
	opts := &CopilotOptions{}

	cmd := &cobra.Command{
		Use:   "copilot",
		Short: "Scan GitHub Copilot session logs for secrets",
		Long: `Scan GitHub Copilot session logs on this machine for secrets using built-in and user-defined patterns.
By default the Copilot CLI session state (cli-sessions) and logs (cli-logs), and the VS Code chat sessions (vscode-chat) and Copilot Chat debug logs and transcripts (vscode-debug) are scanned; select a subset with --source.
The Copilot CLI directory follows COPILOT_HOME (default ~/.copilot) and VS Code is looked up under the user configuration directory (Code/User).
Use --path to scan other directories or files instead, for example the logs of VS Code Insiders.
JSON and JSON Lines files are decoded before scanning, so escaped values such as multi-line private keys are detected; the reported line is the line of the JSON(L) file.
Use --since to skip files not modified recently and --session to keep only sessions whose ID starts with the given prefix.
With --show-secret the full secret is printed; when this command is run by an agent, that output is recorded in the new session log.
Exits with status 1 if any secret is found.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := copilotext.LogOptions{
				Sources:         sources,
				Paths:           paths,
				SessionPrefixes: sessions,
			}
			if cmd.Flags().Changed("since") {
				t, err := parser.ParseTime(since)
				if err != nil {
					return fmt.Errorf("failed to parse --since %q: %w", since, err)
				}
				target.Since = t
			}

			scanner, err := localscan.BuildScanner(".", configFile, showSecret)
			if err != nil {
				return err
			}

			logger.Debug("scanning copilot session logs for secrets", "sources", sources, "paths", paths, "sessions", sessions, "since", target.Since.Format(time.RFC3339))

			findings, err := localscan.Scan(localscan.NewCopilotSource(target), scanner)
			if err != nil {
				return fmt.Errorf("failed to scan copilot session logs: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if err := localscan.RenderCopilotFindings(renderer, findings); err != nil {
				return fmt.Errorf("failed to render findings: %w", err)
			}

			if len(findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	f := cmd.Flags()
	cmdutil.StringSliceEnumFlag(cmd, &sources, "source", "", nil, copilotext.LogSources, "Comma-separated log locations to scan (default: all)")
	f.StringArrayVar(&paths, "path", nil, "Directory or file to scan instead of the default locations (can be repeated)")
	f.StringArrayVar(&sessions, "session", nil, "Scan only sessions whose ID starts with this prefix (can be repeated)")
	f.StringVar(&since, "since", "", `Scan only files modified since this time: an RFC3339 timestamp, a date (2006-01-02), or a period such as "7d", "2w", "24h"`)
	f.StringVar(&configFile, "config", "", "Path to a local secret scanning config file (default: auto-discover .gh-secure-kit-secret-scanning.yml in the current directory)")
	f.BoolVar(&showSecret, "show-secret", false, "Show the full matched secret value instead of a redacted form")
	cmd.MarkFlagsMutuallyExclusive("source", "path")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)

	return cmd
}
