package secretscanning

import (
	"fmt"
	"os"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/internal/localscan"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// DanglingCommitsOptions holds the format exporter for dangling-commits
// command output.
type DanglingCommitsOptions struct {
	Exporter cmdutil.Exporter
}

// NewDanglingCommitsCmd returns the secret-scanning dangling-commits command
func NewDanglingCommitsCmd() *cobra.Command {
	var (
		repo              string
		prNumbers         []int
		limit             int
		local             bool
		noReflogs         bool
		noSquashMerge     bool
		noForcePush       bool
		noClosed          bool
		reachabilityCheck string
		strictErrors      bool
		noCache           bool
		clearCache        bool
		noFetch           bool
		configFile        string
		usePatternCfg     bool
		showSecret        bool
		downloadDir       string
		prConcurrency     int
	)
	opts := &DanglingCommitsOptions{}

	cmd := &cobra.Command{
		Use:   "dangling-commits",
		Short: "Scan commits that are no longer reachable from any branch or tag for secrets",
		Long: `Scan commits that are no longer reachable from any branch or tag ref, but that the GitHub API still serves, for secrets.
Such commits are left behind by squash or rebase merges, by force-pushes on a pull request head branch, and by closed unmerged pull requests, so a secret removed by rewriting history can still be read from them.
By default every closed pull request is inspected, up to --limit; pass --pr to inspect specific pull requests instead.
With --local, the commits that no local ref reaches but that still exist on the remote are scanned instead, which requires running inside a clone of the repository.
The detected commits are fetched into the current clone when it is a clone of the scanned repository, otherwise into a temporary repository, and scanned from the fetched git objects, falling back to the GitHub API for any commit or file the fetch could not provide; pass --no-fetch to read their contents through the GitHub API instead, which is slower and consumes API rate limit.
Files that contain a detected secret are written under --download-dir when it is set.
This is an independent reimplementation and does not use GitHub's official secret scanning patterns.
Exits with status 1 if any secret is found.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := localscan.ValidateDanglingModeFlags(local, cmd.Flags().Changed); err != nil {
				return err
			}

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to resolve the current directory: %w", err)
			}
			scanner, err := localscan.BuildScanner(cwd, configFile, showSecret)
			if err != nil {
				return err
			}
			if usePatternCfg {
				if err := localscan.ApplyPatternConfig(cmd.Context(), scanner, repository); err != nil {
					return err
				}
			}

			source := localscan.NewDanglingSource(cmd.Context(), client, repository, localscan.DanglingSourceOptions{
				Local:             local,
				NoReflogs:         noReflogs,
				PRNumbers:         prNumbers,
				Limit:             limit,
				NoSquashMerge:     noSquashMerge,
				NoForcePush:       noForcePush,
				NoClosed:          noClosed,
				ReachabilityCheck: reachabilityCheck,
				StrictErrors:      strictErrors,
				NoCache:           noCache,
				ClearCache:        clearCache,
				NoFetch:           noFetch,
				PRConcurrency:     prConcurrency,
			})
			// The source keeps the fetched commits available until it is closed
			// so the download step can read file contents locally.
			defer source.Close()

			findings, err := localscan.Scan(source, scanner)
			if err != nil {
				return fmt.Errorf("failed to scan dangling commits: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if err := localscan.RenderFindings(renderer, findings); err != nil {
				return fmt.Errorf("failed to render findings: %w", err)
			}

			if downloadDir != "" {
				if err := localscan.DownloadFindings(source, findings, downloadDir); err != nil {
					return fmt.Errorf("failed to download the files that contain a secret: %w", err)
				}
			}

			if len(findings) > 0 {
				// os.Exit skips deferred calls, so remove the temporary fetch
				// repository before exiting.
				source.Close()
				os.Exit(1)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format '[HOST/]OWNER/REPO' (default: current repository)")
	f.BoolVar(&local, "local", false, "Scan the commits that no local ref reaches but that still exist on the remote, instead of inspecting pull requests")
	f.BoolVar(&noReflogs, "no-reflogs", false, "With --local, ignore reflog entries when determining local reachability")
	f.IntSliceVar(&prNumbers, "pr", nil, "The pull request numbers to inspect (default: every closed pull request)")
	f.IntVar(&limit, "limit", -1, "Maximum number of closed pull requests to inspect, or -1 for no limit (ignored with --pr)")
	f.BoolVar(&noSquashMerge, "no-squash-merge", false, "Do not detect the commits left behind by a squash or rebase merge")
	f.BoolVar(&noForcePush, "no-force-push", false, "Do not detect the commits dropped by a force-push on a pull request head branch")
	f.BoolVar(&noClosed, "no-closed", false, "Do not detect the commits of closed unmerged pull requests")
	cmdutil.StringEnumFlag(cmd, &reachabilityCheck, "reachability-check", "", localscan.DanglingReachabilityCheckNone, localscan.DanglingReachabilityCheckValues, "Verify that a candidate commit really is unreachable before scanning it")
	f.BoolVar(&strictErrors, "strict-errors", false, "Fail on the first API or git error instead of logging it and continuing with partial results")
	f.BoolVar(&noCache, "no-cache", false, "Disable the per-pull-request detection cache; does not clear existing entries")
	f.BoolVar(&clearCache, "clear-cache", false, "Clear the detection cache before scanning, then use it normally")
	f.BoolVar(&noFetch, "no-fetch", false, "Read the commit contents through the GitHub API instead of fetching the commits into a local git repository")
	f.IntVar(&prConcurrency, "pr-concurrency", 0, "Maximum number of pull requests inspected concurrently (<=0 uses the default of 4); higher values are faster but risk GitHub secondary rate limits")
	f.StringVar(&configFile, "config", "", "Path to a local secret scanning config file (default: auto-discover .gh-secure-kit-secret-scanning.yml)")
	f.BoolVar(&usePatternCfg, "pattern-config", false, "Filter patterns using the organization's secret scanning pattern configuration")
	f.BoolVar(&showSecret, "show-secret", false, "Show the full matched secret value instead of a redacted form")
	f.StringVar(&downloadDir, "download-dir", "", "Directory to write the files that contain a detected secret to, as <dir>/<commit>/<path>")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
