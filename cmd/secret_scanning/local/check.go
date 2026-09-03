// Package local implements the "secret-scanning local" commands, which scan
// local git content for secrets without requiring GitHub push protection.
package local

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/internal/localscan"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// CheckOptions holds the format exporter for the check command output.
type CheckOptions struct {
	Exporter cmdutil.Exporter
}

// NewCheckCmd returns the secret-scanning local check command
func NewCheckCmd() *cobra.Command {
	var (
		unpushed      bool
		staged        bool
		uncommitted   bool
		revRange      string
		rev           string
		remote        string
		noAPI         bool
		noGit         bool
		path          string
		configFile    string
		usePatternCfg bool
		owner         string
		repo          string
		showSecret    bool
		maxCommits    int
	)
	opts := &CheckOptions{}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Scan local git content for secrets",
		Long: `Scan local git content for secrets using built-in and user-defined patterns.
Exactly one target must be selected: --unpushed (default), --staged, --uncommitted, --rev-range, or --no-git.
With --rev-range, commits that are missing from the local repository are read through the GitHub API instead, so a shallow CI checkout can scan a range without cloning the whole history; pass --no-api to disable it.
The repository is taken from --repo, or inferred from the git remotes of --path.
This is an independent reimplementation and does not use GitHub's official secret scanning patterns.
Exits with status 1 if any secret is found.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := localscan.TargetUnpushed
			switch {
			case staged:
				mode = localscan.TargetStaged
			case uncommitted:
				mode = localscan.TargetUncommitted
			case cmd.Flags().Changed("rev-range"):
				if revRange == "" {
					return fmt.Errorf("--rev-range requires a value in \"A..B\" or \"B\" form")
				}
				mode = localscan.TargetRevRange
			case noGit:
				mode = localscan.TargetNoGit
			case cmd.Flags().Changed("unpushed") && !unpushed:
				return fmt.Errorf("no scan target selected: --unpushed=false requires one of --staged, --uncommitted, --rev-range or --no-git")
			}

			// --rev and --remote only refine the unpushed target.
			if mode != localscan.TargetUnpushed {
				if cmd.Flags().Changed("rev") {
					return fmt.Errorf("--rev only applies to the --unpushed target")
				}
				if cmd.Flags().Changed("remote") {
					return fmt.Errorf("--remote only applies to the --unpushed target")
				}
			}
			if cmd.Flags().Changed("rev") && rev == "" {
				return fmt.Errorf("--rev requires a revision")
			}
			if cmd.Flags().Changed("remote") && remote == "" {
				return fmt.Errorf("--remote requires a remote name")
			}

			absPath, err := filepath.Abs(path)
			if err != nil {
				return fmt.Errorf("failed to resolve path %q: %w", path, err)
			}

			target := localscan.Target{
				Mode:       mode,
				RepoPath:   absPath,
				RevRange:   revRange,
				Rev:        rev,
				Remote:     remote,
				MaxCommits: maxCommits,
			}

			var source localscan.Source
			switch {
			case mode == localscan.TargetNoGit:
				source = localscan.NewDirSource(target)
			case mode == localscan.TargetRevRange && !noAPI:
				source = localscan.NewFallbackSource(
					localscan.NewGitSource(target),
					localscan.NewAPISource(cmd.Context(), target, repo),
				)
			default:
				source = localscan.NewGitSource(target)
			}

			scanner, err := buildScanner(absPath, configFile, showSecret)
			if err != nil {
				return err
			}

			// --repo is also used to select the repository read through the
			// API, and --owner/--repo for the pattern configuration, so the
			// pattern configuration needs its own opt-in.
			if usePatternCfg {
				if err := applyPatternConfig(cmd, scanner, owner, repo); err != nil {
					return err
				}
			}

			logger.Debug("scanning local content for secrets", "mode", mode, "path", absPath, "rev-range", revRange, "rev", rev, "remote", remote)

			findings, err := localscan.Scan(source, scanner)
			if err != nil {
				return fmt.Errorf("failed to collect scan targets: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if err := renderFindings(renderer, findings); err != nil {
				return fmt.Errorf("failed to render findings: %w", err)
			}

			if len(findings) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&unpushed, "unpushed", true, "Scan commits reachable from HEAD but not pushed to any remote (default)")
	f.BoolVar(&staged, "staged", false, "Scan changes currently staged in the index")
	f.BoolVar(&uncommitted, "uncommitted", false, "Scan modified and untracked files in the worktree")
	f.StringVar(&revRange, "rev-range", "", `Scan an explicit revision range, in "A..B" or "B" form`)
	f.StringVar(&rev, "rev", "", "With --unpushed, scan commits reachable from this revision (instead of HEAD) but not from the destination remote; used by the pre-push hook")
	f.StringVar(&remote, "remote", "", "With --unpushed, exclude only this remote's tracking branches (instead of every remote); used by the pre-push hook")
	f.BoolVar(&noAPI, "no-api", false, "Do not read commits that are missing from the local repository through the GitHub API")
	f.BoolVar(&noGit, "no-git", false, "Scan files under --path directly, without using git")
	cmd.MarkFlagsMutuallyExclusive("unpushed", "staged", "uncommitted", "rev-range", "no-git")

	f.StringVarP(&path, "path", "C", ".", "The repository or directory path to scan")
	f.StringVar(&configFile, "config", "", "Path to a local secret scanning config file (default: auto-discover .gh-secure-kit-secret-scanning.yml)")
	f.BoolVar(&usePatternCfg, "pattern-config", false, "Filter patterns using the organization's secret scanning pattern configuration")
	f.StringVarP(&owner, "owner", "o", "", "The organization name, used with --pattern-config")
	f.StringVarP(&repo, "repo", "R", "", "The [HOST/]OWNER/REPO repository, used with --pattern-config and to read commits through the GitHub API")
	f.BoolVar(&showSecret, "show-secret", false, "Show the full matched secret value instead of a redacted form")
	f.IntVar(&maxCommits, "max-commits", 1000, "Maximum number of commits to scan for --unpushed and --rev-range")
	cmd.MarkFlagsMutuallyExclusive("owner", "repo")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)

	return cmd
}

// buildScanner loads the config file (explicit or auto-discovered) and
// builds a Scanner from it.
func buildScanner(searchDir, configFile string, showSecret bool) (*localscan.Scanner, error) {
	if configFile == "" {
		configFile = localscan.DiscoverConfig(searchDir)
	}

	var cfg *localscan.Config
	if configFile != "" {
		var err error
		cfg, err = localscan.LoadConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file %q: %w", configFile, err)
		}
	}

	scanner, err := localscan.NewScanner(cfg, showSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to build scanner: %w", err)
	}
	return scanner, nil
}

// applyPatternConfig fetches the organization's secret scanning pattern
// configuration and narrows the scanner's patterns accordingly, warning
// instead of failing if the configuration cannot be fetched.
func applyPatternConfig(cmd *cobra.Command, scanner *localscan.Scanner, owner, repo string) error {
	repository, err := parser.Repository(parser.RepositoryInput(repo), parser.RepositoryOwner(owner))
	if err != nil {
		return fmt.Errorf("failed to parse repository: %w", err)
	}
	client, err := gh.NewGitHubClientWithRepo(repository)
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}
	configs, err := gh.ListSecretScanningPatternConfigs(cmd.Context(), client, repository)
	if err != nil {
		logger.Warn("failed to fetch secret scanning pattern configurations, using local settings", "error", err)
		return nil
	}
	scanner.Patterns = localscan.ApplyPatternConfigs(scanner.Patterns, configs)
	return nil
}

// renderFindings renders findings as a table, or via the configured
// exporter (e.g. JSON) when one is set.
func renderFindings(r *render.Renderer, findings []localscan.Finding) error {
	if r.HasExporter() {
		return r.RenderExportedData(findings)
	}
	if len(findings) == 0 {
		return nil
	}
	headers := []string{"Pattern", "Token Type", "Commit", "File", "Line", "Secret"}
	table := r.NewTableWriter(headers)
	for _, f := range findings {
		commit := f.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		table.Append([]string{
			f.PatternID,
			f.TokenType,
			commit,
			f.File,
			fmt.Sprintf("%d", f.StartLine),
			f.Secret,
		})
	}
	return table.Render()
}
