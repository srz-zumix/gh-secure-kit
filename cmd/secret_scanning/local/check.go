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

			// --owner only feeds the pattern configuration, and --repo feeds
			// it too unless it is consumed by the API in a rev-range fallback
			// scan. Reject these flags when they would otherwise be silent
			// no-ops instead of quietly ignoring them.
			if cmd.Flags().Changed("owner") && !usePatternCfg {
				return fmt.Errorf("--owner has no effect without --pattern-config")
			}
			if cmd.Flags().Changed("repo") && !usePatternCfg && (mode != localscan.TargetRevRange || noAPI) {
				return fmt.Errorf("--repo has no effect without --pattern-config outside a --rev-range API scan")
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

			scanner, err := localscan.BuildScanner(absPath, configFile, showSecret)
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
			if err := localscan.RenderFindings(renderer, findings); err != nil {
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
	f.BoolVar(&noGit, "no-git", false, "Scan files under --path directly, without using git")
	cmd.MarkFlagsMutuallyExclusive("unpushed", "staged", "uncommitted", "rev-range", "no-git")

	f.StringVar(&rev, "rev", "", "With --unpushed, scan commits reachable from this revision (instead of HEAD) but not from the destination remote; used by the pre-push hook")
	f.StringVar(&remote, "remote", "", "With --unpushed, exclude only this remote's tracking branches (instead of every remote); used by the pre-push hook")
	f.BoolVar(&noAPI, "no-api", false, "Do not read commits that are missing from the local repository through the GitHub API (the fallback makes about one API request per commit, so large ranges can be slow or hit rate limits)")

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

// applyPatternConfig narrows the scanner's patterns using the pattern
// configuration of the organization selected by --owner or --repo.
func applyPatternConfig(cmd *cobra.Command, scanner *localscan.Scanner, owner, repo string) error {
	repository, err := parser.Repository(parser.RepositoryInput(repo), parser.RepositoryOwner(owner))
	if err != nil {
		return fmt.Errorf("failed to parse repository: %w", err)
	}
	return localscan.ApplyPatternConfig(cmd.Context(), scanner, repository)
}
