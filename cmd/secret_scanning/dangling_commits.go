package secretscanning

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/internal/localscan"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
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
The detected commits are fetched into the current clone when it is a clone of the scanned repository, otherwise into a temporary repository, and scanned from the fetched git objects; pass --no-fetch to read their contents through the GitHub API instead, which is slower and consumes API rate limit.
Files that contain a detected secret are written under --download-dir when it is set.
This is an independent reimplementation and does not use GitHub's official secret scanning patterns.
Exits with status 1 if any secret is found.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !local {
				if cmd.Flags().Changed("no-reflogs") {
					return fmt.Errorf("--no-reflogs only applies to --local")
				}
			} else {
				for _, name := range []string{"pr", "limit", "no-squash-merge", "no-force-push", "no-closed", "reachability-check", "no-cache", "clear-cache", "pr-concurrency"} {
					if cmd.Flags().Changed(name) {
						return fmt.Errorf("--%s does not apply to --local, which inspects local refs instead of pull requests", name)
					}
				}
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

			findings, err := localscan.Scan(source, scanner)
			if err != nil {
				return fmt.Errorf("failed to scan dangling commits: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if err := localscan.RenderFindings(renderer, findings); err != nil {
				return fmt.Errorf("failed to render findings: %w", err)
			}

			if downloadDir != "" {
				if err := downloadFindings(cmd.Context(), client, repository, findings, downloadDir); err != nil {
					return fmt.Errorf("failed to download the files that contain a secret: %w", err)
				}
			}

			if len(findings) > 0 {
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

// downloadFindings writes each file that contains a detected secret to
// <dir>/<commit>/<path>, reading it at the dangling commit that introduced it.
// A file is downloaded once even when it holds several findings.
func downloadFindings(ctx context.Context, client *gh.GitHubClient, repo repository.Repository, findings []localscan.Finding, dir string) error {
	root, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve download directory %q: %w", dir, err)
	}

	downloaded := make(map[string]bool, len(findings))
	for _, finding := range findings {
		if finding.Commit == "" || finding.File == "" {
			continue
		}
		key := finding.Commit + "\x00" + finding.File
		if downloaded[key] {
			continue
		}
		downloaded[key] = true

		dest, err := secureJoin(root, finding.Commit, finding.File)
		if err != nil {
			return err
		}
		content, err := gh.GetFileContent(ctx, client, repo, finding.File, &finding.Commit)
		if err != nil {
			return fmt.Errorf("failed to read %q at commit %s: %w", finding.File, finding.Commit, err)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return fmt.Errorf("failed to create directory for %q: %w", dest, err)
		}
		if err := os.WriteFile(dest, content, 0o600); err != nil {
			return fmt.Errorf("failed to write %q: %w", dest, err)
		}
		logger.Info("downloaded a file that contains a secret", "commit", finding.Commit, "file", finding.File, "path", dest)
	}
	return nil
}

// errPathEscapesRoot reports that a repository path would be written outside
// the download directory.
var errPathEscapesRoot = errors.New("the path escapes the download directory")

// secureJoin joins repository-controlled path elements under root and rejects
// any result that leaves it, so a crafted path cannot overwrite unrelated
// files.
func secureJoin(root string, elems ...string) (string, error) {
	dest := filepath.Join(append([]string{root}, elems...)...)
	rel, err := filepath.Rel(root, dest)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %q under %q: %w", filepath.Join(elems...), root, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("refusing to write %q: %w", filepath.Join(elems...), errPathEscapesRoot)
	}
	return dest, nil
}
