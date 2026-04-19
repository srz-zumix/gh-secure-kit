package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// supportedLintTools lists the lint tools that are supported
var supportedLintTools = []string{"actionlint", "zizmor"}

// NewLintCmd returns the actions lint command
func NewLintCmd() *cobra.Command {
	var repo string
	var ref string
	var recursive bool
	var tool string
	var tmpDir string

	cmd := &cobra.Command{
		Use:   "lint [<workflow-id> | <workflow-name> | <filename>] [flags] [-- <tool-args>...]",
		Short: "Lint workflow and action YAML files using an external tool",
		Long: `Run an external lint tool against workflow YAML and action.yml files.
Files are fetched via the GitHub API and saved to a temporary directory,
then the specified lint tool is executed against them.
Optionally specify a workflow by its ID, name, or filename to lint only that workflow's dependencies.
Use --recursive to also lint files from referenced action repositories and reusable workflows.
Extra arguments after '--' are passed directly to the lint tool.

Supported tools: actionlint, zizmor`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := exec.LookPath(tool); err != nil {
				return fmt.Errorf("lint tool %q not found in PATH: %w", tool, err)
			}

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			// Create fallback client for github.com when the primary host is GitHub Enterprise
			var fallbackClient *gh.GitHubClient
			if repository.Host != "" && repository.Host != "github.com" {
				fc, fcErr := gh.NewGitHubClientForDefaultHost()
				if fcErr == nil {
					fallbackClient = fc
				}
			}

			var refPtr *string
			if ref != "" {
				refPtr = &ref
			}

			// Separate workflow selector (before '--') from tool args (after '--')
			var selector string
			var toolArgs []string
			dashIdx := cmd.ArgsLenAtDash()
			if dashIdx < 0 {
				// No '--' found: all args are potential selectors
				if len(args) > 0 {
					selector = args[0]
				}
			} else {
				// Args before '--' are selectors, after '--' are tool args
				if dashIdx > 0 {
					selector = args[0]
				}
				toolArgs = args[dashIdx:]
			}

			ctx := cmd.Context()
			var deps []parser.WorkflowDependency
			if selector != "" {
				// Resolve selector to a specific workflow file path, then parse only that file
				filePath, resolveErr := gh.ResolveWorkflowFilePath(ctx, client, repository, selector)
				if resolveErr != nil {
					return fmt.Errorf("failed to resolve workflow selector %q: %w", selector, resolveErr)
				}
				deps, err = gh.GetWorkflowFileDependency(ctx, client, repository, filePath, refPtr, recursive, fallbackClient)
			} else {
				deps, err = gh.GetRepositoryWorkflowDependencies(ctx, client, repository, refPtr, recursive, fallbackClient)
			}
			if err != nil {
				return fmt.Errorf("failed to get workflow dependencies: %w", err)
			}

			if len(deps) == 0 {
				fmt.Fprintln(os.Stderr, "No workflow or action files found")
				return nil
			}

			// Prepare temporary directory for downloaded files
			if tmpDir == "" {
				d, err := os.MkdirTemp("", "gh-secure-kit-lint-*")
				if err != nil {
					return fmt.Errorf("failed to create temporary directory: %w", err)
				}
				tmpDir = d
				defer func() {
					_ = os.RemoveAll(tmpDir)
				}()
			} else {
				if err := os.MkdirAll(tmpDir, 0o755); err != nil {
					return fmt.Errorf("failed to create directory %s: %w", tmpDir, err)
				}
			}

			files, err := downloadDependencyFiles(ctx, client, fallbackClient, deps, tmpDir)
			if err != nil {
				return fmt.Errorf("failed to download dependency files: %w", err)
			}

			if len(files) == 0 {
				fmt.Fprintln(os.Stderr, "No files downloaded for linting")
				return nil
			}

			return runLintTool(tool, tmpDir, files, toolArgs)
		},
	}

	f := cmd.Flags()
	cmdutil.StringEnumFlag(cmd, &tool, "tool", "", "zizmor", supportedLintTools, "Lint tool to use")
	f.BoolVarP(&recursive, "recursive", "r", false, "Recursively traverse referenced action repositories")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVar(&ref, "ref", "", "Git reference (branch, tag, or commit SHA) to read workflow files from")
	f.StringVar(&tmpDir, "tmpdir", "", "Directory to store downloaded files (default: auto-created temp dir, removed after lint)")

	return cmd
}

// runLintTool executes the lint tool with the downloaded files
func runLintTool(tool string, tmpDir string, files []string, extraArgs []string) error {
	switch tool {
	case "actionlint":
		return runActionlint(tmpDir, files, extraArgs)
	case "zizmor":
		return runZizmor(tmpDir, files, extraArgs)
	default:
		return fmt.Errorf("unsupported lint tool: %s", tool)
	}
}

// isWorkflowFile returns true if the file path looks like a GitHub Actions workflow file.
func isWorkflowFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	return base != "action.yml" && base != "action.yaml"
}

// runActionlint executes actionlint against workflow files.
// actionlint only supports workflow YAML files, so action.yml files are filtered out.
func runActionlint(tmpDir string, files []string, extraArgs []string) error {
	var workflowFiles []string
	for _, f := range files {
		if isWorkflowFile(f) {
			workflowFiles = append(workflowFiles, f)
		}
	}
	if len(workflowFiles) == 0 {
		fmt.Fprintln(os.Stderr, "No workflow files found for actionlint")
		return nil
	}

	// Build actionlint command: actionlint [extra-args] <files...>
	cmdArgs := make([]string, 0, len(extraArgs)+len(workflowFiles))
	cmdArgs = append(cmdArgs, extraArgs...)
	cmdArgs = append(cmdArgs, workflowFiles...)

	//nolint:gosec // tool name is validated against supportedLintTools
	lintCmd := exec.Command("actionlint", cmdArgs...)
	lintCmd.Dir = tmpDir
	lintCmd.Stdout = os.Stdout
	lintCmd.Stderr = os.Stderr
	lintCmd.Stdin = os.Stdin

	err := lintCmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("failed to run actionlint: %w", err)
	}
	return nil
}

// runZizmor executes zizmor against the specified files.
func runZizmor(tmpDir string, files []string, extraArgs []string) error {
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No files found for zizmor")
		return nil
	}

	// Build zizmor command: zizmor [extra-args] <files...>
	cmdArgs := make([]string, 0, len(extraArgs)+len(files))
	cmdArgs = append(cmdArgs, extraArgs...)
	cmdArgs = append(cmdArgs, files...)

	//nolint:gosec // tool name is validated against supportedLintTools
	lintCmd := exec.Command("zizmor", cmdArgs...)
	lintCmd.Dir = tmpDir
	lintCmd.Stdout = os.Stdout
	lintCmd.Stderr = os.Stderr
	lintCmd.Stdin = os.Stdin

	err := lintCmd.Run()
	if err != nil {
		// lint tools typically exit with non-zero when findings exist;
		// propagate the exit code but do not wrap as an internal error
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("failed to run zizmor: %w", err)
	}
	return nil
}

// downloadDependencyFiles downloads all source files referenced in workflow dependencies
// to the specified directory, preserving directory structure.
// All sources are stored under "owner/repo/path" to provide proper repository context
// for lint tools (e.g. zizmor infers the repository from the file path).
// Returns the list of downloaded file paths (relative to destDir).
func downloadDependencyFiles(ctx context.Context, g *gh.GitHubClient, fallback *gh.GitHubClient, deps []parser.WorkflowDependency, destDir string) ([]string, error) {
	seen := make(map[string]bool)
	var downloadedFiles []string

	for _, dep := range deps {
		if seen[dep.Source] {
			continue
		}
		seen[dep.Source] = true

		repo := dep.Repository
		filePath, isRemote := parseDependencySource(dep.Source)

		content, err := downloadFileWithFallback(ctx, g, fallback, repo, filePath, isRemote)
		if err != nil {
			// Skip files that cannot be downloaded
			continue
		}

		// Determine the destination path: always use "owner/repo/path" structure
		// so that lint tools can infer the repository context from the file path.
		var destPath string
		if isRemote {
			// Remote: "owner/repo:path" -> "owner/repo/path"
			destPath = dep.Source[:strings.Index(dep.Source, ":")] + "/" + filePath
		} else {
			// Local: "path" -> "owner/repo/path"
			repoKey := dep.Repository.Owner + "/" + dep.Repository.Name
			destPath = repoKey + "/" + dep.Source
		}

		fullPath := filepath.Join(destDir, destPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return nil, fmt.Errorf("failed to create directory for %s: %w", destPath, err)
		}
		if err := os.WriteFile(fullPath, content, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write file %s: %w", destPath, err)
		}
		downloadedFiles = append(downloadedFiles, destPath)
	}

	return downloadedFiles, nil
}

// parseDependencySource parses a dep source string into a file path and whether it is remote.
// Remote sources have the format "owner/repo:path", local sources are plain file paths.
func parseDependencySource(source string) (string, bool) {
	idx := strings.Index(source, ":")
	if idx > 0 && strings.Contains(source[:idx], "/") {
		return source[idx+1:], true
	}
	return source, false
}

// downloadFileWithFallback downloads a file from the repository, falling back to the
// fallback client if the primary client fails and the host is not the default.
func downloadFileWithFallback(ctx context.Context, g *gh.GitHubClient, fallback *gh.GitHubClient, repo repository.Repository, filePath string, isRemote bool) ([]byte, error) {
	content, err := gh.GetFileContent(ctx, g, repo, filePath, nil)
	if err != nil && isRemote && fallback != nil && repo.Host != "github.com" {
		// Fallback to github.com for remote dependencies
		repo.Host = "github.com"
		content, err = gh.GetFileContent(ctx, fallback, repo, filePath, nil)
	}
	return content, err
}
