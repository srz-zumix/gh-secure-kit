package actions

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/cmdflags"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type WorkflowOptions struct {
	Exporter cmdutil.Exporter
}

// NewWorkflowCmd returns the actions workflow command
func NewWorkflowCmd() *cobra.Command {
	var repo string
	var ref string
	var nameOnly bool
	var nameWithRef bool
	var recursive bool
	var format string
	var fields []string
	var minNodeVersion int
	var filterUsing []string
	opts := &WorkflowOptions{}

	cmd := &cobra.Command{
		Use:   "workflow [<workflow-id> | <workflow-name> | <filename>]",
		Short: "List action dependencies from workflow YAML files",
		Long: `Parse workflow YAML (.github/workflows/*.yml) and action.yml files in the repository to list GitHub Actions dependencies.
Unlike the 'list' command which uses the Dependency Graph API, this command directly parses YAML files.
Optionally specify a workflow by its ID, name, or filename to parse only that workflow.
Use --min-node-version to filter for workflows and actions that depend on Node actions older than the specified version (automatically enables --recursive).
Use --filter-using to filter by runs.using type (e.g. node16, composite, docker; prefix match supported; automatically enables --recursive).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			// --min-node-version and --filter-using require recursive traversal
			// to populate Using fields when the filter is enabled.
			if minNodeVersion < 0 {
				return fmt.Errorf("invalid value for --min-node-version: must be >= 0")
			}
			if minNodeVersion > 0 || len(filterUsing) > 0 {
				recursive = true
			}

			ctx := cmd.Context()
			var deps []parser.WorkflowDependency
			if len(args) > 0 {
				// Resolve selector to a specific workflow file path, then parse only that file
				filePath, resolveErr := gh.ResolveWorkflowFilePath(ctx, client, repository, args[0])
				if resolveErr != nil {
					return fmt.Errorf("failed to resolve workflow selector %q: %w", args[0], resolveErr)
				}
				deps, err = gh.GetWorkflowFileDependency(ctx, client, repository, filePath, refPtr, recursive, fallbackClient)
			} else {
				// No selector - fetch all workflow files
				deps, err = gh.GetRepositoryWorkflowDependencies(ctx, client, repository, refPtr, recursive, fallbackClient)
			}
			if err != nil {
				return fmt.Errorf("failed to get workflow dependencies: %w", err)
			}

			if minNodeVersion > 0 {
				deps = gh.FilterWorkflowDependenciesByNodeVersion(deps, minNodeVersion)
			}

			if len(filterUsing) > 0 {
				deps = gh.FilterWorkflowDependenciesByUsing(deps, filterUsing)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if nameOnly || nameWithRef {
				refs := gh.FlattenWorkflowDependencies(deps)
				if nameWithRef {
					return renderer.RenderVersionedNames(refs)
				} else {
					return renderer.RenderNames(refs)
				}
			} else {
				return renderer.RenderWorkflowDependenciesWithFormat(format, deps, fields)
			}
		},
	}
	f := cmd.Flags()
	f.BoolVar(&nameOnly, "name-only", false, "Output only action names")
	f.BoolVar(&nameWithRef, "name-with-ref", false, "Output action names with version ref (e.g. actions/checkout@v4)")
	f.IntVar(&minNodeVersion, "min-node-version", 0, "Filter to show only actions/workflows that use a Node action older than the specified version (e.g. 24 shows node20, node16); automatically enables --recursive")
	cmdflags.NonEmptyStringSliceVar(cmd, &filterUsing, "filter-using", nil, "Filter to show only actions/workflows that use actions matching the specified runs.using type (e.g. node16, composite, docker); prefix match supported (e.g. node matches node16/node20); repeatable; automatically enables --recursive")
	f.BoolVarP(&recursive, "recursive", "r", false, "Recursively traverse referenced action repositories")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVar(&ref, "ref", "", "Git reference (branch, tag, or commit SHA) to read workflow files from")
	cmdutil.StringSliceEnumFlag(cmd, &fields, "field", "", nil, render.WorkflowDependencyFields, "Comma-separated list of fields to display in table output")

	// Supported formats are the same as 'list' command, but with additional graph formats that visualize workflow and action relationships
	_ = cmdflags.AddFormatFlags(cmd, &opts.Exporter, &format, "", []string{"dot", "drawio", "mermaid", "markdown", "tree"})
	return cmd
}
