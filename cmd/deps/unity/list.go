package unity

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
	"github.com/srz-zumix/go-gh-extension/pkg/unity"
)

// ListOptions holds options for the unity list command.
type ListOptions struct {
	Exporter cmdutil.Exporter
}

// NewListCmd returns the unity list command.
func NewListCmd() *cobra.Command {
	var repo string
	var ref string
	var path string
	var nameOnly bool
	var fields []string
	opts := &ListOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Unity package dependencies",
		Long:  "List dependency packages defined in a Unity project's Packages/manifest.json. The file path within the repository defaults to \"Packages/manifest.json\" and can be overridden with --path. Use --ref to target a specific branch, tag, or commit.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			manifest, err := unity.GetUnityManifest(ctx, client, repository, path, ref)
			if err != nil {
				return fmt.Errorf("failed to get Unity manifest: %w", err)
			}

			packages := manifest.ToPackages()
			packages, err = unity.ResolveFilePackages(ctx, client, repository, path, ref, packages)
			if err != nil {
				return fmt.Errorf("failed to resolve file packages: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			if nameOnly {
				return renderer.RenderNames(packages)
			} else {
				return renderer.RenderUnityPackages(packages, fields)
			}
		},
	}
	f := cmd.Flags()
	f.BoolVar(&nameOnly, "name-only", false, "Output only package names")
	f.StringVar(&path, "path", "Packages/manifest.json", "Path to manifest.json within the repository")
	f.StringVar(&ref, "ref", "", "Branch, tag, or commit SHA to read from (default: repository default branch)")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	cmdutil.StringSliceEnumFlag(cmd, &fields, "field", "", nil, render.UnityPackageFields, "Comma-separated list of fields to display in table output")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
