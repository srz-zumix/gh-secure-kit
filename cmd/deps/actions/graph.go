package actions

import (
	"fmt"
	"os"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/cmdflags"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type GraphOptions struct {
	Exporter cmdutil.Exporter
}

// NewGraphCmd returns the deps actions graph command
func NewGraphCmd() *cobra.Command {
	var repo string
	var recursive bool
	var output string
	var format string
	opts := &GraphOptions{}

	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Output actions dependency graph in Mermaid format",
		Long:  "Output dependency relationships of GitHub Actions as a Mermaid flowchart. Use --recursive to traverse referenced action repositories.",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			_, edges, err := gh.GetActionsDependencyGraph(ctx, client, repository, recursive)
			if err != nil {
				return fmt.Errorf("failed to get actions dependency graph: %w", err)
			}

			var renderer *render.Renderer
			if output != "" {
				file, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer func() {
					err = file.Close()
				}()
				renderer = render.NewFileRenderer(file, opts.Exporter)
			} else {
				renderer = render.NewRenderer(opts.Exporter)
			}

			return renderer.RenderGraphEdge(format, edges)
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&recursive, "recursive", "r", false, "Recursively traverse referenced action repositories")
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVarP(&output, "output", "o", "", "Output file path (default: stdout)")

	// Supported formats are the same as 'list' command, but with additional graph formats that visualize workflow and action relationships
	cmdflags.AddFormatFlags(cmd, &opts.Exporter, &format, "mermaid", []string{"dot", "drawio", "mermaid", "markdown"})

	return cmd
}
