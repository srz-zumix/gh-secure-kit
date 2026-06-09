package deps

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type SnapshotOptions struct {
	Exporter cmdutil.Exporter
}

// NewSnapshotCmd returns the deps snapshot command
func NewSnapshotCmd() *cobra.Command {
	var repo string
	var file string
	opts := &SnapshotOptions{}

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create a snapshot of repository dependencies",
		Long: `Create a new dependency graph snapshot for a repository.

The snapshot body must be provided as a JSON file via --file.
The JSON must conform to the GitHub dependency submission API schema.

Example JSON file:
  {
    "version": 0,
    "sha": "abc123",
    "ref": "refs/heads/main",
    "job": { "correlator": "my-action", "id": "run-1" },
    "detector": { "name": "my-detector", "version": "1.0.0", "url": "https://example.com" },
    "scanned": "2024-01-01T00:00:00Z",
    "manifests": {}
  }`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("--file is required")
			}

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("failed to read snapshot file: %w", err)
			}

			var snapshot gh.DependencyGraphSnapshot
			if err := json.Unmarshal(data, &snapshot); err != nil {
				return fmt.Errorf("failed to parse snapshot JSON: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			result, err := gh.CreateRepositoryDependencyGraphSnapshot(ctx, client, repository, &snapshot)
			if err != nil {
				return fmt.Errorf("failed to create dependency snapshot: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderDependencyGraphSnapshotResult(result)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVarP(&file, "file", "f", "", "Path to a JSON file containing the snapshot body (required)")
	_ = cmd.MarkFlagRequired("file")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
