package alerts

import (
	"fmt"
	"strconv"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// InstancesOptions holds the format exporter for instances command output.
type InstancesOptions struct {
	Exporter cmdutil.Exporter
}

// NewInstancesCmd returns the code-scanning alerts instances command
func NewInstancesCmd() *cobra.Command {
	var repo string
	var ref string
	opts := &InstancesOptions{}

	cmd := &cobra.Command{
		Use:   "instances <alert-number>",
		Short: "List instances of a code scanning alert",
		Long:  "Lists all instances of the specified code scanning alert for a repository.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			alertNumber, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid alert number %q: %w", args[0], err)
			}

			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			instanceOpts := &gh.ListCodeScanningAlertInstancesOptions{
				Ref: ref,
			}
			instances, err := gh.ListCodeScanningAlertInstances(ctx, client, repository, alertNumber, instanceOpts)
			if err != nil {
				return fmt.Errorf("failed to list code scanning alert instances: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderCodeScanningAlertInstances(instances)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVar(&ref, "ref", "", "Filter by Git ref (branch, tag, or pull request)")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
