package sarif

import (
	"fmt"
	"time"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// UploadOptions holds the format exporter for upload command output.
type UploadOptions struct {
	Exporter cmdutil.Exporter
}

// NewUploadCmd returns the code-scanning sarif upload command
func NewUploadCmd() *cobra.Command {
	var repo string
	var commitSHA string
	var ref string
	var sarifData string
	var checkoutURI string
	var startedAt string
	var toolName string
	opts := &UploadOptions{}

	cmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload SARIF data",
		Long:  "Uploads SARIF data containing the results of a code scanning analysis. The --sarif value must be a Base64 string of gzip-compressed SARIF data.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repository, err := parser.Repository(parser.RepositoryInput(repo))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			var parsedStartedAt time.Time
			if startedAt != "" {
				parsedStartedAt, err = time.Parse(time.RFC3339, startedAt)
				if err != nil {
					return fmt.Errorf("invalid --started-at value %q: %w", startedAt, err)
				}
			}

			uploadOpts := &gh.UploadSARIFOptions{
				CommitSHA:   commitSHA,
				Ref:         ref,
				SARIF:       sarifData,
				CheckoutURI: checkoutURI,
				StartedAt:   parsedStartedAt,
				ToolName:    toolName,
			}

			ctx := cmd.Context()
			sarifID, err := gh.UploadSARIF(ctx, client, repository, uploadOpts)
			if err != nil {
				return fmt.Errorf("failed to upload SARIF data: %w", err)
			}

			renderer := render.NewRenderer(opts.Exporter)
			return renderer.RenderSARIFID(sarifID)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "The repository in the format 'owner/repo'")
	f.StringVar(&commitSHA, "commit-sha", "", "The SHA of the commit to which the analysis relates (required)")
	_ = cmd.MarkFlagRequired("commit-sha")
	f.StringVar(&ref, "ref", "", "The full Git reference (e.g. refs/heads/main) (required)")
	_ = cmd.MarkFlagRequired("ref")
	f.StringVar(&sarifData, "sarif", "", "Base64 string of gzip-compressed SARIF data (required)")
	_ = cmd.MarkFlagRequired("sarif")
	f.StringVar(&checkoutURI, "checkout-uri", "", "The base directory used in the analysis")
	f.StringVar(&startedAt, "started-at", "", "The time the analysis started (ISO 8601 format)")
	f.StringVar(&toolName, "tool-name", "", "The name of the tool used to generate the analysis")
	cmdutil.AddFormatFlags(cmd, &opts.Exporter)
	return cmd
}
