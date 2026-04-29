package configurations

import (
	"fmt"
	"strconv"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewAttachCmd returns the code-security configurations attach command
func NewAttachCmd() *cobra.Command {
	var owner string
	var scope string
	var repoIDs []int64

	cmd := &cobra.Command{
		Use:   "attach <configuration-id>",
		Short: "Attach a code security configuration to repositories",
		Long:  "Attach a code security configuration to a set of repositories in an organization. --scope=selected requires --repo-id values.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid configuration id %q: %w", args[0], err)
			}
			if scope == "selected" && len(repoIDs) == 0 {
				return fmt.Errorf("--repo-id is required when --scope=selected")
			}
			if scope != "selected" && len(repoIDs) > 0 {
				return fmt.Errorf("--repo-id can only be used with --scope=selected")
			}
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			ctx := cmd.Context()
			if err := gh.AttachCodeSecurityConfiguration(ctx, client, repository, id, scope, repoIDs); err != nil {
				return fmt.Errorf("failed to attach code security configuration: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Attached code security configuration #%d in %s (scope=%s)\n", id, repository.Owner, scope)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	cmdutil.StringEnumFlag(cmd, &scope, "scope", "", "", gh.CodeSecurityAttachScopes, "Type of repositories to attach the configuration to")
	_ = cmd.MarkFlagRequired("scope")
	f.Int64SliceVar(&repoIDs, "repo-id", nil, "Repository IDs to attach (only with --scope=selected, repeatable)")
	return cmd
}
