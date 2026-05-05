package pushprotection

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/parser"
)

// NewUpdateCmd returns the secret-scanning push-protection update command
func NewUpdateCmd() *cobra.Command {
	var owner string
	var patternConfigVersion string
	var providerPatterns []string
	var customPatterns []string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update secret scanning push protection pattern configurations",
		Long: `Update secret scanning push protection pattern configurations for an organization.

Use --provider-pattern to update provider patterns in TOKEN_TYPE=SETTING format.
Use --custom-pattern to update custom patterns in TOKEN_TYPE=SETTING or TOKEN_TYPE:VERSION=SETTING format.
Valid settings: enabled, disabled, not_set.

Obtain the pattern config version from the list command and pass it via --pattern-config-version.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(providerPatterns) == 0 && len(customPatterns) == 0 {
				return fmt.Errorf("at least one of --provider-pattern or --custom-pattern is required")
			}
			repository, err := parser.Repository(parser.RepositoryOwner(owner))
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}

			client, err := gh.NewGitHubClientWithRepo(repository)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}

			updateOpts := &gh.SecretScanningPatternConfigsUpdateOptions{}
			if patternConfigVersion != "" {
				updateOpts.PatternConfigVersion = patternConfigVersion
			}

			for _, p := range providerPatterns {
				setting, err := gh.ParseProviderPattern(p)
				if err != nil {
					return fmt.Errorf("invalid --provider-pattern value %q: %w", p, err)
				}
				updateOpts.ProviderPatternSettings = append(updateOpts.ProviderPatternSettings, setting)
			}

			for _, p := range customPatterns {
				setting, err := gh.ParseCustomPattern(p)
				if err != nil {
					return fmt.Errorf("invalid --custom-pattern value %q: %w", p, err)
				}
				updateOpts.CustomPatternSettings = append(updateOpts.CustomPatternSettings, setting)
			}

			ctx := cmd.Context()
			result, err := gh.UpdateSecretScanningPatternConfigs(ctx, client, repository, updateOpts)
			if err != nil {
				return fmt.Errorf("failed to update secret scanning pattern configurations: %w", err)
			}
			version := ""
			if result.PatternConfigVersion != nil {
				version = *result.PatternConfigVersion
			}
			logger.Info("Updated secret scanning pattern configurations", "owner", repository.Owner, "pattern_config_version", version)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&owner, "owner", "o", "", "The organization name")
	f.StringVar(&patternConfigVersion, "pattern-config-version", "", "The pattern config version (from list command)")
	f.StringArrayVar(&providerPatterns, "provider-pattern", nil, "Provider pattern setting in TOKEN_TYPE=SETTING format (repeatable)")
	f.StringArrayVar(&customPatterns, "custom-pattern", nil, "Custom pattern setting in TOKEN_TYPE=SETTING or TOKEN_TYPE:VERSION=SETTING format (repeatable)")
	return cmd
}
