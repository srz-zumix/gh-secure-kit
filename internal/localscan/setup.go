package localscan

import (
	"context"
	"fmt"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// BuildScanner builds a Scanner from configFile, or from the config
// auto-discovered under searchDir when configFile is empty.
func BuildScanner(searchDir, configFile string, showSecret bool) (*Scanner, error) {
	if configFile == "" {
		configFile = DiscoverConfig(searchDir)
	}

	var cfg *Config
	if configFile != "" {
		var err error
		cfg, err = LoadConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file %q: %w", configFile, err)
		}
	}

	scanner, err := NewScanner(cfg, showSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to build scanner: %w", err)
	}
	return scanner, nil
}

// ApplyPatternConfig narrows the scanner's patterns to the ones the
// organization's secret scanning pattern configuration enables. It warns
// instead of failing when the configuration cannot be fetched, so a missing
// entitlement or permission does not abort the scan.
func ApplyPatternConfig(ctx context.Context, scanner *Scanner, repo repository.Repository) error {
	client, err := gh.NewGitHubClientWithRepo(repo)
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}
	configs, err := gh.ListSecretScanningPatternConfigs(ctx, client, repo)
	if err != nil {
		logger.Warn("failed to fetch secret scanning pattern configurations, using local settings", "error", err)
		return nil
	}
	scanner.Patterns = ApplyPatternConfigs(scanner.Patterns, configs)
	return nil
}

// RenderFindings renders findings as a table, or through the configured
// exporter (e.g. JSON) when one is set.
func RenderFindings(r *render.Renderer, findings []Finding) error {
	if r.HasExporter() {
		return r.RenderExportedData(findings)
	}
	if len(findings) == 0 {
		return nil
	}
	headers := []string{"Pattern", "Token Type", "Commit", "File", "Line", "Secret"}
	table := r.NewTableWriter(headers)
	for _, f := range findings {
		commit := f.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		table.Append([]string{
			f.PatternID,
			f.TokenType,
			commit,
			f.File,
			fmt.Sprintf("%d", f.StartLine),
			f.Secret,
		})
	}
	return table.Render()
}
