package localscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

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
	verified := slices.ContainsFunc(findings, func(f Finding) bool { return f.Validity != "" })
	if verified {
		headers = append(headers, "Validity")
	}
	table := r.NewTableWriter(headers)
	for _, finding := range findings {
		commit := finding.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		row := []string{
			finding.PatternID,
			finding.TokenType,
			commit,
			finding.File,
			fmt.Sprintf("%d", finding.StartLine),
			finding.Secret,
		}
		if verified {
			row = append(row, finding.Validity)
		}
		table.Append(row)
	}
	return table.Render()
}

func RenderLocalFindings(r *render.Renderer, findings []Finding) error {
	if r.HasExporter() {
		return r.RenderExportedData(findings)
	}
	if len(findings) == 0 {
		return nil
	}
	return renderFindingGroups(r, findings, false)
}

// RenderCopilotFindings renders Copilot log findings grouped by session, or through
// the configured exporter (e.g. JSON) when one is set.
func RenderCopilotFindings(r *render.Renderer, findings []Finding) error {
	if r.HasExporter() {
		return r.RenderExportedData(findings)
	}
	if len(findings) == 0 {
		return nil
	}
	return renderFindingGroups(r, findings, true)
}

type findingGroup struct {
	metadata Finding
	findings []Finding
}

func renderFindingGroups(r *render.Renderer, findings []Finding, copilot bool) error {
	type groupKey struct{ id, file string }
	indexes := make(map[groupKey]int)
	var groups []findingGroup
	for _, finding := range findings {
		key := groupKey{id: finding.Commit}
		if copilot {
			key.id = finding.SessionID
			if key.id == "" {
				key.file = finding.File
			}
		}
		index, exists := indexes[key]
		if !exists {
			index = len(groups)
			indexes[key] = index
			groups = append(groups, findingGroup{metadata: finding})
		}
		group := &groups[index]
		group.findings = append(group.findings, finding)
		if finding.Date.After(group.metadata.Date) {
			group.metadata.Date = finding.Date
		}
		if group.metadata.SessionName == "" {
			group.metadata.SessionName = finding.SessionName
		}
		if group.metadata.Workspace == "" {
			group.metadata.Workspace = finding.Workspace
		}
		if group.metadata.Source == "" {
			group.metadata.Source = finding.Source
		}
	}
	if copilot {
		slices.SortStableFunc(groups, func(left, right findingGroup) int {
			if order := right.metadata.Date.Compare(left.metadata.Date); order != 0 {
				return order
			}
			if order := strings.Compare(left.metadata.SessionID, right.metadata.SessionID); order != 0 {
				return order
			}
			return strings.Compare(left.metadata.File, right.metadata.File)
		})
	}
	home, _ := os.UserHomeDir()
	var output strings.Builder
	knownGroups, ungroupedFiles := 0, 0
	for index, group := range groups {
		if index > 0 {
			output.WriteByte('\n')
		}
		metadata := group.metadata
		if copilot {
			name := metadata.SessionName
			if name == "" {
				name = "(no name)"
			}
			writeFindingHeading(&output, r, "* "+name)
			session := metadata.SessionID
			if session == "" {
				session = "(no session)"
				ungroupedFiles++
			} else {
				knownGroups++
			}
			fmt.Fprintf(&output, "  Session: %s\n", findingText(session))
			if metadata.Source != "" {
				fmt.Fprintf(&output, "  Source: %s\n", findingText(metadata.Source))
			}
			if metadata.Workspace != "" {
				fmt.Fprintf(&output, "  Workspace: %s\n", findingText(shortenHome(metadata.Workspace, home)))
			}
		} else if metadata.Commit != "" {
			commit := metadata.Commit
			if len(commit) > 12 {
				commit = commit[:12]
			}
			writeFindingHeading(&output, r, "* Commit "+commit)
			knownGroups++
			if metadata.Author != "" {
				fmt.Fprintf(&output, "  Author: %s\n", findingText(metadata.Author))
			}
		} else {
			files := make(map[string]struct{})
			for _, finding := range group.findings {
				files[finding.File] = struct{}{}
			}
			ungroupedFiles += len(files)
		}
		if !metadata.Date.IsZero() && (copilot || metadata.Commit != "") {
			label := "Date"
			if copilot {
				label = "Updated"
			}
			fmt.Fprintf(&output, "  %s: %s\n", label, metadata.Date.Format("2006-01-02 15:04:05 MST"))
		}
		if err := renderFindingFiles(&output, group.findings, home); err != nil {
			return fmt.Errorf("failed to render finding files: %w", err)
		}
	}
	unit := "commit"
	if copilot {
		unit = "session"
	}
	fmt.Fprintf(&output, "\n%s in ", findingCount(len(findings), "finding"))
	if knownGroups > 0 {
		output.WriteString(findingCount(knownGroups, unit))
		if ungroupedFiles > 0 {
			output.WriteString(" and ")
		}
	}
	if ungroupedFiles > 0 {
		unit = "uncommitted file"
		if copilot {
			unit = "sessionless file"
		} else if knownGroups == 0 {
			unit = "file"
		}
		output.WriteString(findingCount(ungroupedFiles, unit))
	}
	output.WriteByte('\n')
	_, err := fmt.Fprint(r.IO.Out, output.String())
	return err
}

func renderFindingFiles(output *strings.Builder, findings []Finding, home string) error {
	var files []string
	byFile := make(map[string][]Finding)
	for _, finding := range findings {
		if _, exists := byFile[finding.File]; !exists {
			files = append(files, finding.File)
		}
		byFile[finding.File] = append(byFile[finding.File], finding)
	}
	for _, file := range files {
		fmt.Fprintf(output, "  %s\n", findingText(shortenHome(file, home)))
		rows := byFile[file]
		slices.SortStableFunc(rows, func(left, right Finding) int {
			if left.StartLine < right.StartLine {
				return -1
			}
			if left.StartLine > right.StartLine {
				return 1
			}
			return 0
		})
		writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
		for _, finding := range rows {
			if _, err := fmt.Fprintf(writer, "    %d\t%s\t%s", finding.StartLine, findingText(finding.PatternID), findingText(finding.Secret)); err != nil {
				return err
			}
			if finding.Validity != "" {
				if _, err := fmt.Fprintf(writer, "\t[%s]", findingText(finding.Validity)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func writeFindingHeading(output *strings.Builder, r *render.Renderer, heading string) {
	heading = findingText(heading)
	if r.IO.IsStdoutTTY() {
		heading = r.IO.ColorScheme().Bold(heading)
	}
	fmt.Fprintln(output, heading)
}

func findingText(value string) string {
	var output strings.Builder
	for _, char := range value {
		switch {
		case char == '\r':
			output.WriteString(`\r`)
		case char == '\n':
			output.WriteString(`\n`)
		case char == '\t':
			output.WriteString(`\t`)
		case char < 0x20 || char >= 0x7f && char <= 0x9f:
			fmt.Fprintf(&output, `\x%02x`, char)
		default:
			output.WriteRune(char)
		}
	}
	return output.String()
}

func findingCount(count int, unit string) string {
	if count != 1 {
		unit += "s"
	}
	return fmt.Sprintf("%d %s", count, unit)
}

// shortenHome replaces a leading home directory in path with "~".
func shortenHome(path, home string) string {
	if home == "" {
		return path
	}
	if path == home {
		return "~"
	}
	if strings.HasPrefix(path, home+string(filepath.Separator)) {
		return "~" + path[len(home):]
	}
	return path
}
