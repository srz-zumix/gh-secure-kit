package recommended

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// ConfigFileName is the file name auto-discovered in the current directory
// when no explicit configuration path is given.
const ConfigFileName = ".gh-secure-kit-recommended.yml"

// Config is the recommended settings configuration. Ignore lists the rules, or
// individual targets of a rule, that are excluded from evaluation, typically
// accepted as a baseline by golden.
type Config struct {
	Ignore []IgnoreEntry `yaml:"ignore"`
}

// IgnoreEntry ignores a whole rule when Targets is empty. Otherwise only the
// targets matching one of the Targets regular expressions are ignored.
type IgnoreEntry struct {
	ID      string
	Targets []string
}

// UnmarshalYAML accepts either a rule ID or a mapping of a rule ID to a list of target patterns.
func (e *IgnoreEntry) UnmarshalYAML(data []byte) error {
	var id string
	if err := yaml.Unmarshal(data, &id); err == nil {
		*e = IgnoreEntry{ID: id}
		return nil
	}
	var entry map[string][]string
	if err := yaml.Unmarshal(data, &entry); err != nil {
		return fmt.Errorf("ignore entry must be a rule ID or a mapping of a rule ID to target patterns: %w", err)
	}
	if len(entry) != 1 {
		return fmt.Errorf("ignore entry mapping must have exactly one rule ID, got %d", len(entry))
	}
	for id, targets := range entry {
		if len(targets) == 0 {
			return fmt.Errorf("ignore entry for rule %s has no target patterns", id)
		}
		*e = IgnoreEntry{ID: id, Targets: targets}
	}
	return nil
}

// MarshalYAML writes a whole-rule ignore as a scalar and a targeted one as a mapping.
func (e IgnoreEntry) MarshalYAML() (interface{}, error) {
	if len(e.Targets) == 0 {
		return e.ID, nil
	}
	return map[string][]string{e.ID: e.Targets}, nil
}

// IgnoreIDs returns the IDs of the rules that are ignored as a whole.
func (c *Config) IgnoreIDs() []string {
	var ids []string
	for _, entry := range c.Ignore {
		if len(entry.Targets) == 0 {
			ids = append(ids, entry.ID)
		}
	}
	return ids
}

// TargetIgnores compiles the per-target ignore patterns of the configuration.
func (c *Config) TargetIgnores() (TargetIgnores, error) {
	ignores := TargetIgnores{}
	for _, entry := range c.Ignore {
		id := strings.ToUpper(entry.ID)
		for _, pattern := range entry.Targets {
			re, err := CompileTargetPattern(pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", id, err)
			}
			ignores[id] = append(ignores[id], re)
		}
	}
	return ignores, nil
}

// validate reports unknown rule IDs, targets on rules that do not enumerate
// targets, and invalid target patterns.
func (c *Config) validate() error {
	var ids []string
	for _, entry := range c.Ignore {
		ids = append(ids, entry.ID)
	}
	if unknown := UnknownRuleIDs(ids); len(unknown) > 0 {
		return fmt.Errorf("unknown rule ID(s): %s", strings.Join(unknown, ", "))
	}
	for _, entry := range c.Ignore {
		if len(entry.Targets) == 0 {
			continue
		}
		if rule, _ := RuleByID(strings.ToUpper(entry.ID)); rule.TargetKind == "" {
			return fmt.Errorf("rule %s does not support ignoring individual targets", strings.ToUpper(entry.ID))
		}
	}
	_, err := c.TargetIgnores()
	return err
}

// LoadConfig reads the configuration at path. Rule IDs are normalized to upper
// case; entries are deduplicated and sorted. Unknown rule IDs, targets on rules
// that do not support them, and invalid target patterns are reported as errors.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config file %q: %w", path, err)
	}
	return GoldenConfig(&cfg, nil, false), nil
}

// ResolveConfig loads the configuration at path when it is non-empty.
// Otherwise it auto-discovers ConfigFileName in the current directory and
// returns an empty configuration when that file does not exist.
func ResolveConfig(path string) (*Config, error) {
	if path != "" {
		return LoadConfig(path)
	}
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	path = filepath.Join(dir, ConfigFileName)
	// Lstat so that a dangling symlink is surfaced as a load error instead of
	// being treated as a missing file.
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return &Config{Ignore: []IgnoreEntry{}}, nil
		}
		return nil, err
	}
	return LoadConfig(path)
}

// GoldenRules returns the rules to evaluate for golden after validating the
// rule IDs in filter. Without prune, rules already ignored as a whole by cfg are
// skipped because they stay ignored regardless of their result. With prune, they
// are evaluated so that passing rules can be removed from the configuration.
func GoldenRules(cfg *Config, filter Filter, prune bool) ([]Rule, error) {
	ids := append(append([]string{}, filter.IDs...), filter.IgnoreIDs...)
	if unknown := UnknownRuleIDs(ids); len(unknown) > 0 {
		return nil, fmt.Errorf("unknown rule ID(s): %s", strings.Join(unknown, ", "))
	}
	if !prune {
		filter.IgnoreIDs = append(append([]string{}, filter.IgnoreIDs...), cfg.IgnoreIDs()...)
	}
	return filter.Apply(AllRules()), nil
}

// GoldenTargetIgnores returns the per-target ignores to apply while evaluating
// for golden. With prune none apply, so that every currently failing target is
// reported and stale patterns can be removed.
func GoldenTargetIgnores(cfg *Config, prune bool) (TargetIgnores, error) {
	if prune {
		return nil, nil
	}
	return cfg.TargetIgnores()
}

// GoldenConfig returns a new configuration that keeps every ignore entry of base
// and adds the failing results: a failing rule whose findings are all attributed
// to targets adds one pattern per target, any other failing rule is ignored as a
// whole. With prune, entries of passing results are removed and target patterns
// that match no failing target are dropped; skipped and unevaluated rules always
// keep their entries.
func GoldenConfig(base *Config, results []Result, prune bool) *Config {
	whole := map[string]bool{}
	patterns := map[string]map[string]bool{}
	for _, entry := range base.Ignore {
		id := strings.ToUpper(entry.ID)
		if len(entry.Targets) == 0 {
			whole[id] = true
			continue
		}
		if patterns[id] == nil {
			patterns[id] = map[string]bool{}
		}
		for _, p := range entry.Targets {
			patterns[id][p] = true
		}
	}

	for _, result := range results {
		id := strings.ToUpper(result.Rule.ID)
		switch {
		case prune && result.Status == StatusPass:
			delete(whole, id)
			delete(patterns, id)
		case result.Status != StatusFail || whole[id]:
		case result.Targets == nil:
			whole[id] = true
			delete(patterns, id)
		default:
			patterns[id] = reconcileTargetPatterns(patterns[id], result.Targets, prune)
		}
	}

	var entries []IgnoreEntry
	for id := range whole {
		entries = append(entries, IgnoreEntry{ID: id})
	}
	for id, set := range patterns {
		if whole[id] || len(set) == 0 {
			continue
		}
		targets := make([]string, 0, len(set))
		for p := range set {
			targets = append(targets, p)
		}
		sort.Strings(targets)
		entries = append(entries, IgnoreEntry{ID: id, Targets: targets})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	if entries == nil {
		entries = []IgnoreEntry{}
	}
	return &Config{Ignore: entries}
}

// reconcileTargetPatterns adds an exact pattern for every failing target that no
// existing pattern matches and, with prune, drops patterns matching no failing target.
func reconcileTargetPatterns(existing map[string]bool, failing []string, prune bool) map[string]bool {
	result := map[string]bool{}
	compiled := map[string]*regexp.Regexp{}
	for p := range existing {
		re, err := CompileTargetPattern(p)
		if err != nil {
			// Keep patterns that cannot be evaluated rather than losing them silently.
			result[p] = true
			continue
		}
		compiled[p] = re
	}
	covered := map[string]bool{}
	for p, re := range compiled {
		used := false
		for _, target := range failing {
			if re.MatchString(target) {
				used = true
				covered[target] = true
			}
		}
		if used || !prune {
			result[p] = true
		}
	}
	for _, target := range failing {
		if !covered[target] {
			result[regexp.QuoteMeta(target)] = true
		}
	}
	return result
}

// WriteConfig writes cfg to writer as YAML.
func WriteConfig(writer io.Writer, cfg *Config) error {
	data, err := marshalConfig(cfg)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func marshalConfig(cfg *Config) ([]byte, error) {
	comments := yaml.CommentMap{}
	for index, entry := range cfg.Ignore {
		rule, ok := RuleByID(strings.ToUpper(entry.ID))
		if !ok {
			continue
		}
		path := fmt.Sprintf("$.ignore[%d]", index)
		if len(entry.Targets) > 0 {
			path += "." + entry.ID
		}
		comments[path] = []*yaml.Comment{yaml.LineComment(" " + rule.Title)}
	}
	return yaml.MarshalWithOptions(cfg, yaml.WithComment(comments))
}

func ResolveGoldenOutput(configPath, output string, overwrite bool) (string, error) {
	if output == "" {
		output = configPath
		if output == "" {
			output = ConfigFileName
		}
	}
	if output == "-" {
		return output, nil
	}
	if err := validateConfigOutput(output, overwrite); err != nil {
		return "", err
	}
	return output, nil
}

func validateConfigOutput(path string, overwrite bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !overwrite {
		return fmt.Errorf("configuration output %q already exists; use --overwrite to replace it", path)
	}
	if info.IsDir() {
		return fmt.Errorf("configuration output %q is a directory", path)
	}
	return nil
}

// WriteConfigFile atomically writes cfg, replacing existing paths only when overwrite is true.
func WriteConfigFile(path string, cfg *Config, overwrite bool) error {
	if err := validateConfigOutput(path, overwrite); err != nil {
		return err
	}
	data, err := marshalConfig(cfg)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !overwrite {
		return os.Link(tmpPath, path)
	}
	return os.Rename(tmpPath, path)
}
