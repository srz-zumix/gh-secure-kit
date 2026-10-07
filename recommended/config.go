package recommended

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// ConfigFileName is the file name auto-discovered in the current directory
// when no explicit configuration path is given.
const ConfigFileName = ".gh-secure-kit-recommended.yml"

// Config is the recommended settings configuration. Ignore lists rule IDs that
// are excluded from evaluation, typically accepted as a baseline by golden.
type Config struct {
	Ignore []string `yaml:"ignore"`
}

// LoadConfig reads the configuration at path. Rule IDs are normalized to upper
// case, deduplicated, and sorted; unknown rule IDs are reported as an error.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", path, err)
	}
	if unknown := UnknownRuleIDs(cfg.Ignore); len(unknown) > 0 {
		return nil, fmt.Errorf("unknown rule ID(s) in config file %q: %s", path, strings.Join(unknown, ", "))
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
			return &Config{Ignore: []string{}}, nil
		}
		return nil, err
	}
	return LoadConfig(path)
}

// GoldenRules returns the rules to evaluate for golden after validating the
// rule IDs in filter. Without prune, rules already ignored by cfg are skipped
// because they stay ignored regardless of their result. With prune, they are
// evaluated so that passing rules can be removed from the configuration.
func GoldenRules(cfg *Config, filter Filter, prune bool) ([]Rule, error) {
	ids := append(append([]string{}, filter.IDs...), filter.IgnoreIDs...)
	if unknown := UnknownRuleIDs(ids); len(unknown) > 0 {
		return nil, fmt.Errorf("unknown rule ID(s): %s", strings.Join(unknown, ", "))
	}
	if !prune {
		filter.IgnoreIDs = append(append([]string{}, filter.IgnoreIDs...), cfg.Ignore...)
	}
	return filter.Apply(AllRules()), nil
}

// GoldenConfig returns a new configuration that keeps every ignored ID of base
// and adds the IDs of failing results. With prune, IDs of passing results are
// removed; skipped and unevaluated rules always remain ignored.
func GoldenConfig(base *Config, results []Result, prune bool) *Config {
	ignore := toSet(base.Ignore)
	for _, result := range results {
		id := strings.ToUpper(result.Rule.ID)
		if result.Status == StatusFail {
			ignore[id] = true
		} else if prune && result.Status == StatusPass {
			delete(ignore, id)
		}
	}
	cfg := &Config{Ignore: make([]string, 0, len(ignore))}
	for id := range ignore {
		cfg.Ignore = append(cfg.Ignore, id)
	}
	sort.Strings(cfg.Ignore)
	return cfg
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
	for index, id := range cfg.Ignore {
		if rule, ok := RuleByID(strings.ToUpper(id)); ok {
			comments[fmt.Sprintf("$.ignore[%d]", index)] = []*yaml.Comment{yaml.LineComment(" " + rule.Title)}
		}
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
