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

const ConfigFileName = ".gh-secure-kit-recommended.yml"

type Config struct {
	Ignore []string `yaml:"ignore"`
}

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

func ResolveConfig(path string) (*Config, error) {
	if path != "" {
		return LoadConfig(path)
	}
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	path = filepath.Join(dir, ConfigFileName)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return &Config{Ignore: []string{}}, nil
		}
		return nil, err
	}
	return LoadConfig(path)
}

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

func WriteConfig(writer io.Writer, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}
