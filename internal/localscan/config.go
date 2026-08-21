package localscan

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

// ConfigFileName is the default configuration file name searched for at the
// repository root.
const ConfigFileName = ".gh-secure-kit-secret-scanning.yml"

// Config is the YAML configuration schema for local secret scanning.
type Config struct {
	Patterns  []ConfigPattern `yaml:"patterns"`
	Allowlist ConfigAllowlist `yaml:"allowlist"`
}

// ConfigPattern defines a user-provided detection pattern, merged with the
// builtin patterns (a matching ID overrides the builtin definition).
type ConfigPattern struct {
	ID          string   `yaml:"id"`
	TokenType   string   `yaml:"token_type"`
	DisplayName string   `yaml:"display_name"`
	Regex       string   `yaml:"regex"`
	Keywords    []string `yaml:"keywords"`
}

// ConfigAllowlist defines exclusions applied to scan findings.
type ConfigAllowlist struct {
	Regexes   []string `yaml:"regexes"`
	Paths     []string `yaml:"paths"`
	Commits   []string `yaml:"commits"`
	StopWords []string `yaml:"stopwords"`
}

// LoadConfig reads and parses a configuration file at the given path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", path, err)
	}
	return &cfg, nil
}

// DiscoverConfig looks for the default config file starting at dir and
// returns its path, or an empty string if not found.
func DiscoverConfig(dir string) string {
	candidate := filepath.Join(dir, ConfigFileName)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}
