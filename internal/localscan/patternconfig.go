package localscan

import "github.com/google/go-github/v90/github"

// ApplyPatternConfigs filters and enables/disables patterns according to an
// organization's secret scanning pattern configuration, matching on token
// type. Patterns with no matching override are left unchanged.
func ApplyPatternConfigs(patterns []Pattern, configs *github.SecretScanningPatternConfigs) []Pattern {
	if configs == nil {
		return patterns
	}

	settings := make(map[string]string)
	for _, p := range configs.ProviderPatternOverrides {
		settings[p.GetTokenType()] = effectiveSetting(p.GetSetting(), p.GetDefaultSetting())
	}
	for _, p := range configs.CustomPatternOverrides {
		settings[p.GetTokenType()] = effectiveSetting(p.GetSetting(), p.GetDefaultSetting())
	}

	result := make([]Pattern, len(patterns))
	for i, p := range patterns {
		result[i] = p
		if setting, ok := settings[p.TokenType]; ok {
			result[i].Enabled = setting == "enabled"
		}
	}
	return result
}

// effectiveSetting resolves a pattern's effective setting, falling back to
// the default when explicitly "not_set".
func effectiveSetting(setting, defaultSetting string) string {
	if setting == "" || setting == "not_set" {
		return defaultSetting
	}
	return setting
}
