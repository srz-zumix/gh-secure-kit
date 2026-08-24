package localscan

import (
	"testing"

	"github.com/google/go-github/v90/github"
)

func TestApplyPatternConfigs(t *testing.T) {
	patterns := []Pattern{
		{ID: "github_personal_access_token", TokenType: "github_token", Enabled: true},
		{ID: "aws_access_key_id", TokenType: "aws_access_key_id", Enabled: true},
		{ID: "custom_thing", TokenType: "unrelated_token", Enabled: true},
	}

	configs := &github.SecretScanningPatternConfigs{
		ProviderPatternOverrides: []*github.SecretScanningPatternOverride{
			{
				TokenType:      github.Ptr("github_token"),
				Setting:        github.Ptr("disabled"),
				DefaultSetting: github.Ptr("enabled"),
			},
			{
				TokenType:      github.Ptr("aws_access_key_id"),
				Setting:        github.Ptr("not_set"),
				DefaultSetting: github.Ptr("enabled"),
			},
		},
	}

	result := ApplyPatternConfigs(patterns, configs)

	byID := make(map[string]Pattern)
	for _, p := range result {
		byID[p.ID] = p
	}

	if byID["github_personal_access_token"].Enabled {
		t.Error("expected github_personal_access_token to be disabled")
	}
	if !byID["aws_access_key_id"].Enabled {
		t.Error("expected aws_access_key_id to fall back to default enabled setting")
	}
	if !byID["custom_thing"].Enabled {
		t.Error("expected pattern with no override to remain unchanged")
	}
}

func TestApplyPatternConfigsNilConfigsIsNoop(t *testing.T) {
	patterns := []Pattern{{ID: "a", Enabled: true}}
	result := ApplyPatternConfigs(patterns, nil)
	if len(result) != 1 || !result[0].Enabled {
		t.Errorf("expected patterns unchanged, got %+v", result)
	}
}
