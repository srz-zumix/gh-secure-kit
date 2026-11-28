package recommended

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

type securityDefaultConfiguration struct {
	DefaultForNewRepos string                     `json:"default_for_new_repos"`
	Configuration      map[string]json.RawMessage `json:"configuration"`
}

func getSecuritySettings(ctx context.Context, g *gh.GitHubClient, path string, result any) error {
	client := g.GetClient()
	req, err := client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("create security settings request: %w", err)
	}
	if _, err := client.Do(req, result); err != nil {
		return fmt.Errorf("get security settings: %w", err)
	}
	return nil
}

func getRepositorySecurityAnalysis(ctx context.Context, g *gh.GitHubClient, repo repository.Repository) (map[string]json.RawMessage, error) {
	var response struct {
		SecurityAndAnalysis map[string]json.RawMessage `json:"security_and_analysis"`
	}
	path := fmt.Sprintf("repos/%s/%s", url.PathEscape(repo.Owner), url.PathEscape(repo.Name))
	if err := getSecuritySettings(ctx, g, path, &response); err != nil {
		return nil, err
	}
	return response.SecurityAndAnalysis, nil
}

func getSecurityDefaults(ctx context.Context, g *gh.GitHubClient, repo repository.Repository) ([]securityDefaultConfiguration, error) {
	var defaults []securityDefaultConfiguration
	path := fmt.Sprintf("orgs/%s/code-security/configurations/defaults", url.PathEscape(repo.Owner))
	if err := getSecuritySettings(ctx, g, path, &defaults); err != nil {
		return nil, err
	}
	return defaults, nil
}

func getAIScanSettings(ctx context.Context, g *gh.GitHubClient, repo repository.Repository, scope Scope) (map[string]json.RawMessage, error) {
	var path string
	if scope == ScopeOrganization {
		path = fmt.Sprintf("orgs/%s/code-scanning/ai-scan", url.PathEscape(repo.Owner))
	} else {
		path = fmt.Sprintf("repos/%s/%s/code-scanning/ai-scan", url.PathEscape(repo.Owner), url.PathEscape(repo.Name))
	}
	var settings map[string]json.RawMessage
	if err := getSecuritySettings(ctx, g, path, &settings); err != nil {
		return nil, err
	}
	return settings, nil
}

func fatalSecuritySettingsError(err error) bool {
	return isAccessDenied(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func securityStringField(object map[string]json.RawMessage, field string) (string, bool) {
	raw, ok := object[field]
	if !ok {
		return "", false
	}
	var value *string
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return "", false
	}
	return *value, true
}

func repositorySecurityStatus(analysis map[string]json.RawMessage, field string) (string, bool) {
	raw, ok := analysis[field]
	if !ok {
		return "", false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return "", false
	}
	return securityStringField(object, "status")
}
