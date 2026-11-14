package localscan

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
)

func TestActionsURLTokenHostTrustAndFallback(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		repoInput   string
		knownHosts  []string
		defaultHost string
		tokens      map[string]string
		wantToken   string
		wantCalls   []string
		wantErr     string
	}{
		{"github token", "github.com", "", nil, "github.com", map[string]string{"github.com": "fixture-github"}, "fixture-github", []string{"github.com"}, ""},
		{"unknown host", "github.example.invalid", "", nil, "github.com", map[string]string{"github.com": "fixture-github"}, "", nil, "not configured"},
		{"unknown host with short repo", "github.example.invalid", "example-owner/example-repo", nil, "github.com", map[string]string{"github.com": "fixture-github"}, "", nil, "not configured"},
		{"configured host token", "github.example.invalid", "", []string{"GitHub.Example.invalid"}, "github.com", map[string]string{"github.example.invalid": "fixture-enterprise", "github.com": "fixture-github"}, "fixture-enterprise", []string{"github.example.invalid"}, ""},
		{"configured default port alias", "github.example.invalid", "", []string{"github.example.invalid:443"}, "github.com", map[string]string{"github.example.invalid:443": "fixture-enterprise"}, "fixture-enterprise", []string{"github.example.invalid", "github.example.invalid:443"}, ""},
		{"app with enterprise default port alias", "github.example.invalid", "", []string{"github.example.invalid:443"}, "github.example.invalid:443", nil, "", []string{"github.example.invalid", "github.example.invalid:443"}, ""},
		{"cloud port alias cannot select enterprise token", "github.com", "", []string{"github.com:443"}, "github.com:443", map[string]string{"github.com:443": "fixture-enterprise"}, "", []string{"github.com"}, "different host"},
		{"explicit host token", "github.example.invalid", "github.example.invalid/example-owner/example-repo", nil, "github.com", map[string]string{"github.example.invalid": "fixture-enterprise"}, "fixture-enterprise", []string{"github.example.invalid"}, ""},
		{"explicit default port", "github.example.invalid", "github.example.invalid:443/example-owner/example-repo", nil, "github.com", map[string]string{"github.example.invalid": "fixture-enterprise"}, "fixture-enterprise", []string{"github.example.invalid"}, ""},
		{"no cross-host fallback", "github.example.invalid", "", []string{"github.example.invalid"}, "github.com", map[string]string{"github.com": "fixture-github"}, "", []string{"github.example.invalid"}, "different host"},
		{"no cross-host fallback for github", "github.com", "", nil, "github.example.invalid", map[string]string{"github.example.invalid": "fixture-enterprise"}, "", []string{"github.com"}, "different host"},
		{"same host without token permits app", "github.example.invalid", "", []string{"github.example.invalid"}, "github.example.invalid", nil, "", []string{"github.example.invalid"}, ""},
		{"different hosts require explicit app host", "github.example.invalid", "", []string{"github.example.invalid"}, "github.com", nil, "", []string{"github.example.invalid"}, "set GH_HOST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			token, err := actionsURLToken(repository.Repository{Host: tt.host}, tt.repoInput, actionsURLAuth{
				knownHosts:  tt.knownHosts,
				defaultHost: tt.defaultHost,
				tokenForHost: func(host string) string {
					calls = append(calls, host)
					return tt.tokens[host]
				},
			})
			if token != tt.wantToken || !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Fatalf("token = %q, calls = %v; want token %q, calls %v", token, calls, tt.wantToken, tt.wantCalls)
			}
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("got error %v, want %q", err, tt.wantErr)
			}
			if err != nil && (strings.Contains(err.Error(), "fixture-github") || strings.Contains(err.Error(), "fixture-enterprise")) {
				t.Fatalf("error disclosed credentials: %v", err)
			}
		})
	}
}
