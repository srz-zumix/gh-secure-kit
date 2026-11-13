package localscan

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

type actionsURLAuth struct {
	knownHosts   []string
	defaultHost  string
	tokenForHost func(string) string
}

func actionsURLToken(repo repository.Repository, repoInput string, authInfo actionsURLAuth) (string, error) {
	trusted := strings.EqualFold(repo.Host, "github.com") || actionsRepoExplicitlyNamesHost(repoInput, repo.Host)
	var aliases []string
	for _, host := range authInfo.knownHosts {
		canonical, err := canonicalActionsHostString(host)
		if err == nil && strings.EqualFold(canonical, repo.Host) {
			trusted = true
			if !strings.EqualFold(host, repo.Host) {
				aliases = append(aliases, host)
			}
		}
	}
	if !trusted {
		return "", fmt.Errorf("--run URL host is not configured in gh; use GH_HOST or a matching host-qualified --repo")
	}
	token := authInfo.tokenForHost(repo.Host)
	if token != "" {
		return token, nil
	}
	enterpriseHost := repo.Host != "github.com" && repo.Host != "github.localhost" && !strings.HasSuffix(repo.Host, ".ghe.com")
	if enterpriseHost {
		for _, alias := range aliases {
			if token := authInfo.tokenForHost(alias); token != "" {
				return token, nil
			}
		}
	}
	sameDefaultHost := strings.EqualFold(repo.Host, authInfo.defaultHost)
	if !sameDefaultHost && enterpriseHost {
		defaultHost, err := canonicalActionsHostString(authInfo.defaultHost)
		sameDefaultHost = err == nil && strings.EqualFold(repo.Host, defaultHost)
	}
	if !sameDefaultHost {
		return "", fmt.Errorf("no credentials for the --run URL host; refusing fallback from a different host (set GH_HOST for GitHub App authentication)")
	}
	return "", nil
}

func actionsRepoExplicitlyNamesHost(input, host string) bool {
	if !strings.Contains(input, "://") {
		parts := strings.SplitN(input, "/", 3)
		if len(parts) != 3 {
			return false
		}
		input = "https://" + parts[0]
	}
	u, err := url.Parse(input)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	explicitHost, err := canonicalActionsHost(u)
	return err == nil && strings.EqualFold(explicitHost, host)
}

// NewActionsClient prevents inferred URL hosts from receiving unrelated credentials.
func NewActionsClient(repo repository.Repository, inferredURL bool, repoInput string) (*gh.GitHubClient, error) {
	if !inferredURL {
		return gh.NewGitHubClientWithRepo(repo)
	}
	defaultHost, _ := auth.DefaultHost()
	token, err := actionsURLToken(repo, repoInput, actionsURLAuth{
		knownHosts:  auth.KnownHosts(),
		defaultHost: defaultHost,
		tokenForHost: func(host string) string {
			token, _ := auth.TokenForHost(host)
			return token
		},
	})
	if err != nil {
		return nil, err
	}
	if token != "" {
		return gh.NewGitHubClientWithToken(repo, token)
	}
	return gh.NewGitHubClientWithRepo(repo)
}
