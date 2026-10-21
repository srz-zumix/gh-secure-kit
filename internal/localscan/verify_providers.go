package localscan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type verificationProvider struct {
	url    string
	method string
	basic  bool
	github bool
}

const githubPublicVerificationURL = "https://api.github.com/user"

var verificationProviders = map[string]verificationProvider{
	"github_personal_access_token": {url: githubPublicVerificationURL, github: true},
	"github_fine_grained_pat":      {url: githubPublicVerificationURL, github: true},
	"github_oauth_token":           {url: githubPublicVerificationURL, github: true},
	"github_app_token":             {url: "https://api.github.com/installation/repositories", github: true},
	"slack_token":                  {url: "https://slack.com/api/auth.test", method: http.MethodPost},
	"stripe_api_key":               {url: "https://api.stripe.com/v1/balance", basic: true},
	"sendgrid_api_key":             {url: "https://api.sendgrid.com/v3/scopes"},
	"npm_access_token":             {url: "https://registry.npmjs.org/-/whoami"},
	"openai_api_key":               {url: "https://api.openai.com/v1/models"},
}

func githubVerificationURL(host string) (string, error) {
	if host == "" {
		host = "github.com"
	}
	endpoint, err := url.Parse("https://" + host)
	if err != nil || endpoint.Host != host || endpoint.User != nil || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || strings.ContainsAny(host, "#\\") {
		return "", fmt.Errorf("verification host must be a hostname with an optional port, not a URL")
	}
	hostname := strings.ToLower(endpoint.Hostname())
	if hostname == "" || len(hostname) > 253 || strings.HasSuffix(host, ":") {
		return "", fmt.Errorf("invalid verification hostname")
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return "", fmt.Errorf("invalid verification host port")
		}
	}
	if net.ParseIP(hostname) == nil {
		for _, label := range strings.Split(hostname, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", fmt.Errorf("invalid verification hostname")
			}
			for _, char := range label {
				if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
					return "", fmt.Errorf("invalid verification hostname")
				}
			}
		}
	}
	endpoint.Host = strings.ToLower(endpoint.Host)
	if hostname == "github.com" || hostname == "api.github.com" {
		port := endpoint.Port()
		endpoint.Host = "api.github.com"
		if port != "" {
			endpoint.Host = net.JoinHostPort("api.github.com", port)
		}
		endpoint.Path = "/user"
	} else {
		endpoint.Path = "/api/v3/user"
	}
	return endpoint.String(), nil
}

func verifyToken(ctx context.Context, client *http.Client, pattern, secret, githubEndpoint string) string {
	if ctx.Err() != nil {
		return ValidityUnknown
	}
	if pattern == "jwt" {
		return verifyJWTExpiry(secret, time.Now())
	}
	provider, ok := verificationProviders[pattern]
	if !ok {
		return ValidityUnsupported
	}
	if provider.github {
		provider.url = githubEndpoint
		if pattern == "github_app_token" {
			endpoint, err := url.Parse(githubEndpoint)
			if err != nil {
				return ValidityUnknown
			}
			endpoint.Path = strings.TrimSuffix(endpoint.Path, "/user") + "/installation/repositories"
			provider.url = endpoint.String()
		}
	}
	method := provider.method
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, provider.url, nil)
	if err != nil {
		return ValidityUnknown
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "gh-secure-kit-secret-verification")
	if provider.github {
		request.Header.Set("Accept", "application/vnd.github+json")
	}
	if provider.basic {
		request.SetBasicAuth(secret, "")
	} else {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	response, err := client.Do(request)
	if err != nil {
		return ValidityUnknown
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return ValidityInactive
	}
	if pattern == "slack_token" && response.StatusCode == http.StatusOK {
		var result struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) != nil {
			return ValidityUnknown
		}
		if result.OK {
			return ValidityActive
		}
		switch result.Error {
		case "invalid_auth", "token_revoked", "account_inactive", "not_authed":
			return ValidityInactive
		default:
			return ValidityUnknown
		}
	}
	if pattern == "stripe_api_key" && response.StatusCode == http.StatusForbidden {
		var result struct {
			Error struct {
				Type string `json:"type"`
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) == nil &&
			(result.Error.Type == "permission_error" || result.Error.Code == "permission_error") {
			return ValidityActive
		}
		return ValidityUnknown
	}
	if response.StatusCode == http.StatusOK {
		return ValidityActive
	}
	return ValidityUnknown
}

func verifyJWTExpiry(secret string, now time.Time) string {
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		return ValidityUnknown
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ValidityUnknown
	}
	var claims map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil {
		return ValidityUnknown
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ValidityUnknown
	}
	expiry, ok := claims["exp"].(json.Number)
	if !ok {
		return ValidityUnknown
	}
	seconds, err := strconv.ParseFloat(string(expiry), 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return ValidityUnknown
	}
	if seconds <= float64(now.Unix()) {
		return ValidityInactive
	}
	return ValidityUnknown
}
