package localscan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

func TestGitHubVerificationURL(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"", "https://api.github.com/user"},
		{"github.com", "https://api.github.com/user"},
		{"api.github.com", "https://api.github.com/user"},
		{"GITHUB.COM", "https://api.github.com/user"},
		{"github.com:443", "https://api.github.com/user"},
		{"api.github.com:443", "https://api.github.com/user"},
		{"github.com:8443", "https://api.github.com:8443/user"},
		{"github.example.com", "https://github.example.com/api/v3/user"},
		{"github.example.com:8443", "https://github.example.com:8443/api/v3/user"},
		{"[::1]:8443", "https://[::1]:8443/api/v3/user"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			got, err := githubVerificationURL(tc.host)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, host := range []string{
		"https://github.example.com", "http://github.example.com", "github.example.com/api/v3",
		"user@github.example.com", "github.example.com?query=1", "github.example.com#fragment",
		"github.example.com#", "github.example.com?", "github.example.com:0", "github.example.com:65536",
		"github.example.com:", "github.example.com:invalid", "-example.com", "github..example.com",
		"github.example.com;command", "github.example.com$(command)", "github.example.com\ncommand",
		"github.example.com\\path", "github.example.com'", "github.example.com ",
	} {
		t.Run(host, func(t *testing.T) {
			if _, err := githubVerificationURL(host); err == nil {
				t.Fatal("accepted an unsafe or invalid verification host")
			}
		})
	}
}

func TestVerificationGitHubEnterpriseRouting(t *testing.T) {
	const host = "github.example.com:8443"
	for pattern, provider := range verificationProviders {
		t.Run(pattern, func(t *testing.T) {
			var requests atomic.Int32
			var publicRequests atomic.Int32
			client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				endpoint, _ := url.Parse(provider.url)
				if provider.github && request.Host == "api.github.com" {
					publicRequests.Add(1)
				} else if provider.github {
					endpoint, _ = url.Parse("https://" + host + "/api/v3/user")
					if pattern == "github_app_token" {
						endpoint.Path = "/api/v3/installation/repositories"
					}
				}
				if request.Host != endpoint.Host || request.URL.Path != endpoint.Path {
					t.Error("token was routed to an unexpected host or API path")
				}
				writer.WriteHeader(http.StatusOK)
				writeVerificationResponse(t, writer, `{"ok":true}`)
			})
			findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: pattern}}
			if err := verifyFindings(context.Background(), findings, client, host); err != nil {
				t.Fatal(err)
			}
			wantRequests, wantPublic := int32(1), int32(0)
			if provider.github {
				wantRequests, wantPublic = 2, 1
			}
			if requests.Load() != wantRequests || publicRequests.Load() != wantPublic || findings[0].Validity != ValidityActive || findings[0].rawSecret != "" {
				t.Fatal("incorrect result or verification destinations")
			}
			if verificationProviders[pattern].url != provider.url {
				t.Fatal("host selection modified the shared provider table")
			}
		})
	}
}

func TestVerificationGitHubEnterpriseAuthenticatedUser(t *testing.T) {
	for _, pattern := range []string{"github_personal_access_token", "github_fine_grained_pat", "github_oauth_token"} {
		t.Run(pattern, func(t *testing.T) {
			client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Authorization") != "Bearer "+testGitHubToken || request.Header.Get("Accept") != "application/vnd.github+json" {
					t.Error("incorrect GitHub authentication or media type")
				}
				switch {
				case request.Host == "github.example.com" && request.URL.Path == "/api/v3/user":
					writer.WriteHeader(http.StatusOK)
					writeVerificationResponse(t, writer, `{"login":"example-user","id":123}`)
				case request.Host == "github.example.com" && request.URL.Path == "/api/v3/rate_limit":
					writer.WriteHeader(http.StatusForbidden)
				default:
					writer.WriteHeader(http.StatusUnauthorized)
				}
			})
			findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: pattern}}
			if err := verifyFindings(context.Background(), findings, client, "github.example.com"); err != nil {
				t.Fatal(err)
			}
			if findings[0].Validity != ValidityActive {
				t.Fatalf("got %q, want active from the authenticated user endpoint", findings[0].Validity)
			}
		})
	}
}

func TestVerificationGitHubInstallationProbe(t *testing.T) {
	for _, host := range []string{"", "github.com", "github.example.com:8443"} {
		t.Run(host, func(t *testing.T) {
			var requests atomic.Int32
			client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if (request.Host != "api.github.com" || request.URL.Path != "/installation/repositories") &&
					(request.Host != "github.example.com:8443" || request.URL.Path != "/api/v3/installation/repositories") {
					t.Error("installation token was sent to an incorrect authentication endpoint")
					writer.WriteHeader(http.StatusForbidden)
					return
				}
				writer.WriteHeader(http.StatusOK)
				writeVerificationResponse(t, writer, `{"total_count":0,"repositories":[]}`)
			})
			findings := []Finding{{rawSecret: "synthetic-installation-token", verificationPattern: "github_app_token"}}
			if err := verifyFindings(context.Background(), findings, client, host); err != nil {
				t.Fatal(err)
			}
			wantRequests := int32(1)
			if host == "github.example.com:8443" {
				wantRequests = 2
			}
			if findings[0].Validity != ValidityActive || requests.Load() != wantRequests {
				t.Fatal("incorrect installation validity or duplicate verification")
			}
		})
	}
}

func TestVerificationGitHubEnterpriseRejection(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{401, ValidityInactive},
		{403, ValidityUnknown},
		{429, ValidityUnknown},
		{302, ValidityUnknown},
		{500, ValidityUnknown},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			var requests atomic.Int32
			client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if (request.Host != "github.example.com" || request.URL.Path != "/api/v3/user") &&
					(request.Host != "api.github.com" || request.URL.Path != "/user") {
					t.Error("GitHub token was sent to an unexpected host or path")
				}
				writer.Header().Set("Location", "https://api.github.com/user")
				writer.WriteHeader(tc.status)
			})
			findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: "github_oauth_token"}}
			if err := verifyFindings(context.Background(), findings, client, "github.example.com"); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 2 || findings[0].Validity != tc.want {
				t.Fatal("unexpected retry, redirect, or validity")
			}
		})
	}
}

func TestVerificationGitHubCombinedValidity(t *testing.T) {
	for _, tc := range []struct {
		enterpriseStatus int
		publicStatus     int
		want             string
	}{
		{200, 200, ValidityActive},
		{200, 401, ValidityActive},
		{401, 200, ValidityActive},
		{200, 500, ValidityActive},
		{500, 200, ValidityActive},
		{401, 401, ValidityInactive},
		{401, 403, ValidityUnknown},
		{403, 401, ValidityUnknown},
		{401, 429, ValidityUnknown},
		{429, 401, ValidityUnknown},
		{401, 500, ValidityUnknown},
		{500, 401, ValidityUnknown},
		{500, 500, ValidityUnknown},
	} {
		t.Run(fmt.Sprintf("enterprise_%d_public_%d", tc.enterpriseStatus, tc.publicStatus), func(t *testing.T) {
			var enterpriseRequests, publicRequests atomic.Int32
			client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Authorization") != "Bearer "+testGitHubToken {
					t.Error("verification did not send the expected synthetic token")
				}
				switch request.Host {
				case "github.example.com":
					enterpriseRequests.Add(1)
					writer.WriteHeader(tc.enterpriseStatus)
				case "api.github.com":
					publicRequests.Add(1)
					writer.WriteHeader(tc.publicStatus)
				default:
					t.Error("verification used an unexpected destination")
					writer.WriteHeader(http.StatusInternalServerError)
				}
			})
			findings := []Finding{
				{rawSecret: testGitHubToken, verificationPattern: "github_personal_access_token"},
				{rawSecret: testGitHubToken, verificationPattern: "github_personal_access_token"},
			}
			if err := verifyFindings(context.Background(), findings, client, "github.example.com"); err != nil {
				t.Fatal(err)
			}
			if enterpriseRequests.Load() != 1 || publicRequests.Load() != 1 {
				t.Fatal("each unique token must be checked once on both hosts")
			}
			for _, finding := range findings {
				if finding.Validity != tc.want || finding.rawSecret != "" || finding.verificationPattern != "" {
					t.Fatalf("got validity %q, want %q, or retained raw verification data", finding.Validity, tc.want)
				}
			}
			wantRemaining := 2
			if tc.want == ValidityInactive {
				wantRemaining = 0
			}
			if remaining := len(ExcludeFindings(findings, []string{ValidityInactive})); remaining != wantRemaining {
				t.Fatalf("got %d remaining findings, want %d", remaining, wantRemaining)
			}
		})
	}
}

func TestVerificationGitHubPublicHostNotDuplicated(t *testing.T) {
	for _, host := range []string{"", "github.com", "GITHUB.COM", "api.github.com"} {
		t.Run(host, func(t *testing.T) {
			var requests atomic.Int32
			client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.Host != "api.github.com" || request.URL.Path != "/user" {
					t.Error("verification used an unexpected destination")
				}
				writer.WriteHeader(http.StatusOK)
			})
			findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: "github_personal_access_token"}}
			if err := verifyFindings(context.Background(), findings, client, host); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 || findings[0].Validity != ValidityActive {
				t.Fatal("GitHub.com was not checked exactly once")
			}
		})
	}
}

func TestVerificationHostValidation(t *testing.T) {
	for _, tc := range []struct {
		verify    bool
		hosts     []string
		wantError bool
	}{
		{true, []string{"github.example.com"}, false},
		{false, []string{"github.example.com"}, true},
		{false, []string{""}, false},
		{true, []string{"https://github.example.com"}, true},
		{true, []string{"github.example.com", "other.example.com"}, true},
	} {
		if err := ValidateVerificationOptions(tc.verify, nil, tc.hosts...); (err != nil) != tc.wantError {
			t.Fatal("unexpected verification host validation result")
		}
	}
	client := &http.Client{Transport: verificationRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("invalid host triggered a request")
		return nil, errors.New("network disabled")
	})}
	findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: "github_personal_access_token"}}
	if err := verifyFindings(context.Background(), findings, client, "https://github.example.com"); err == nil || findings[0].rawSecret != "" {
		t.Fatal("invalid host did not fail or retained a raw secret")
	}
}

func TestExcludeFindings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		excluded []string
		want     []string
	}{
		{"none", nil, []string{ValidityActive, ValidityInactive, ValidityUnknown, ValidityUnsupported, ""}},
		{"inactive", []string{ValidityInactive}, []string{ValidityActive, ValidityUnknown, ValidityUnsupported, ""}},
		{"multiple", []string{ValidityInactive, ValidityUnknown}, []string{ValidityActive, ValidityUnsupported, ""}},
		{"active", []string{ValidityActive}, []string{ValidityInactive, ValidityUnknown, ValidityUnsupported, ""}},
		{"unsupported", []string{ValidityUnsupported}, []string{ValidityActive, ValidityInactive, ValidityUnknown, ""}},
		{"duplicate", []string{ValidityInactive, ValidityInactive}, []string{ValidityActive, ValidityUnknown, ValidityUnsupported, ""}},
		{"all verified", []string{ValidityActive, ValidityInactive, ValidityUnknown, ValidityUnsupported}, []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var findings []Finding
			for _, validity := range []string{ValidityActive, ValidityInactive, ValidityUnknown, ValidityUnsupported, ""} {
				findings = append(findings, Finding{Validity: validity})
			}
			got := ExcludeFindings(findings, tc.excluded)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings, want %d", len(got), len(tc.want))
			}
			for index, validity := range tc.want {
				if got[index].Validity != validity {
					t.Fatalf("finding %d: got %q, want %q", index, got[index].Validity, validity)
				}
			}
		})
	}
}

func TestExcludeFindingsSingleStatus(t *testing.T) {
	for _, tc := range []struct {
		name       string
		validities []string
		want       []string
	}{
		{"empty", nil, nil},
		{"all inactive", []string{ValidityInactive, ValidityInactive}, nil},
		{"mixed", []string{ValidityInactive, ValidityActive, ValidityUnknown, ValidityInactive, ValidityUnsupported, ""}, []string{ValidityActive, ValidityUnknown, ValidityUnsupported, ""}},
		{"no inactive", []string{ValidityActive, ValidityUnknown, ValidityUnsupported, ""}, []string{ValidityActive, ValidityUnknown, ValidityUnsupported, ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var findings []Finding
			for _, validity := range tc.validities {
				findings = append(findings, Finding{Validity: validity})
			}
			got := ExcludeFindings(findings, []string{ValidityInactive})
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings, want %d", len(got), len(tc.want))
			}
			for index := range got {
				if got[index].Validity != tc.want[index] {
					t.Fatalf("finding %d: got %q, want %q", index, got[index].Validity, tc.want[index])
				}
			}
		})
	}
}

func TestValidateVerificationOptions(t *testing.T) {
	for _, verify := range []bool{false, true} {
		for _, excluded := range [][]string{nil, {ValidityInactive}, {ValidityInactive, ValidityUnknown}, {ValidityActive, ValidityUnsupported}} {
			err := ValidateVerificationOptions(verify, excluded)
			if (err != nil) != (len(excluded) > 0 && !verify) {
				t.Fatalf("verify=%v excluded=%v: unexpected validation result", verify, excluded)
			}
		}
	}
	for _, excluded := range [][]string{{""}, {"invalid"}, {"Inactive"}, {ValidityInactive, "unknown;command"}, {"inactive,unknown"}} {
		if err := ValidateVerificationOptions(true, excluded); err == nil {
			t.Fatalf("accepted invalid excluded statuses: %v", excluded)
		}
	}
}

func TestVerificationRetainsOnlyOptedInBuiltinSecrets(t *testing.T) {
	for _, verify := range []bool{false, true} {
		for _, custom := range []bool{false, true} {
			var cfg *Config
			if custom {
				cfg = &Config{Patterns: []ConfigPattern{{ID: "github_personal_access_token", Regex: `ghp_[0-9A-Za-z]{36}`}}}
			}
			scanner, err := NewScanner(cfg, false)
			if err != nil {
				t.Fatal(err)
			}
			scanner.Verify = verify
			findings := scanner.ScanFragment(Fragment{Content: testGitHubToken})
			if len(findings) != 1 {
				t.Fatalf("got %d findings", len(findings))
			}
			finding := findings[0]
			retained := finding.rawSecret != "" && finding.verificationPattern != ""
			if retained != (verify && !custom) {
				t.Fatalf("verify=%v custom=%v: incorrect raw value retention", verify, custom)
			}
			data, err := json.Marshal(finding)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), testGitHubToken) || strings.Contains(string(data), `"validity"`) {
				t.Fatal("JSON exposed a raw secret or an unset validity")
			}
		}
	}
}

type verificationRoundTripper func(*http.Request) (*http.Response, error)

func (transport verificationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func writeVerificationResponse(t *testing.T, writer http.ResponseWriter, body string) {
	t.Helper()
	if _, err := fmt.Fprint(writer, body); err != nil {
		t.Errorf("failed to write verification response: %v", err)
	}
}

func localVerificationClient(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: verificationRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme != "https" {
			t.Error("verification endpoint was not HTTPS")
		}
		forwarded := request.Clone(request.Context())
		forwarded.URL.Scheme = target.Scheme
		forwarded.URL.Host = target.Host
		return server.Client().Transport.RoundTrip(forwarded)
	})}
}

func TestVerificationProviderResponses(t *testing.T) {
	for pattern, provider := range verificationProviders {
		t.Run(pattern, func(t *testing.T) {
			for _, tc := range []struct {
				name, body, want string
				status           int
			}{
				{"accepted", `{"ok":true}`, ValidityActive, 200},
				{"rejected", `{}`, ValidityInactive, 401},
				{"forbidden", `{}`, ValidityUnknown, 403},
				{"limited", `{}`, ValidityUnknown, 429},
				{"server error", `{}`, ValidityUnknown, 500},
			} {
				// SendGrid 401 stays unknown because IP Access Management can reject valid keys.
				// OpenAI 401 stays unknown unless the body explicitly reports an invalid key.
				if (pattern == "sendgrid_api_key" || pattern == "openai_api_key") && tc.status == http.StatusUnauthorized {
					tc.want = ValidityUnknown
				}
				t.Run(tc.name, func(t *testing.T) {
					client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
						endpoint, _ := url.Parse(provider.url)
						if request.Host != endpoint.Host || request.URL.Path != endpoint.Path || request.URL.RawQuery != "" {
							t.Error("unexpected verification endpoint")
						}
						method := http.MethodGet
						if provider.method != "" {
							method = provider.method
							if request.ContentLength != 0 {
								t.Error("verification POST had a payload")
							}
						}
						if request.Method != method {
							t.Error("unexpected verification method")
						}
						if provider.basic {
							username, password, ok := request.BasicAuth()
							if !ok || username != testGitHubToken || password != "" {
								t.Error("incorrect basic authentication")
							}
						} else if request.Header.Get("Authorization") != "Bearer "+testGitHubToken {
							t.Error("incorrect bearer authentication")
						}
						writer.WriteHeader(tc.status)
						writeVerificationResponse(t, writer, tc.body)
					})
					findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: pattern}}
					if err := verifyFindings(context.Background(), findings, client); err != nil {
						t.Fatal(err)
					}
					if findings[0].Validity != tc.want || findings[0].rawSecret != "" {
						t.Fatalf("got validity %q, want %q, or retained raw secret", findings[0].Validity, tc.want)
					}
				})
			}
		})
	}
}

func TestVerificationProviderSpecificErrors(t *testing.T) {
	for _, tc := range []struct {
		pattern, body, want string
		status              int
	}{
		{"slack_token", `{"ok":false,"error":"invalid_auth"}`, ValidityUnknown, 200},
		{"slack_token", `{"ok":false,"error":"token_revoked"}`, ValidityInactive, 200},
		{"slack_token", `{"ok":false,"error":"account_inactive"}`, ValidityInactive, 200},
		{"slack_token", `{"ok":false,"error":"not_authed"}`, ValidityInactive, 200},
		{"slack_token", `{"ok":false,"error":"missing_scope"}`, ValidityUnknown, 200},
		{"slack_token", `broken`, ValidityUnknown, 200},
		{"stripe_api_key", `{"error":{"type":"permission_error"}}`, ValidityActive, 403},
		{"stripe_api_key", `broken`, ValidityUnknown, 403},
		{"openai_api_key", `{"error":{"code":"invalid_api_key"}}`, ValidityInactive, 401},
		{"openai_api_key", `{"error":{"code":"ip_not_authorized"}}`, ValidityUnknown, 401},
		{"openai_api_key", `{"error":{"code":"no_organization"}}`, ValidityUnknown, 401},
		{"openai_api_key", `broken`, ValidityUnknown, 401},
		{"sendgrid_api_key", `{"errors":[{"message":"The requestor's IP Address is not whitelisted"}]}`, ValidityUnknown, 401},
	} {
		t.Run(tc.pattern+tc.body, func(t *testing.T) {
			client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(tc.status)
				writeVerificationResponse(t, writer, tc.body)
			})
			findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: tc.pattern}}
			if err := verifyFindings(context.Background(), findings, client); err != nil {
				t.Fatal(err)
			}
			if findings[0].Validity != tc.want {
				t.Fatalf("got %q, want %q", findings[0].Validity, tc.want)
			}
			if remaining := len(ExcludeFindings(findings, []string{ValidityInactive})); (tc.want == ValidityInactive) != (remaining == 0) {
				t.Fatalf("unexpected exclusion result for validity %q", tc.want)
			}
		})
	}
}

func TestVerificationDoesNotFollowRedirects(t *testing.T) {
	var requests atomic.Int32
	client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.Header().Set("Location", "/redirected")
		writer.WriteHeader(http.StatusFound)
	})
	findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: "github_personal_access_token"}}
	if err := verifyFindings(context.Background(), findings, client); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || findings[0].Validity != ValidityUnknown {
		t.Fatal("redirect followed or incorrect validity")
	}
}

func TestVerificationDeduplicatesAndLimitsConcurrency(t *testing.T) {
	var requests, running, peak atomic.Int32
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		current := running.Add(1)
		defer running.Add(-1)
		for previous := peak.Load(); current > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, current) {
				break
			}
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		writer.WriteHeader(http.StatusOK)
	})
	var findings []Finding
	for index := range 6 {
		for range 2 {
			findings = append(findings, Finding{rawSecret: fmt.Sprintf("ghp_%036d", index+1), verificationPattern: "github_personal_access_token"})
		}
	}
	done := make(chan error, 1)
	go func() { done <- verifyFindings(context.Background(), findings, client) }()
	for range 4 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("verification workers did not start")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 6 || peak.Load() != 4 {
		t.Fatalf("requests=%d peak=%d, want 6 and 4", requests.Load(), peak.Load())
	}
	for _, finding := range findings {
		if finding.Validity != ValidityActive || finding.rawSecret != "" {
			t.Fatal("incorrect result or retained raw secret")
		}
	}
}

func TestVerificationTimeoutAndCancellation(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Millisecond, Transport: verificationRoundTripper(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	findings := []Finding{{rawSecret: testGitHubToken, verificationPattern: "github_personal_access_token"}}
	if err := verifyFindings(context.Background(), findings, client); err != nil || findings[0].Validity != ValidityUnknown {
		t.Fatal("timeout did not produce unknown")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings[0].rawSecret = testGitHubToken
	findings[0].verificationPattern = "github_personal_access_token"
	if err := verifyFindings(ctx, findings, client); !errors.Is(err, context.Canceled) || findings[0].rawSecret != "" {
		t.Fatal("cancellation did not clear raw data or propagate")
	}
}

func TestVerificationOfflineAndUnsupported(t *testing.T) {
	client := &http.Client{Transport: verificationRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("unexpected external request")
		return nil, errors.New("network disabled")
	})}
	findings := []Finding{{PatternID: "github_personal_access_token"}, {rawSecret: "example", verificationPattern: "aws_access_key_id"}}
	if err := verifyFindings(context.Background(), findings, client); err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Validity != ValidityUnsupported {
			t.Fatal("untrusted or unsupported pattern was verified")
		}
	}
	now := time.Unix(2000, 0)
	for _, tc := range []struct{ payload, want string }{
		{`{"exp":1000}`, ValidityInactive},
		{`{"exp":2000}`, ValidityInactive},
		{`{"exp":3000}`, ValidityUnknown},
		{`{"exp":"1000"}`, ValidityUnknown},
		{`{"exp":1e9999}`, ValidityUnknown},
		{`{}`, ValidityUnknown},
		{`broken`, ValidityUnknown},
		{`{"exp":1000} trailing`, ValidityUnknown},
	} {
		token := "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(tc.payload)) + ".synthetic-signature"
		if got := verifyJWTExpiry(token, now); got != tc.want {
			t.Fatalf("payload %q: got %q, want %q", tc.payload, got, tc.want)
		}
	}
}

func TestVerificationValidityRendering(t *testing.T) {
	for name, renderFindings := range map[string]func(*render.Renderer, []Finding) error{
		"local": RenderLocalFindings, "copilot": RenderCopilotFindings,
	} {
		t.Run(name, func(t *testing.T) {
			for _, validity := range []string{"", ValidityInactive} {
				output := render.NewStringRenderer(nil)
				findings := []Finding{{PatternID: "example", Secret: "masked", Validity: validity}}
				if err := renderFindings(&output.Renderer, findings); err != nil {
					t.Fatal(err)
				}
				text := strings.ToLower(output.Stdout.String())
				if strings.Contains(text, "[inactive]") != (validity != "") {
					t.Fatal("incorrect conditional validity status")
				}
				if validity != "" && !strings.Contains(text, validity) {
					t.Fatal("validity was not rendered")
				}
				data, err := json.Marshal(findings)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), `"validity"`) != (validity != "") {
					t.Fatal("incorrect conditional JSON validity")
				}
			}
		})
	}
}

func TestVerificationMaskedScanPipeline(t *testing.T) {
	scanner, err := NewScanner(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	scanner.Verify = true
	findings := scanner.ScanFragment(Fragment{Content: testGitHubToken})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	client := localVerificationClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testGitHubToken {
			t.Error("verifier did not receive the original value")
		}
		writer.WriteHeader(http.StatusUnauthorized)
	})
	if err := verifyFindings(context.Background(), findings, client); err != nil {
		t.Fatal(err)
	}
	if findings[0].Validity != ValidityInactive || findings[0].rawSecret != "" {
		t.Fatal("incorrect validity or retained raw value")
	}
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), testGitHubToken) || !strings.Contains(string(data), `"validity":"inactive"`) {
		t.Fatal("JSON exposed a raw value or omitted validity")
	}
}
