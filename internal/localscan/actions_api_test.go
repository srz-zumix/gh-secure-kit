package localscan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v93/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh/client"
)

type actionsFixtureTransport struct {
	storageURL    string
	requests      []string
	logStatus     map[string]int
	logFailure    error
	archiveStatus int
}

func (f *actionsFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer synthetic-api-credential")
	f.requests = append(f.requests, req.URL.RequestURI())
	header := http.Header{"Content-Type": []string{"application/json"}}
	status := http.StatusOK
	body := ""
	switch req.URL.Path {
	case "/repos/example-owner/example-repo/actions/workflows":
		if req.URL.Query().Get("page") == "2" {
			body = `{"total_count":2,"workflows":[{"id":5,"name":"Release","path":".github/workflows/release.yml"}]}`
		} else {
			body = `{"total_count":2,"workflows":[{"id":4,"name":"Build","path":".github/workflows/build.yml"}]}`
			header.Set("Link", `<https://api.example.invalid/repos/example-owner/example-repo/actions/workflows?page=2&per_page=100>; rel="next"`)
		}
	case "/repos/example-owner/example-repo/actions/workflows/4/runs",
		"/repos/example-owner/example-repo/actions/workflows/5/runs":
		if req.URL.Query().Get("status") != "completed" {
			return nil, fmt.Errorf("workflow runs request does not select completed runs")
		}
		if strings.Contains(req.URL.Path, "/workflows/4/") {
			body = `{"total_count":1,"workflow_runs":[{"id":400,"workflow_id":4,"run_attempt":2,"status":"completed","name":"Build","path":".github/workflows/build.yml"}]}`
		} else {
			body = `{"total_count":1,"workflow_runs":[{"id":500,"workflow_id":5,"run_attempt":1,"status":"completed","name":"Release","path":".github/workflows/release.yml"}]}`
		}
	case "/repos/example-owner/example-repo/actions/runs/400":
		body = `{"id":400,"workflow_id":4,"run_attempt":2,"status":"completed","name":"Build","path":".github/workflows/build.yml"}`
	case "/repos/example-owner/example-repo/actions/runs/500":
		body = `{"id":500,"workflow_id":5,"run_attempt":1,"status":"completed","name":"Release","path":".github/workflows/release.yml"}`
	case "/repos/example-owner/example-repo/actions/runs/400/attempts/1":
		body = `{"id":400,"workflow_id":4,"run_attempt":1,"status":"completed","name":"Build","path":".github/workflows/build.yml"}`
	case "/repos/example-owner/example-repo/actions/runs/400/attempts/1/jobs":
		body = `{"total_count":1,"jobs":[{"id":4000,"run_id":400,"run_attempt":1,"name":"old-build","status":"completed"}]}`
	case "/repos/example-owner/example-repo/actions/jobs/4000":
		body = `{"id":4000,"run_id":400,"run_attempt":1,"name":"old-build","status":"completed","steps":[{"number":1}]}`
	case "/repos/example-owner/example-repo/actions/jobs/5001":
		body = `{"id":5001,"run_id":500,"name":"release","status":"completed"}`
	case "/repos/example-owner/example-repo/actions/jobs/5002":
		body = `{"id":5002,"run_id":500,"name":"absent","status":"completed"}`
	case "/repos/example-owner/example-repo/actions/runs/400/attempts/2/jobs":
		if req.URL.Query().Get("page") == "2" {
			body = `{"total_count":2,"jobs":[{"id":4002,"run_id":400,"run_attempt":2,"name":"test","status":"completed"}]}`
		} else {
			body = `{"total_count":2,"jobs":[{"id":4001,"run_id":400,"run_attempt":2,"name":"build","status":"completed"}]}`
			header.Set("Link", `<https://api.example.invalid/repos/example-owner/example-repo/actions/runs/400/attempts/2/jobs?page=2&per_page=100>; rel="next"`)
		}
	case "/repos/example-owner/example-repo/actions/runs/500/attempts/1/jobs":
		body = `{"total_count":1,"jobs":[{"id":5001,"run_id":500,"name":"release","status":"completed"}]}`
	case "/repos/example-owner/example-repo/actions/runs/400/attempts/1/logs":
		status = f.archiveStatus
		if status == 0 {
			status = http.StatusFound
			header.Set("Location", f.storageURL+"/archive?signature=synthetic-value")
		}
	case "/repos/example-owner/example-repo/actions/jobs/4000/logs",
		"/repos/example-owner/example-repo/actions/jobs/4000/steps/1/logs",
		"/repos/example-owner/example-repo/actions/jobs/4001/logs",
		"/repos/example-owner/example-repo/actions/jobs/4002/logs",
		"/repos/example-owner/example-repo/actions/jobs/5001/logs":
		if f.logFailure != nil {
			return nil, f.logFailure
		}
		status = f.logStatus[req.URL.Path]
		if status == 0 {
			status = http.StatusFound
			path := "/log"
			if strings.Contains(req.URL.Path, "/steps/") {
				path = "/step"
			}
			header.Set("Location", f.storageURL+path+"?signature=synthetic-value")
		}
	default:
		return nil, fmt.Errorf("unexpected API request: %s", req.URL.Path)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func TestActionsAPIStepFallbackAndIsolatedStorage(t *testing.T) {
	log := "\xef\xbb\xbf2026-01-02T03:04:05Z ordinary\n2026-01-02T03:04:05Z fixture-token-abcdefghij\n"
	step := "\xef\xbb\xbf2026-01-02T03:04:06Z ordinary\n2026-01-02T03:04:06Z fixture-token-abcdefghij\n"
	archive := makeActionsArchive(t,
		actionsArchiveFixture{"0_old-build.txt", log},
		actionsArchiveFixture{"old-build/system.txt", "system data\n"},
	)
	var mu sync.Mutex
	var storageRequests []string
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		storageRequests = append(storageRequests, req.URL.Path+"|"+req.Header.Get("Authorization")+"|"+req.Header.Get("Referer"))
		mu.Unlock()
		switch req.URL.Path {
		case "/log":
			writeActionsResponse(t, w, log)
		case "/archive":
			writeActionsResponse(t, w, string(archive))
		case "/step":
			http.Redirect(w, req, "/step-body?signature=synthetic-value", http.StatusFound)
		case "/step-body":
			writeActionsResponse(t, w, step)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer storage.Close()
	transport := &actionsFixtureTransport{storageURL: storage.URL}
	api := fixtureActionsAPI(t, transport, storage.Client())
	opts := urlActionsOptions(t, fakeActionsURL+"400/job/4000")
	opts.LocationURL = true
	result, err := scanActions(t.Context(), api, fakeActionsRepository(), opts, fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || len(result.Findings) != 1 || len(result.Warnings) != 0 ||
		!strings.HasSuffix(result.Findings[0].LocationURL, "#step:1:2") || result.Findings[0].StartLine != 2 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	wantLast := "/repos/example-owner/example-repo/actions/jobs/4000/steps/1/logs"
	if transport.requests[len(transport.requests)-1] != wantLast {
		t.Fatalf("incorrect step endpoint: %v", transport.requests)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(storageRequests, []string{"/log||", "/archive||", "/step||", "/step-body||"}) {
		t.Fatalf("unexpected requests or leaked headers: %v", storageRequests)
	}
}

func TestActionsAPIStepErrorsAndDownloadLimit(t *testing.T) {
	const path = "/repos/example-owner/example-repo/actions/jobs/4000/steps/1/logs"
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		writeActionsResponse(t, w, strings.Repeat("x", 32))
	}))
	defer storage.Close()
	for _, status := range []int{404, 410, 401, 403, 429, 500, 0} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			transport := &actionsFixtureTransport{storageURL: storage.URL, logStatus: map[string]int{path: status}}
			api := fixtureActionsAPI(t, transport, storage.Client())
			_, err := api.getStepLog(t.Context(), 4000, 1, 16)
			if err == nil || strings.Contains(err.Error(), "signature") || strings.Contains(err.Error(), storage.URL) {
				t.Fatalf("missing or unsafe error: %v", err)
			}
			if status == 0 {
				if !strings.Contains(err.Error(), "16-byte limit") {
					t.Fatalf("limit not enforced: %v", err)
				}
			} else if !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status)) {
				t.Fatalf("status lost: %v", err)
			}
		})
	}
}

func TestActionsAPILocationUsesExactAttemptAndIsolatedStorage(t *testing.T) {
	log := "fixture-token-abcdefghij\n"
	archive := makeActionsArchive(t,
		actionsArchiveFixture{"0_old-build.txt", log},
		actionsArchiveFixture{"old-build/1_step.txt", log},
		actionsArchiveFixture{"1_Unselected.txt", "fixture-token-zzzzzzzzzz\n"},
	)
	var mu sync.Mutex
	var storageRequests []string
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		storageRequests = append(storageRequests, req.URL.Path+"|"+req.Header.Get("Authorization")+"|"+req.Header.Get("Referer"))
		mu.Unlock()
		switch req.URL.Path {
		case "/log":
			writeActionsResponse(t, w, log)
		case "/archive":
			writeActionsResponse(t, w, string(archive))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer storage.Close()
	transport := &actionsFixtureTransport{storageURL: storage.URL}
	api := fixtureActionsAPI(t, transport, storage.Client())
	opts := urlActionsOptions(t, fakeActionsURL+"400/job/4000")
	opts.LocationURL = true
	result, err := scanActions(t.Context(), api, fakeActionsRepository(), opts, fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || len(result.Findings) != 1 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	want := "https://github.com/example-owner/example-repo/actions/runs/400/job/4000#step:1:1"
	if result.Findings[0].LocationURL != want {
		t.Fatalf("location URL = %q, want %q", result.Findings[0].LocationURL, want)
	}
	wantRequests := []string{
		"/repos/example-owner/example-repo/actions/runs/400",
		"/repos/example-owner/example-repo/actions/jobs/4000",
		"/repos/example-owner/example-repo/actions/runs/400/attempts/1",
		"/repos/example-owner/example-repo/actions/jobs/4000/logs",
		"/repos/example-owner/example-repo/actions/runs/400/attempts/1/logs",
	}
	if !reflect.DeepEqual(transport.requests, wantRequests) {
		t.Fatalf("API requests = %v, want %v", transport.requests, wantRequests)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(storageRequests, []string{"/log||", "/archive||"}) {
		t.Fatalf("storage received credentials or unexpected requests: %v", storageRequests)
	}
}

func TestActionsAPIExactAttemptAndJobURLs(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		requests []string
		wantJob  int64
		wantErr  string
	}{
		{
			name:     "specific attempt",
			selector: fakeActionsURL + "400/attempts/1",
			wantJob:  4000,
			requests: []string{
				"/repos/example-owner/example-repo/actions/runs/400",
				"/repos/example-owner/example-repo/actions/runs/400/attempts/1",
				"/repos/example-owner/example-repo/actions/runs/400/attempts/1/jobs?per_page=100",
				"/repos/example-owner/example-repo/actions/jobs/4000/logs",
			},
		},
		{
			name:     "specific older job",
			selector: fakeActionsURL + "400/job/4000",
			wantJob:  4000,
			requests: []string{
				"/repos/example-owner/example-repo/actions/runs/400",
				"/repos/example-owner/example-repo/actions/jobs/4000",
				"/repos/example-owner/example-repo/actions/runs/400/attempts/1",
				"/repos/example-owner/example-repo/actions/jobs/4000/logs",
			},
		},
		{
			name:     "job missing attempt metadata",
			selector: fakeActionsURL + "500/job/5001",
			wantJob:  5001,
			requests: []string{
				"/repos/example-owner/example-repo/actions/runs/500",
				"/repos/example-owner/example-repo/actions/jobs/5001",
				"/repos/example-owner/example-repo/actions/runs/500/attempts/1/jobs?per_page=100",
				"/repos/example-owner/example-repo/actions/jobs/5001/logs",
			},
		},
		{
			name:     "unlisted job missing attempt metadata",
			selector: fakeActionsURL + "500/job/5002",
			wantErr:  "could not determine the attempt",
			requests: []string{
				"/repos/example-owner/example-repo/actions/runs/500",
				"/repos/example-owner/example-repo/actions/jobs/5002",
				"/repos/example-owner/example-repo/actions/runs/500/attempts/1/jobs?per_page=100",
			},
		},
		{
			name:     "unlisted job missing explicit attempt metadata",
			selector: fakeActionsURL + "500/attempts/1/job/5002",
			wantErr:  "does not belong to the attempt",
			requests: []string{
				"/repos/example-owner/example-repo/actions/runs/500",
				"/repos/example-owner/example-repo/actions/jobs/5002",
				"/repos/example-owner/example-repo/actions/runs/500/attempts/1/jobs?per_page=100",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeActionsResponse(t, w, "fixture-token-abcdefghij\n")
			}))
			defer storage.Close()
			transport := &actionsFixtureTransport{storageURL: storage.URL}
			api := fixtureActionsAPI(t, transport, storage.Client())
			result, err := scanActions(t.Context(), api, fakeActionsRepository(), urlActionsOptions(t, tt.selector), fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || len(result.Findings) != 0 {
					t.Fatalf("result = %+v, err = %v, want %q", result, err, tt.wantErr)
				}
			} else if err != nil || len(result.Findings) != 1 || result.Findings[0].RunAttempt != 1 || result.Findings[0].JobID != tt.wantJob {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
			if !reflect.DeepEqual(transport.requests, tt.requests) {
				t.Fatalf("requests = %v, want %v", transport.requests, tt.requests)
			}
		})
	}
}

func fixtureActionsAPI(t *testing.T, transport *actionsFixtureTransport, downloadClient *http.Client) *githubActionsAPI {
	t.Helper()
	base := "https://api.example.invalid/"
	githubClient, err := github.NewClient(
		github.WithHTTPClient(&http.Client{Transport: transport}),
		github.WithURLs(&base, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := client.NewClient(githubClient)
	if err != nil {
		t.Fatal(err)
	}
	return &githubActionsAPI{
		client:     wrapped,
		repo:       repository.Repository{Owner: "example-owner", Name: "example-repo"},
		httpClient: downloadClient,
	}
}

func TestActionsAPIDefaultWorkflowTraversal(t *testing.T) {
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeActionsResponse(t, w, "fixture-token-abcdefghij\n")
	}))
	defer storage.Close()
	transport := &actionsFixtureTransport{storageURL: storage.URL}
	api := fixtureActionsAPI(t, transport, storage.Client())
	result, err := scanActions(t.Context(), api, fakeActionsRepository(), testActionsOptions(), fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || len(result.Findings) != 3 || result.Summary.Scanned != 3 || result.Summary.Workflows != 2 || result.Summary.Runs != 2 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	var jobLogRequests []string
	for _, request := range transport.requests {
		if strings.Contains(request, "/actions/jobs/") && strings.HasSuffix(request, "/logs") {
			jobLogRequests = append(jobLogRequests, request)
		}
	}
	want := []string{
		"/repos/example-owner/example-repo/actions/jobs/4001/logs",
		"/repos/example-owner/example-repo/actions/jobs/5001/logs",
		"/repos/example-owner/example-repo/actions/jobs/4002/logs",
	}
	if !reflect.DeepEqual(jobLogRequests, want) {
		t.Fatalf("job log order = %v, want %v; requests = %v", jobLogRequests, want, transport.requests)
	}
	if indexOfCall(transport.requests, "/repos/example-owner/example-repo/actions/workflows?page=2&per_page=100") < 0 {
		t.Fatalf("workflow pagination not followed: %v", transport.requests)
	}
}

func TestActionsAPIExplicitRunPaginationAndStorageAuthentication(t *testing.T) {
	var mu sync.Mutex
	var storageAuth []string
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		storageAuth = append(storageAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		writeActionsResponse(t, w, "fixture-token-abcdefghij\n")
	}))
	defer storage.Close()
	transport := &actionsFixtureTransport{storageURL: storage.URL}
	api := fixtureActionsAPI(t, transport, storage.Client())
	opts := testActionsOptions()
	opts.Runs = []int64{400}
	result, err := scanActions(t.Context(), api, fakeActionsRepository(), opts, fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || len(result.Findings) != 2 || result.Summary.Scanned != 2 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	want := []string{
		"/repos/example-owner/example-repo/actions/runs/400",
		"/repos/example-owner/example-repo/actions/runs/400/attempts/2/jobs?per_page=100",
		"/repos/example-owner/example-repo/actions/runs/400/attempts/2/jobs?page=2&per_page=100",
		"/repos/example-owner/example-repo/actions/jobs/4001/logs",
		"/repos/example-owner/example-repo/actions/jobs/4002/logs",
	}
	if !reflect.DeepEqual(transport.requests, want) {
		t.Fatalf("API requests = %v, want %v", transport.requests, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(storageAuth, []string{"", ""}) {
		t.Fatalf("GitHub authentication was sent to storage: %v", storageAuth)
	}
}

func TestActionsAPILogStatusIsPreserved(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusGone, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			path := "/repos/example-owner/example-repo/actions/jobs/4001/logs"
			transport := &actionsFixtureTransport{logStatus: map[string]int{path: status}}
			api := fixtureActionsAPI(t, transport, &http.Client{})
			_, err := api.getLog(t.Context(), 4001)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status)) {
				t.Fatalf("got %v, want status %d", err, status)
			}
			if actionsLogUnavailable(err) != (status == http.StatusNotFound || status == http.StatusGone) {
				t.Fatalf("incorrect availability classification: %v", err)
			}
		})
	}
}

func TestActionsAPILogNetworkErrorIsSanitized(t *testing.T) {
	transport := &actionsFixtureTransport{logFailure: fmt.Errorf("synthetic-sensitive-error")}
	api := fixtureActionsAPI(t, transport, &http.Client{})
	_, err := api.getLog(t.Context(), 4001)
	if err == nil || !strings.Contains(err.Error(), "requesting the GitHub job log") || strings.Contains(err.Error(), "synthetic-sensitive-error") {
		t.Fatalf("unsanitized API error: %v", err)
	}
}
