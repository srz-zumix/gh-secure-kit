package localscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v93/github"
)

type flakyActionsAPI struct {
	*fakeActionsAPI
	failures []error
	calls    int
}

func (a *flakyActionsAPI) listJobs(ctx context.Context, runID, attempt int64) ([]*github.WorkflowJob, error) {
	a.calls++
	if a.calls <= len(a.failures) {
		return nil, a.failures[a.calls-1]
	}
	return a.fakeActionsAPI.listJobs(ctx, runID, attempt)
}

func githubStatusError(status int, retryAfter string) error {
	header := http.Header{}
	if retryAfter != "" {
		header.Set("Retry-After", retryAfter)
	}
	return &github.ErrorResponse{Response: &http.Response{StatusCode: status, Header: header}, Message: "fixture"}
}

func newTestRetryingAPI(api actionsAPI, delays *[]time.Duration) *retryingActionsAPI {
	retrying := newRetryingActionsAPI(api, nil)
	retrying.jitter = nil
	retrying.wait = func(_ context.Context, delay time.Duration) error {
		*delays = append(*delays, delay)
		return nil
	}
	return retrying
}

func TestActionsRetryPolicy(t *testing.T) {
	for _, tt := range []struct {
		name       string
		failures   []error
		wantCalls  int
		wantDelays []time.Duration
		wantErr    bool
	}{
		{"502 then success", []error{githubStatusError(502, "")}, 2, []time.Duration{2 * time.Second}, false},
		{"gateway errors exhaust retries", []error{githubStatusError(502, ""), githubStatusError(503, ""), githubStatusError(504, ""), githubStatusError(502, "")}, 4,
			[]time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}, true},
		{"500 retried once", []error{githubStatusError(500, ""), githubStatusError(500, "")}, 2, []time.Duration{2 * time.Second}, true},
		{"Retry-After honored", []error{githubStatusError(503, "7")}, 2, []time.Duration{7 * time.Second}, false},
		{"long Retry-After gives up", []error{githubStatusError(503, "120")}, 1, nil, true},
		{"404 not retried", []error{githubStatusError(404, "")}, 1, nil, true},
		{"403 not retried", []error{githubStatusError(403, "")}, 1, nil, true},
		{"log network error retried", []error{&actionsLogError{stage: "job log", cause: errors.New("fixture"), transient: true}}, 2, []time.Duration{2 * time.Second}, false},
		{"log download 502 retried", []error{&actionsLogError{stage: "job log", status: 502}}, 2, []time.Duration{2 * time.Second}, false},
		{"other error not retried", []error{errors.New("fixture")}, 1, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeActionsAPI()
			fake.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{fakeActionsJob(1001, 100, 1, "completed", "one")}
			flaky := &flakyActionsAPI{fakeActionsAPI: fake, failures: tt.failures}
			var delays []time.Duration
			_, err := newTestRetryingAPI(flaky, &delays).listJobs(t.Context(), 100, 1)
			if (err != nil) != tt.wantErr || flaky.calls != tt.wantCalls || fmt.Sprint(delays) != fmt.Sprint(tt.wantDelays) {
				t.Fatalf("err %v, calls %d, delays %v", err, flaky.calls, delays)
			}
		})
	}
}

func TestActionsRetryStopsOnCancellation(t *testing.T) {
	fake := newFakeActionsAPI()
	flaky := &flakyActionsAPI{fakeActionsAPI: fake, failures: []error{githubStatusError(502, ""), githubStatusError(502, "")}}
	retrying := newRetryingActionsAPI(flaky, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := retrying.listJobs(ctx, 100, 1)
	if flaky.calls != 1 || err == nil {
		t.Fatalf("err %v, calls %d", err, flaky.calls)
	}
}

func TestActionsScanRetriesTransientJobListing(t *testing.T) {
	fake := newFakeActionsAPI()
	fake.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	fake.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{fakeActionsJob(1001, 100, 1, "completed", "one")}
	fake.logs[1001] = "fixture-token-abcdefghij"
	flaky := &flakyActionsAPI{fakeActionsAPI: fake, failures: []error{githubStatusError(502, "")}}
	var delays []time.Duration
	opts := testActionsOptions()
	opts.Runs = []int64{100}
	result, err := scanActions(t.Context(), newTestRetryingAPI(flaky, &delays), fakeActionsRepository(), opts,
		fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || len(result.Findings) != 1 || len(delays) != 1 {
		t.Fatalf("result %+v, err %v, delays %v", result, err, delays)
	}
}

func TestActionsSummaryReportsFailedRunsAndWorkflows(t *testing.T) {
	var out bytes.Buffer
	err := RenderActionsSummary(&out, ActionsScanResult{Summary: ActionsScanSummary{Failed: 2, FailedRuns: 1, FailedWorkflows: 3}})
	if err != nil || !strings.Contains(out.String(), "2 failed jobs, 1 failed run, 3 failed workflows") {
		t.Fatalf("summary %q, err %v", out.String(), err)
	}
}
