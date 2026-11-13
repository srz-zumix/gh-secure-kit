package localscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v93/github"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type actionsAttemptKey struct {
	run, attempt int64
}

type fakeActionsAPI struct {
	workflows     []*github.Workflow
	runs          map[int64]*github.WorkflowRun
	runAttempts   map[actionsAttemptKey]*github.WorkflowRun
	history       map[int64][]*github.WorkflowRun
	runErrors     map[int64]error
	jobs          map[int64]*github.WorkflowJob
	attempts      map[actionsAttemptKey][]*github.WorkflowJob
	jobErrors     map[actionsAttemptKey]error
	logs          map[int64]string
	logErrors     map[int64]error
	beforeLog     func(int64)
	archives      map[actionsAttemptKey][]byte
	archiveErrors map[actionsAttemptKey]error
	stepLogs      map[[2]int64]string
	stepErrors    map[[2]int64]error
	calls         []string
	logIDs        []int64
}

func newFakeActionsAPI() *fakeActionsAPI {
	return &fakeActionsAPI{
		runs:          make(map[int64]*github.WorkflowRun),
		runAttempts:   make(map[actionsAttemptKey]*github.WorkflowRun),
		history:       make(map[int64][]*github.WorkflowRun),
		runErrors:     make(map[int64]error),
		jobs:          make(map[int64]*github.WorkflowJob),
		attempts:      make(map[actionsAttemptKey][]*github.WorkflowJob),
		jobErrors:     make(map[actionsAttemptKey]error),
		logs:          make(map[int64]string),
		logErrors:     make(map[int64]error),
		archives:      make(map[actionsAttemptKey][]byte),
		archiveErrors: make(map[actionsAttemptKey]error),
		stepLogs:      make(map[[2]int64]string),
		stepErrors:    make(map[[2]int64]error),
	}
}

func (a *fakeActionsAPI) listWorkflows(context.Context) ([]*github.Workflow, error) {
	a.calls = append(a.calls, "workflows")
	return a.workflows, nil
}

func (a *fakeActionsAPI) listRuns(_ context.Context, workflowID int64, limit int) ([]*github.WorkflowRun, error) {
	a.calls = append(a.calls, fmt.Sprintf("runs:%d:%d", workflowID, limit))
	if err := a.runErrors[workflowID]; err != nil {
		return nil, err
	}
	return a.history[workflowID], nil
}

func (a *fakeActionsAPI) getRun(_ context.Context, id int64) (*github.WorkflowRun, error) {
	a.calls = append(a.calls, fmt.Sprintf("run:%d", id))
	run := a.runs[id]
	if run == nil {
		return nil, fmt.Errorf("run not found")
	}
	return run, nil
}

func (a *fakeActionsAPI) getRunAttempt(_ context.Context, id, attempt int64) (*github.WorkflowRun, error) {
	a.calls = append(a.calls, fmt.Sprintf("attempt:%d:%d", id, attempt))
	run := a.runAttempts[actionsAttemptKey{id, attempt}]
	if run == nil {
		return nil, fmt.Errorf("run attempt not found")
	}
	return run, nil
}

func (a *fakeActionsAPI) listJobs(_ context.Context, runID, attempt int64) ([]*github.WorkflowJob, error) {
	a.calls = append(a.calls, fmt.Sprintf("jobs:%d:%d", runID, attempt))
	if err := a.jobErrors[actionsAttemptKey{runID, attempt}]; err != nil {
		return nil, err
	}
	return a.attempts[actionsAttemptKey{runID, attempt}], nil
}

func (a *fakeActionsAPI) getJob(_ context.Context, id int64) (*github.WorkflowJob, error) {
	a.calls = append(a.calls, fmt.Sprintf("job:%d", id))
	job := a.jobs[id]
	if job == nil {
		return nil, fmt.Errorf("job not found")
	}
	return job, nil
}

func (a *fakeActionsAPI) getLog(_ context.Context, id int64) ([]byte, error) {
	a.calls = append(a.calls, fmt.Sprintf("log:%d", id))
	a.logIDs = append(a.logIDs, id)
	if a.beforeLog != nil {
		a.beforeLog(id)
	}
	if err := a.logErrors[id]; err != nil {
		return nil, err
	}
	log, ok := a.logs[id]
	if !ok {
		return nil, fmt.Errorf("unexpected job log request")
	}
	return []byte(log), nil
}

func (a *fakeActionsAPI) getRunLogArchive(ctx context.Context, runID, attempt int64) ([]byte, error) {
	a.calls = append(a.calls, fmt.Sprintf("archive:%d:%d", runID, attempt))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := actionsAttemptKey{runID, attempt}
	if err := a.archiveErrors[key]; err != nil {
		return nil, err
	}
	archive, ok := a.archives[key]
	if !ok {
		return nil, fmt.Errorf("unexpected run log archive request")
	}
	return archive, nil
}

func fakeActionsRepository() repository.Repository {
	return repository.Repository{Host: "github.com", Owner: "example-owner", Name: "example-repo"}
}

func (a *fakeActionsAPI) getStepLog(ctx context.Context, jobID, number, limit int64) ([]byte, error) {
	a.calls = append(a.calls, fmt.Sprintf("step:%d:%d", jobID, number))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := [2]int64{jobID, number}
	if err := a.stepErrors[key]; err != nil {
		return nil, err
	}
	log, ok := a.stepLogs[key]
	if !ok {
		return nil, &actionsLogError{stage: "requesting the GitHub step log", status: http.StatusNotFound}
	}
	if int64(len(log)) > limit {
		return nil, fmt.Errorf("step log exceeds download limit")
	}
	return []byte(log), nil
}

func fakeActionsRun(id, workflowID int64, attempt int, status, name, workflowPath string) *github.WorkflowRun {
	return &github.WorkflowRun{
		ID: github.Ptr(id), WorkflowID: github.Ptr(workflowID), RunAttempt: github.Ptr(attempt),
		Status: github.Ptr(status), Name: github.Ptr(name), Path: github.Ptr(workflowPath),
		HeadSHA: github.Ptr(strings.Repeat("1", 40)),
	}
}

func fakeActionsJob(id, runID, attempt int64, status, name string) *github.WorkflowJob {
	return &github.WorkflowJob{
		ID: github.Ptr(id), RunID: github.Ptr(runID), RunAttempt: github.Ptr(attempt),
		Status: github.Ptr(status), Name: github.Ptr(name),
		HTMLURL: github.Ptr(fmt.Sprintf("https://example.invalid/runs/%d/jobs/%d", runID, id)),
	}
}

func fakeActionsScanner(t *testing.T, showSecret bool) *Scanner {
	t.Helper()
	scanner, err := NewScanner(&Config{
		Patterns: []ConfigPattern{{ID: "fixture_token", Regex: `fixture-token-[a-z0-9]{10}`}},
	}, showSecret)
	if err != nil {
		t.Fatal(err)
	}
	return scanner
}

func fakeScanActions(t *testing.T, api *fakeActionsAPI, opts ActionsScanOptions) (ActionsScanResult, error) {
	t.Helper()
	return scanActions(t.Context(), api, fakeActionsRepository(), opts, fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
}

func TestActionsScanRotatesWorkflowsBeforeOlderRuns(t *testing.T) {
	api := newFakeActionsAPI()
	api.workflows = []*github.Workflow{
		{ID: github.Ptr(int64(1)), Name: github.Ptr("Build"), Path: github.Ptr(".github/workflows/build.yml")},
		{ID: github.Ptr(int64(2)), Name: github.Ptr("Release"), Path: github.Ptr(".github/workflows/release.yml")},
	}
	first := fakeActionsRun(110, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	firstOld := fakeActionsRun(111, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	second := fakeActionsRun(210, 2, 1, "completed", "Release", ".github/workflows/release.yml")
	secondOld := fakeActionsRun(211, 2, 1, "completed", "Release", ".github/workflows/release.yml")
	api.history[1] = []*github.WorkflowRun{first, firstOld}
	api.history[2] = []*github.WorkflowRun{second, secondOld}
	api.attempts[actionsAttemptKey{110, 1}] = []*github.WorkflowJob{
		fakeActionsJob(1101, 110, 1, "completed", "a"),
		fakeActionsJob(1102, 110, 1, "completed", "b"),
		fakeActionsJob(1103, 110, 1, "completed", "c"),
	}
	api.attempts[actionsAttemptKey{210, 1}] = []*github.WorkflowJob{fakeActionsJob(2101, 210, 1, "completed", "d")}
	api.attempts[actionsAttemptKey{111, 1}] = []*github.WorkflowJob{fakeActionsJob(1111, 111, 1, "completed", "e")}
	api.attempts[actionsAttemptKey{211, 1}] = []*github.WorkflowJob{fakeActionsJob(2111, 211, 1, "completed", "f")}
	for _, id := range []int64{1101, 1102, 1103, 2101, 1111, 2111} {
		api.logs[id] = "fixture-token-abcdefghij\nfixture-token-abcdefghij\n"
	}
	opts := testActionsOptions()
	opts.RunsPerWorkflow = 2
	result, err := fakeScanActions(t, api, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []int64{1101, 2101, 1102, 1103, 1111, 2111}
	if !reflect.DeepEqual(api.logIDs, want) {
		t.Fatalf("log order = %v, want %v; calls: %v", api.logIDs, want, api.calls)
	}
	if result.Summary.Scanned != len(want) || result.Summary.Runs != 4 || len(result.Findings) != len(want) {
		t.Fatalf("unexpected coverage or deduplication: %+v, %d findings", result.Summary, len(result.Findings))
	}
	firstLog := indexOfCall(api.calls, "log:1101")
	olderJobs := indexOfCall(api.calls, "jobs:111:1")
	lastCurrentLog := indexOfCall(api.calls, "log:1103")
	if firstLog < 0 || olderJobs <= lastCurrentLog {
		t.Fatalf("older jobs were listed before current jobs were scanned: %v", api.calls)
	}
}

func indexOfCall(calls []string, want string) int {
	for i, call := range calls {
		if call == want {
			return i
		}
	}
	return -1
}

func TestActionsScanExplicitRunsAndSelectors(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 2, "completed", "Build", ".github/workflows/build.yml")
	api.runs[200] = fakeActionsRun(200, 2, 1, "completed", "Release", ".github/workflows/release.yml")
	api.jobs[1001] = fakeActionsJob(1001, 100, 1, "completed", "old build")
	api.attempts[actionsAttemptKey{100, 2}] = []*github.WorkflowJob{
		fakeActionsJob(1002, 100, 2, "completed", "build"),
		fakeActionsJob(1003, 100, 2, "completed", "other"),
	}
	api.logs[1001] = "fixture-token-abcdefghij"
	api.logs[1002] = "fixture-token-klmnopqrst"
	opts := testActionsOptions()
	opts.Runs = []int64{100, 100, 200}
	opts.Workflows = []string{"build.yml"}
	opts.Jobs = []string{"1001", "build"}
	result, err := fakeScanActions(t, api, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(api.logIDs, []int64{1001, 1002}) {
		t.Fatalf("scanned unexpected logs: %v", api.logIDs)
	}
	if len(result.Findings) != 2 || result.Findings[0].RunAttempt != 1 || result.Findings[1].RunAttempt != 2 {
		t.Fatalf("incorrect attempt attribution: %+v", result.Findings)
	}
	if result.Summary.Runs != 1 || result.Summary.Filtered != 1 {
		t.Fatalf("incorrect filtered coverage: %+v", result.Summary)
	}
	for _, forbidden := range []string{"workflows", "runs:1:1", "jobs:200:1", "jobs:100:1"} {
		if indexOfCall(api.calls, forbidden) >= 0 {
			t.Fatalf("unexpected request %q: %v", forbidden, api.calls)
		}
	}
	if indexOfCall(api.calls, "jobs:100:2") < 0 || indexOfCall(api.calls, "run:200") < 0 {
		t.Fatalf("missing explicit run or pinned attempt request: %v", api.calls)
	}
}

func TestActionsScanDirectJobAndRunIsolation(t *testing.T) {
	t.Run("direct job bypasses history", func(t *testing.T) {
		api := newFakeActionsAPI()
		api.runs[100] = fakeActionsRun(100, 1, 4, "completed", "Build", ".github/workflows/build.yml")
		api.jobs[1001] = fakeActionsJob(1001, 100, 1, "completed", "build")
		api.logs[1001] = "fixture-token-abcdefghij"
		opts := testActionsOptions()
		opts.Jobs = []string{"1001", "1001"}
		result, err := fakeScanActions(t, api, opts)
		if err != nil || len(result.Findings) != 1 || result.Findings[0].RunAttempt != 1 {
			t.Fatalf("result = %+v, err = %v", result, err)
		}
		if !reflect.DeepEqual(api.calls, []string{"job:1001", "run:100", "log:1001"}) {
			t.Fatalf("direct job made unrelated requests: %v", api.calls)
		}
	})
	t.Run("job outside explicit run is rejected before fetching logs", func(t *testing.T) {
		api := newFakeActionsAPI()
		api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
		api.jobs[2001] = fakeActionsJob(2001, 200, 1, "completed", "build")
		opts := testActionsOptions()
		opts.Runs, opts.Jobs = []int64{100}, []string{"2001"}
		_, err := fakeScanActions(t, api, opts)
		if err == nil || !strings.Contains(err.Error(), "does not belong") || len(api.logIDs) != 0 {
			t.Fatalf("result error = %v, log IDs = %v", err, api.logIDs)
		}
		if indexOfCall(api.calls, "run:200") >= 0 {
			t.Fatalf("unexpected lookup of an unselected run: %v", api.calls)
		}
	})
	t.Run("invalid combinations make no API calls", func(t *testing.T) {
		api := newFakeActionsAPI()
		opts := testActionsOptions()
		opts.Runs, opts.RunsPerWorkflowSet = []int64{100}, true
		_, err := fakeScanActions(t, api, opts)
		if err == nil || len(api.calls) != 0 {
			t.Fatalf("got error %v and calls %v", err, api.calls)
		}
	})
}

func TestActionsDirectJobWithoutAttemptMetadata(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 3, "completed", "Build", ".github/workflows/build.yml")
	old := fakeActionsJob(1001, 100, 1, "completed", "build")
	old.RunAttempt = nil
	api.jobs[1001] = old
	api.attempts[actionsAttemptKey{100, 3}] = []*github.WorkflowJob{fakeActionsJob(1003, 100, 3, "completed", "test")}
	api.attempts[actionsAttemptKey{100, 2}] = []*github.WorkflowJob{fakeActionsJob(1002, 100, 2, "completed", "test")}
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{old}
	api.logs[1001] = "fixture-token-abcdefghij"
	opts := testActionsOptions()
	opts.Jobs = []string{"1001"}
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 1 || result.Findings[0].RunAttempt != 1 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	if !reflect.DeepEqual(api.calls, []string{"job:1001", "run:100", "jobs:100:3", "jobs:100:2", "jobs:100:1", "log:1001"}) {
		t.Fatalf("unexpected attempt lookup: %v", api.calls)
	}
}

func TestActionsScanIncompleteRun(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 2, "in_progress", "Build", ".github/workflows/build.yml")
	finished := fakeActionsJob(1001, 100, 2, "completed", "build")
	running := fakeActionsJob(1002, 100, 2, "in_progress", "scan")
	queued := fakeActionsJob(1003, 100, 2, "queued", "test")
	skipped := fakeActionsJob(1004, 100, 2, "completed", "skipped")
	skipped.Conclusion = github.Ptr("skipped")
	api.attempts[actionsAttemptKey{100, 2}] = []*github.WorkflowJob{finished, running, queued, skipped}
	api.logs[1001] = "fixture-token-abcdefghij"
	opts := testActionsOptions()
	opts.Runs = []int64{100}
	if _, err := fakeScanActions(t, api, opts); err == nil || len(api.logIDs) != 0 {
		t.Fatalf("unfinished run was accepted without the flag: %v, %v", err, api.logIDs)
	}
	api.calls = nil
	opts.AllowInProgress = true
	result, err := fakeScanActions(t, api, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(api.logIDs, []int64{1001}) || result.Summary.Scanned != 1 ||
		result.Summary.Incomplete != 2 || result.Summary.Skipped != 1 || result.Summary.IncompleteRuns != 1 {
		t.Fatalf("incorrect incomplete-run coverage: %+v, logs %v", result.Summary, api.logIDs)
	}
	if len(result.Warnings) != 3 {
		t.Fatalf("warnings = %v", result.Warnings)
	}
	api.attempts[actionsAttemptKey{100, 2}] = nil
	api.logIDs = nil
	result, err = fakeScanActions(t, api, opts)
	if err != nil || result.Summary.Scanned != 0 || result.Summary.IncompleteRuns != 1 || len(result.Warnings) == 0 {
		t.Fatalf("empty incomplete run appeared fully scanned: %+v, %v", result, err)
	}
}

func TestActionsSelectorsAndPartialFindings(t *testing.T) {
	t.Run("ambiguous workflow names", func(t *testing.T) {
		api := newFakeActionsAPI()
		api.workflows = []*github.Workflow{
			{ID: github.Ptr(int64(1)), Name: github.Ptr("Build"), Path: github.Ptr(".github/workflows/one.yml")},
			{ID: github.Ptr(int64(2)), Name: github.Ptr("build"), Path: github.Ptr(".github/workflows/two.yml")},
		}
		opts := testActionsOptions()
		opts.Workflows = []string{"Build"}
		_, err := fakeScanActions(t, api, opts)
		if err == nil || !strings.Contains(err.Error(), "ambiguous") || len(api.logIDs) != 0 {
			t.Fatalf("ambiguous selector: %v, logs %v", err, api.logIDs)
		}
	})
	t.Run("later metadata failure returns prior findings", func(t *testing.T) {
		api := newFakeActionsAPI()
		api.workflows = []*github.Workflow{
			{ID: github.Ptr(int64(1)), Name: github.Ptr("Build")},
			{ID: github.Ptr(int64(2)), Name: github.Ptr("Release")},
		}
		api.history[1] = []*github.WorkflowRun{fakeActionsRun(100, 1, 1, "completed", "Build", "")}
		api.history[2] = []*github.WorkflowRun{fakeActionsRun(200, 2, 1, "completed", "Release", "")}
		api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{fakeActionsJob(1001, 100, 1, "completed", "build")}
		api.jobErrors[actionsAttemptKey{200, 1}] = errors.New("synthetic API failure")
		api.logs[1001] = "fixture-token-abcdefghij"
		result, err := fakeScanActions(t, api, testActionsOptions())
		if err == nil || !strings.Contains(err.Error(), "synthetic API failure") || result.Summary.Scanned != 1 || len(result.Findings) != 1 {
			t.Fatalf("result = %+v, err = %v", result, err)
		}
	})
	t.Run("missing job returns prior findings", func(t *testing.T) {
		api := newFakeActionsAPI()
		api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
		api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{fakeActionsJob(1001, 100, 1, "completed", "build")}
		api.logs[1001] = "fixture-token-abcdefghij"
		opts := testActionsOptions()
		opts.Runs, opts.Jobs = []int64{100}, []string{"build", "missing"}
		result, err := fakeScanActions(t, api, opts)
		if err == nil || !strings.Contains(err.Error(), "missing") || len(result.Findings) != 1 {
			t.Fatalf("result = %+v, err = %v", result, err)
		}
	})
	t.Run("unknown selector is redacted", func(t *testing.T) {
		api := newFakeActionsAPI()
		opts := testActionsOptions()
		secret := "fixture-token-abcdefghij"
		opts.Workflows = []string{secret}
		_, err := fakeScanActions(t, api, opts)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("selector error leaked secret: %v", err)
		}
	})
}

func TestActionsUnavailableAndFatalLogErrors(t *testing.T) {
	for _, tt := range []struct {
		status      int
		unavailable bool
		recoverable bool
	}{
		{http.StatusNotFound, true, false},
		{http.StatusGone, true, false},
		{http.StatusUnauthorized, false, false},
		{http.StatusForbidden, false, false},
		{http.StatusTooManyRequests, false, false},
		{http.StatusInternalServerError, false, true},
		{http.StatusServiceUnavailable, false, true},
	} {
		t.Run(fmt.Sprint(tt.status), func(t *testing.T) {
			api := newFakeActionsAPI()
			api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
			api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{
				fakeActionsJob(1001, 100, 1, "completed", "one"),
				fakeActionsJob(1002, 100, 1, "completed", "two"),
				fakeActionsJob(1003, 100, 1, "completed", "three"),
			}
			api.logs[1001] = "fixture-token-abcdefghij"
			api.logs[1003] = "fixture-token-klmnopqrst"
			api.logErrors[1002] = &actionsLogError{stage: "job log", status: tt.status}
			opts := testActionsOptions()
			opts.Runs = []int64{100}
			result, err := fakeScanActions(t, api, opts)
			if tt.unavailable {
				if err != nil || result.Summary.Unavailable != 1 || result.Summary.Scanned != 2 || len(result.Findings) != 2 || len(result.Warnings) != 1 {
					t.Fatalf("unavailable handling: result %+v, err %v", result, err)
				}
			} else if tt.recoverable {
				if err == nil || !strings.Contains(err.Error(), fmt.Sprint(tt.status)) || !strings.Contains(err.Error(), "1 error(s) occurred") ||
					result.Summary.Scanned != 2 || result.Summary.Failed != 1 || len(result.Findings) != 2 || len(api.logIDs) != 3 {
					t.Fatalf("recoverable handling: result %+v, err %v, logs %v", result, err, api.logIDs)
				}
			} else if err == nil || !strings.Contains(err.Error(), fmt.Sprint(tt.status)) || result.Summary.Scanned != 1 || len(result.Findings) != 1 || len(api.logIDs) != 2 {
				t.Fatalf("fatal handling: result %+v, err %v, logs %v", result, err, api.logIDs)
			}
		})
	}
}

func TestActionsFailedAcquisitionsCountAndWaitCanCancel(t *testing.T) {
	for _, cancelDuringWait := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelDuringWait), func(t *testing.T) {
			api := newFakeActionsAPI()
			api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
			api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{
				fakeActionsJob(1001, 100, 1, "completed", "one"),
				fakeActionsJob(1002, 100, 1, "completed", "two"),
			}
			api.logErrors[1001] = &actionsLogError{stage: "job log", status: http.StatusNotFound}
			api.logs[1002] = "fixture-token-abcdefghij"
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			limiter := newActionsRateLimiter(1, nil)
			limiter.now = func() time.Time { return now }
			waited := false
			limiter.wait = func(ctx context.Context, delay time.Duration) error {
				waited = true
				if delay != time.Hour || !reflect.DeepEqual(api.logIDs, []int64{1001}) {
					t.Fatalf("incorrect wait or early log fetch: %v, %v", delay, api.logIDs)
				}
				if cancelDuringWait {
					cancel()
					return ctx.Err()
				}
				now = now.Add(delay)
				return nil
			}
			opts := testActionsOptions()
			opts.Runs, opts.MaxJobsPerHour = []int64{100}, 1
			result, err := scanActions(ctx, api, fakeActionsRepository(), opts, fakeActionsScanner(t, false), limiter)
			if !waited || result.Summary.Unavailable != 1 {
				t.Fatalf("failure did not consume the limit: %+v, %v", result.Summary, err)
			}
			if cancelDuringWait {
				if err != nil || !result.Interrupted || len(api.logIDs) != 1 {
					t.Fatalf("wait cancellation: %v, logs %v", err, api.logIDs)
				}
			} else if err != nil || !reflect.DeepEqual(api.logIDs, []int64{1001, 1002}) || len(result.Findings) != 1 {
				t.Fatalf("wait continuation: %+v, %v, logs %v", result, err, api.logIDs)
			}
		})
	}
}

func TestActionsCancellationPreservesEarlierFindings(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{
		fakeActionsJob(1001, 100, 1, "completed", "first"),
		fakeActionsJob(1002, 100, 1, "completed", "second"),
	}
	api.logs[1001] = "fixture-token-abcdefghij"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	limiter := newActionsRateLimiter(1, nil)
	limiter.wait = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	opts := testActionsOptions()
	opts.Runs, opts.MaxJobsPerHour = []int64{100}, 1
	result, err := scanActions(ctx, api, fakeActionsRepository(), opts, fakeActionsScanner(t, false), limiter)
	if err != nil || !result.Interrupted || result.Summary.Scanned != 1 || len(result.Findings) != 1 || !reflect.DeepEqual(api.logIDs, []int64{1001}) {
		t.Fatalf("result = %+v, err = %v, logs = %v", result, err, api.logIDs)
	}
	if code := result.ExitCode(); code != 1 {
		t.Fatalf("ExitCode() = %d, want 1", code)
	}
	var summary strings.Builder
	if err := RenderActionsSummary(&summary, result); err != nil || !strings.Contains(summary.String(), "Scan interrupted") {
		t.Fatalf("summary = %q, err = %v", summary.String(), err)
	}
}

func TestActionsInterruptedDuringLogDownloadKeepsResults(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{
		fakeActionsJob(1001, 100, 1, "completed", "first"),
		fakeActionsJob(1002, 100, 1, "completed", "second"),
	}
	api.logs[1001] = "fixture-token-abcdefghij"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	api.logErrors[1002] = fmt.Errorf("download interrupted: %w", context.Canceled)
	api.beforeLog = func(jobID int64) {
		if jobID == 1002 {
			cancel()
		}
	}
	opts := testActionsOptions()
	opts.Runs = []int64{100}
	result, err := scanActions(ctx, api, fakeActionsRepository(), opts, fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || !result.Interrupted || result.Summary.Scanned != 1 || len(result.Findings) != 1 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestActionsUnrelatedCancellationErrorIsReported(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{fakeActionsJob(1001, 100, 1, "completed", "first")}
	api.logErrors[1001] = fmt.Errorf("upstream: %w", context.Canceled)
	opts := testActionsOptions()
	opts.Runs = []int64{100}
	result, err := fakeScanActions(t, api, opts)
	if !errors.Is(err, context.Canceled) || result.Interrupted {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestActionsScanResultExitCode(t *testing.T) {
	for _, tt := range []struct {
		name   string
		result ActionsScanResult
		want   int
	}{
		{"clean", ActionsScanResult{}, 0},
		{"findings", ActionsScanResult{Findings: []ActionsFinding{{}}}, 1},
		{"interrupted", ActionsScanResult{Interrupted: true}, 130},
		{"interrupted with findings", ActionsScanResult{Findings: []ActionsFinding{{}}, Interrupted: true}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.ExitCode(); got != tt.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestActionsFindingsMaskMetadataAndRender(t *testing.T) {
	secret := "fixture-token-abcdefghij"
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "workflow\t"+secret, ".github/workflows/"+secret+".yml")
	job := fakeActionsJob(1001, 100, 1, "completed", "build\n"+secret)
	job.HTMLURL = github.Ptr("https://example.invalid/" + secret)
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{job}
	api.logs[1001] = "line\n" + secret + "\n" + secret + "\n"
	opts := testActionsOptions()
	opts.Runs = []int64{100}
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 1 || result.Findings[0].StartLine != 2 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	data, err := json.Marshal(result.Findings)
	if err != nil || strings.Contains(string(data), secret) {
		t.Fatalf("JSON leaked secret: %s, %v", data, err)
	}
	output := render.NewStringRenderer(nil)
	if err := RenderActionsFindings(&output.Renderer, result.Findings); err != nil {
		t.Fatal(err)
	}
	text := output.Stdout.String()
	for _, want := range []string{"workflow\\t", "build\\n", "Run: 100 (attempt 1)", "Job:", "1 finding in 1 job"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	if strings.Contains(text, secret) {
		t.Fatalf("text leaked secret: %q", text)
	}
	exported := render.NewStringRenderer(cmdutil.NewJSONExporter())
	if err := RenderActionsFindings(&exported.Renderer, result.Findings); err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(exported.Stdout.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"workflow_id", "workflow_name", "workflow_path", "run_id", "run_attempt", "job_id", "job_name", "job_url", "start_line", "secret"} {
		if _, ok := decoded[0][key]; !ok {
			t.Fatalf("missing JSON field %q: %s", key, exported.Stdout.String())
		}
	}
	var summary bytes.Buffer
	if err := RenderActionsSummary(&summary, result); err != nil || !strings.Contains(summary.String(), "Scanned 1 job log; 1 run considered, 1 workflow selected") {
		t.Fatalf("summary = %q, err = %v", summary.String(), err)
	}
	if err := RenderActionsSummary(findingErrorWriter{}, result); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("summary write error = %v", err)
	}
	output.Renderer.IO.Out = findingErrorWriter{}
	if err := RenderActionsFindings(&output.Renderer, result.Findings); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("findings write error = %v", err)
	}
	exported.Renderer.IO.Out = findingErrorWriter{}
	if err := RenderActionsFindings(&exported.Renderer, result.Findings); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("exported findings write error = %v", err)
	}
	shown, err := scanActions(t.Context(), api, fakeActionsRepository(), opts, fakeActionsScanner(t, true), newActionsRateLimiter(0, nil))
	if err != nil || len(shown.Findings) != 1 || shown.Findings[0].Secret != secret || !strings.Contains(shown.Findings[0].JobName, secret) {
		t.Fatalf("show-secret did not apply to finding metadata: %+v, %v", shown, err)
	}
}

func TestActionsFindingPatternMetadataIsMasked(t *testing.T) {
	secret := "fixture-token-abcdefghij"
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{fakeActionsJob(1001, 100, 1, "completed", "build")}
	api.logs[1001] = secret
	scanner, err := NewScanner(&Config{Patterns: []ConfigPattern{{
		ID: secret, TokenType: secret, DisplayName: secret, Regex: `fixture-token-[a-z0-9]{10}`,
	}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	opts := testActionsOptions()
	opts.Runs = []int64{100}
	result, err := scanActions(t.Context(), api, fakeActionsRepository(), opts, scanner, newActionsRateLimiter(0, nil))
	if err != nil || len(result.Findings) != 1 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	data, err := json.Marshal(result.Findings)
	if err != nil || strings.Contains(string(data), secret) {
		t.Fatalf("pattern metadata leaked a secret: %s, %v", data, err)
	}
}

func TestActionsScanAppliesConfiguredAllowlist(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{
		fakeActionsJob(1001, 100, 1, "completed", "build"),
		fakeActionsJob(1002, 100, 1, "completed", "test"),
	}
	api.logs[1001] = "fixture-token-abcdefghij"
	api.logs[1002] = "fixture-token-abcdefghij"
	scanner, err := NewScanner(&Config{
		Patterns:  []ConfigPattern{{ID: "fixture_token", Regex: `fixture-token-[a-z0-9]{10}`}},
		Allowlist: ConfigAllowlist{Paths: []string{"actions/jobs/1001.log"}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	opts := testActionsOptions()
	opts.Runs = []int64{100}
	result, err := scanActions(t.Context(), api, fakeActionsRepository(), opts, scanner, newActionsRateLimiter(0, nil))
	if err != nil || result.Summary.Scanned != 2 || len(result.Findings) != 1 || result.Findings[0].JobID != 1002 {
		t.Fatalf("allowlist result = %+v, err = %v", result, err)
	}
}

func TestActionsCancelledBeforeDiscovery(t *testing.T) {
	api := newFakeActionsAPI()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := scanActions(ctx, api, fakeActionsRepository(), testActionsOptions(), fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || !result.Interrupted || len(api.calls) != 0 {
		t.Fatalf("cancelled scan made API requests: %v, %v", err, api.calls)
	}
}

func TestActionsScanContinuesAfterWorkflowErrors(t *testing.T) {
	api := newFakeActionsAPI()
	api.workflows = []*github.Workflow{
		{ID: github.Ptr(int64(1)), Name: github.Ptr("Build"), Path: github.Ptr(".github/workflows/build.yml")},
		{ID: github.Ptr(int64(2)), Name: github.Ptr("Lint"), Path: github.Ptr(".github/workflows/lint.yml")},
		{ID: github.Ptr(int64(3)), Name: github.Ptr("Release"), Path: github.Ptr(".github/workflows/release.yml")},
	}
	api.runErrors[1] = &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusBadGateway}, Message: "fixture outage"}
	api.history[2] = []*github.WorkflowRun{fakeActionsRun(200, 2, 1, "completed", "Lint", ".github/workflows/lint.yml")}
	api.history[3] = []*github.WorkflowRun{fakeActionsRun(300, 3, 1, "completed", "Release", ".github/workflows/release.yml")}
	api.jobErrors[actionsAttemptKey{200, 1}] = errors.New("fixture job listing failure")
	api.attempts[actionsAttemptKey{300, 1}] = []*github.WorkflowJob{fakeActionsJob(3001, 300, 1, "completed", "publish")}
	api.logs[3001] = "fixture-token-abcdefghij"
	opts := testActionsOptions()
	opts.RunsPerWorkflow = 2
	result, err := fakeScanActions(t, api, opts)
	if err == nil || !strings.Contains(err.Error(), "2 error(s) occurred") || !strings.Contains(err.Error(), "fixture job listing failure") ||
		len(result.Findings) != 1 || result.Summary.Scanned != 1 || result.Summary.FailedRuns != 1 || result.Summary.FailedWorkflows != 1 {
		t.Fatalf("result %+v, err %v, calls %v", result, err, api.calls)
	}
	if got := strings.Count(strings.Join(api.calls, ","), "runs:1:"); got != 1 {
		t.Fatalf("failed workflow listed %d times, calls %v", got, api.calls)
	}
}

func TestActionsScanStopsAfterConsecutiveErrors(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	var jobs []*github.WorkflowJob
	for id := int64(1001); id <= 1015; id++ {
		jobs = append(jobs, fakeActionsJob(id, 100, 1, "completed", fmt.Sprintf("job-%d", id)))
		api.logErrors[id] = &actionsLogError{stage: "job log", status: http.StatusServiceUnavailable}
	}
	api.attempts[actionsAttemptKey{100, 1}] = jobs
	opts := testActionsOptions()
	opts.Runs = []int64{100}
	result, err := fakeScanActions(t, api, opts)
	if err == nil || !strings.Contains(err.Error(), "consecutive errors") || len(api.logIDs) != maxActionsConsecutiveErrors ||
		result.Summary.Failed != maxActionsConsecutiveErrors {
		t.Fatalf("result %+v, err %v, logs %v", result, err, api.logIDs)
	}
}

func TestActionsFatalError(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{&actionsLogError{stage: "job log", status: http.StatusForbidden}, true},
		{&actionsLogError{stage: "job log", status: http.StatusServiceUnavailable}, false},
		{&github.RateLimitError{Message: "fixture"}, true},
		{&github.AbuseRateLimitError{Message: "fixture"}, true},
		{&github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusUnauthorized}}, true},
		{&github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusInternalServerError}}, false},
		{errors.New("fixture"), false},
	} {
		if got := actionsFatalError(fmt.Errorf("wrapped: %w", tt.err)); got != tt.want {
			t.Errorf("actionsFatalError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
