package localscan

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v93/github"
)

func stepFallbackFixture(t *testing.T) (*fakeActionsAPI, ActionsScanOptions) {
	t.Helper()
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", "dynamic/example/build")
	job := fakeActionsJob(1001, 100, 1, "completed", "Build")
	job.Steps = actionsJobSteps(1, 27)
	api.jobs[1001] = job
	prefix := "2026-01-02T03:04:05.123Z "
	api.logs[1001] = "\xef\xbb\xbf" + prefix + "prepare\n" + prefix + "ordinary\n" + prefix + "fixture-token-abcdefghij\n" + prefix + "finished\n"
	api.stepLogs[[2]int64{1001, 1}] = "\xef\xbb\xbf2026-01-02T03:04:06Z prepare\n"
	api.stepLogs[[2]int64{1001, 27}] = "\xef\xbb\xbf2026-01-02T03:04:07Z ordinary\n2026-01-02T03:04:07Z fixture-token-abcdefghij\n2026-01-02T03:04:07Z finished"
	api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_Build.txt", api.logs[1001]},
		actionsArchiveFixture{"Build/system.txt", "system data\n"},
		actionsArchiveFixture{"1_Unselected.txt", "fixture-token-zzzzzzzzzz\n"},
	)
	opts := urlActionsOptions(t, fakeActionsURL+"100/job/1001")
	opts.LocationURL = true
	return api, opts
}

func TestActionsLocationStepAPIFallback(t *testing.T) {
	api, opts := stepFallbackFixture(t)
	api.jobs[1001].Steps = append(api.jobs[1001].Steps, &github.TaskStep{
		Number: new(int64(2)), Conclusion: new("skipped"),
	})
	limiter := newActionsRateLimiter(1, nil)
	limiter.wait = func(context.Context, time.Duration) error {
		t.Fatal("step log retrieval must not consume the job hourly limit")
		return nil
	}
	result, err := scanActions(t.Context(), api, fakeActionsRepository(), opts, fakeActionsScanner(t, false), limiter)
	if err != nil || len(result.Findings) != 1 || len(result.Warnings) != 0 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	finding := result.Findings[0]
	if finding.StartLine != 3 || !strings.HasSuffix(finding.LocationURL, "#step:27:2") {
		t.Fatalf("unexpected coordinates: %+v", finding)
	}
	if len(limiter.starts) != 1 || !reflect.DeepEqual(api.logIDs, []int64{1001}) {
		t.Fatalf("fallback affected job scope or hourly accounting: %v, %v", limiter.starts, api.logIDs)
	}
	var stepCalls []string
	for _, call := range api.calls {
		if strings.HasPrefix(call, "step:") {
			stepCalls = append(stepCalls, call)
		}
	}
	if !reflect.DeepEqual(stepCalls, []string{"step:1001:1", "step:1001:27"}) {
		t.Fatalf("step calls = %v", stepCalls)
	}
}

func TestActionsLocationStepAPISearchBudget(t *testing.T) {
	api := newFakeActionsAPI()
	job := fakeActionsJob(1001, 100, 1, "completed", "Build")
	for number := int64(1); number <= 300; number++ {
		job.Steps = append(job.Steps, &github.TaskStep{Number: new(number)})
		api.stepLogs[[2]int64{1001, number}] = "target\n"
	}
	runner := actionsRunner{api: api}
	content := []byte("target\n" + strings.Repeat("x", 2<<20))
	_, err := runner.apiStepRanges(t.Context(), job, content)
	if err == nil || !strings.Contains(err.Error(), "search limit") || len(api.calls) >= len(job.Steps) {
		t.Fatalf("matching budget not enforced: %v, %d calls", err, len(api.calls))
	}
}

func TestActionsLocationStepAPIAmbiguity(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*fakeActionsAPI)
	}{
		{"duplicate step body", func(api *fakeActionsAPI) {
			api.stepLogs[[2]int64{1001, 1}] = api.stepLogs[[2]int64{1001, 27}]
		}},
		{"overlapping step body", func(api *fakeActionsAPI) {
			api.stepLogs[[2]int64{1001, 1}] = "fixture-token-abcdefghij\n"
		}},
		{"missing whole job", func(api *fakeActionsAPI) {
			api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t, actionsArchiveFixture{"Build/system.txt", "system\n"})
		}},
		{"changed whole job", func(api *fakeActionsAPI) {
			api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t, actionsArchiveFixture{"0_Build.txt", "different\n"})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api, opts := stepFallbackFixture(t)
			tt.change(api)
			result, err := fakeScanActions(t, api, opts)
			if err != nil || len(result.Findings) != 1 || result.Findings[0].LocationURL != "" || len(result.Warnings) == 0 {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
		})
	}
}

func TestActionsLocationStepAPIUnavailableAndFatal(t *testing.T) {
	for _, status := range []int{404, 410, 401, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			api, opts := stepFallbackFixture(t)
			api.stepErrors[[2]int64{1001, 1}] = &actionsLogError{stage: "requesting step log", status: status}
			result, err := fakeScanActions(t, api, opts)
			unavailable := status == 404 || status == 410
			if (err == nil) != unavailable || len(result.Findings) != 1 {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
			if unavailable {
				if len(result.Warnings) != 1 || !strings.HasSuffix(result.Findings[0].LocationURL, "#step:27:2") {
					t.Fatalf("unavailable step prevented another step from resolving: %+v", result)
				}
			} else if result.Findings[0].LocationURL != "" || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("unexpected fatal result: %+v, %v", result, err)
			}
		})
	}
}

func TestNormalizedActionsStepMatching(t *testing.T) {
	for _, tt := range []struct {
		name, log, step string
		wantLine        int
	}{
		{"different timestamps and BOM", "\xef\xbb\xbf2026-01-01T00:00:00Z before\n2026-01-01T00:00:00Z target\n", "\xef\xbb\xbf2026-01-01T00:00:01.123Z target\n", 2},
		{"CRLF and terminal newline", "before\r\ntarget\r\n", "target", 2},
		{"blank lines", "before\n\n\ntarget\n", "\n\ntarget\n", 2},
		{"timestamp payload", "2026-01-01T00:00:00Z 2026-01-01T00:00:02Z target\n", "2026-01-01T00:00:01Z 2026-01-01T00:00:02Z target\n", 1},
		{"malformed timestamp preserved", "2026-99-99T00:00:00Z target\n", "2026-99-99T00:00:00Z target\n", 1},
		{"malformed timestamp differs", "2026-99-99T00:00:00Z target\n", "target\n", 0},
		{"repeated content", "target\nmiddle\ntarget\n", "target\n", 0},
		{"overlapping repeated content", "a\na\na\n", "a\na\n", 0},
		{"partial line", "not-target\n", "target\n", 0},
		{"bare CR", "before\rtarget\n", "target\n", 0},
		{"bare CR in step", "target\n", "tar\rget\n", 0},
		{"empty step", "target\n", "", 0},
		{"BOM only", "target\n", "\xef\xbb\xbf", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			position, ok := uniqueActionsStepRange(normalizedActionsLocationLog([]byte(tt.log)), normalizedActionsLocationLog([]byte(tt.step)), 27)
			if ok != (tt.wantLine > 0) || ok && position.firstLine != tt.wantLine {
				t.Fatalf("position = %+v, ok = %v", position, ok)
			}
		})
	}
}

type cancelStepActionsAPI struct {
	*fakeActionsAPI
	cancel context.CancelFunc
}

func (a *cancelStepActionsAPI) getStepLog(ctx context.Context, jobID, step, limit int64) ([]byte, error) {
	content, err := a.fakeActionsAPI.getStepLog(ctx, jobID, step, limit)
	a.cancel()
	return content, err
}

func TestActionsLocationStepAPIPreservesEarlierLocationsOnError(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprint(canceled), func(t *testing.T) {
			api, opts := stepFallbackFixture(t)
			api.logs[1001] = "fixture-token-klmnopqrst\n" + api.logs[1001]
			api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
				actionsArchiveFixture{"0_Build.txt", api.logs[1001]},
				actionsArchiveFixture{"Build/1_Prepare.txt", "fixture-token-klmnopqrst\n"},
			)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var source actionsAPI = api
			if canceled {
				source = &cancelStepActionsAPI{fakeActionsAPI: api, cancel: cancel}
			} else {
				api.stepErrors[[2]int64{1001, 1}] = &actionsLogError{stage: "step", status: http.StatusForbidden}
			}
			result, err := scanActions(ctx, source, fakeActionsRepository(), opts, fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
			if canceled && (err != nil || !result.Interrupted) || !canceled && (err == nil || result.Interrupted) || len(result.Findings) != 2 ||
				!strings.HasSuffix(result.Findings[0].LocationURL, "#step:1:1") || result.Findings[1].LocationURL != "" {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
		})
	}
}
