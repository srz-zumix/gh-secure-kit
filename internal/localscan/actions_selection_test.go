package localscan

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-github/v93/github"
)

func fakeURLActionsAPI() *fakeActionsAPI {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 3, "completed", "Build", ".github/workflows/build.yml")
	api.runs[200] = fakeActionsRun(200, 2, 2, "completed", "Release", ".github/workflows/release.yml")
	api.runAttempts[actionsAttemptKey{100, 1}] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	api.runAttempts[actionsAttemptKey{100, 2}] = fakeActionsRun(100, 1, 2, "completed", "Build", ".github/workflows/build.yml")
	api.runAttempts[actionsAttemptKey{200, 1}] = fakeActionsRun(200, 2, 1, "completed", "Release", ".github/workflows/release.yml")
	jobs := []*github.WorkflowJob{
		fakeActionsJob(1001, 100, 1, "completed", "old"),
		fakeActionsJob(1002, 100, 2, "completed", "middle"),
		fakeActionsJob(1003, 100, 3, "completed", "build"),
		fakeActionsJob(1004, 100, 3, "completed", "test"),
		fakeActionsJob(2001, 200, 2, "completed", "release"),
		fakeActionsJob(2002, 200, 2, "completed", "deploy"),
	}
	for _, job := range jobs {
		id := job.GetID()
		api.jobs[id] = job
		key := actionsAttemptKey{job.GetRunID(), job.GetRunAttempt()}
		api.attempts[key] = append(api.attempts[key], job)
		api.logs[id] = "fixture-token-abcdefghij"
	}
	return api
}

func urlActionsOptions(t *testing.T, selectors ...string) ActionsScanOptions {
	t.Helper()
	targets, err := ParseActionsRunTargets(selectors)
	if err != nil {
		t.Fatal(err)
	}
	opts := testActionsOptions()
	opts.Runs, opts.RunTargets = targets.Runs, targets.Targets
	return opts
}

const fakeActionsURL = "https://github.com/example-owner/example-repo/actions/runs/"

func TestActionsURLSelectionUnionsAndFairness(t *testing.T) {
	tests := []struct {
		name        string
		selectors   []string
		wantLogs    []int64
		needed      []string
		forbidden   []string
		wantRuns    int
		wantAttempt []int64
	}{
		{
			name:        "full run and different run job",
			selectors:   []string{"100", fakeActionsURL + "200/job/2001"},
			wantLogs:    []int64{1003, 2001, 1004},
			needed:      []string{"jobs:100:3", "job:2001"},
			forbidden:   []string{"jobs:200:2", "log:2002"},
			wantRuns:    2,
			wantAttempt: []int64{3, 2, 3},
		},
		{
			name:        "latest plus historical attempt and jobs",
			selectors:   []string{"100", fakeActionsURL + "100/attempts/2", fakeActionsURL + "100/job/1001", fakeActionsURL + "100/job/1003"},
			wantLogs:    []int64{1001, 1003, 1004, 1002},
			needed:      []string{"attempt:100:1", "attempt:100:2", "jobs:100:3", "jobs:100:2"},
			forbidden:   []string{"jobs:100:1"},
			wantRuns:    1,
			wantAttempt: []int64{1, 3, 3, 2},
		},
		{
			name:        "two historical attempts without latest",
			selectors:   []string{fakeActionsURL + "100/attempts/1", fakeActionsURL + "100/attempts/2"},
			wantLogs:    []int64{1001, 1002},
			needed:      []string{"attempt:100:1", "attempt:100:2", "jobs:100:1", "jobs:100:2"},
			forbidden:   []string{"jobs:100:3"},
			wantRuns:    1,
			wantAttempt: []int64{1, 2},
		},
		{
			name:        "latest overlaps exact attempt",
			selectors:   []string{fakeActionsURL + "100/attempts/3", "100", "100"},
			wantLogs:    []int64{1003, 1004},
			needed:      []string{"jobs:100:3"},
			forbidden:   []string{"attempt:100:3", "jobs:100:1", "jobs:100:2"},
			wantRuns:    1,
			wantAttempt: []int64{3, 3},
		},
		{
			name:        "job URL selects only that older job",
			selectors:   []string{fakeActionsURL + "100/job/1001"},
			wantLogs:    []int64{1001},
			needed:      []string{"job:1001", "attempt:100:1"},
			forbidden:   []string{"jobs:100:1", "jobs:100:2", "jobs:100:3"},
			wantRuns:    1,
			wantAttempt: []int64{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := fakeURLActionsAPI()
			result, err := fakeScanActions(t, api, urlActionsOptions(t, tt.selectors...))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(api.logIDs, tt.wantLogs) || result.Summary.Runs != tt.wantRuns || len(result.Findings) != len(tt.wantLogs) {
				t.Fatalf("logs = %v, summary = %+v, findings = %d, calls = %v", api.logIDs, result.Summary, len(result.Findings), api.calls)
			}
			for i, finding := range result.Findings {
				if finding.RunAttempt != tt.wantAttempt[i] {
					t.Fatalf("finding %d attempt = %d, want %d", i, finding.RunAttempt, tt.wantAttempt[i])
				}
			}
			for _, call := range tt.needed {
				if indexOfCall(api.calls, call) < 0 {
					t.Fatalf("missing call %q: %v", call, api.calls)
				}
			}
			for _, call := range tt.forbidden {
				if indexOfCall(api.calls, call) >= 0 {
					t.Fatalf("unexpected call %q: %v", call, api.calls)
				}
			}
		})
	}
}

func TestActionsURLSelectionIntersectsJobFilters(t *testing.T) {
	tests := []struct {
		name      string
		selectors []string
		jobs      []string
		wantLogs  []int64
		wantErr   string
	}{
		{"matching job name", []string{fakeActionsURL + "100/job/1001", fakeActionsURL + "100/job/1002"}, []string{"old"}, []int64{1001}, ""},
		{"nonmatching job name", []string{fakeActionsURL + "100/job/1001"}, []string{"build"}, nil, "no job matches"},
		{"matching numeric job", []string{fakeActionsURL + "100/job/1001", fakeActionsURL + "100/job/1002"}, []string{"1002"}, []int64{1002}, ""},
		{"numeric job cannot broaden job URL", []string{fakeActionsURL + "100/job/1001"}, []string{"1002"}, nil, "outside the targets"},
		{"numeric job cannot broaden exact attempt", []string{fakeActionsURL + "100/attempts/2"}, []string{"1001"}, nil, "outside the targets"},
		{"numeric job can match exact attempt", []string{fakeActionsURL + "100/attempts/2"}, []string{"1002"}, []int64{1002}, ""},
		{"latest full run keeps older numeric job", []string{"100"}, []string{"1001"}, []int64{1001}, ""},
		{"explicit job URL extends exact attempt", []string{fakeActionsURL + "100/attempts/2", fakeActionsURL + "100/job/1001"}, []string{"1001"}, []int64{1001}, ""},
		{"separate per-run scopes", []string{"100", fakeActionsURL + "200/job/2001"}, []string{"deploy"}, nil, "no job matches"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := fakeURLActionsAPI()
			opts := urlActionsOptions(t, tt.selectors...)
			opts.Jobs = tt.jobs
			_, err := fakeScanActions(t, api, opts)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("got error %v, want %q; calls = %v", err, tt.wantErr, api.calls)
			}
			if !reflect.DeepEqual(api.logIDs, tt.wantLogs) {
				t.Fatalf("logs = %v, want %v; calls = %v", api.logIDs, tt.wantLogs, api.calls)
			}
		})
	}
}

func TestActionsURLSelectionValidatesJobIdentity(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		change   func(*fakeActionsAPI)
		wantErr  string
	}{
		{
			"job belongs to different selected run",
			fakeActionsURL + "100/job/2001",
			func(*fakeActionsAPI) {},
			"does not belong to the run",
		},
		{
			"job belongs to different attempt",
			fakeActionsURL + "100/attempts/2/job/1001",
			func(*fakeActionsAPI) {},
			"does not belong to the attempt",
		},
		{
			"job lacks attempt and is absent from expected attempt",
			fakeActionsURL + "100/attempts/2/job/1001",
			func(api *fakeActionsAPI) { api.jobs[1001].RunAttempt = nil },
			"does not belong to the attempt",
		},
		{
			"attempt metadata has wrong workflow",
			fakeActionsURL + "100/attempts/1",
			func(api *fakeActionsAPI) {
				api.runAttempts[actionsAttemptKey{100, 1}].WorkflowID = github.Ptr(int64(2))
			},
			"inconsistent metadata",
		},
		{
			"attempt metadata has wrong attempt",
			fakeActionsURL + "100/attempts/1",
			func(api *fakeActionsAPI) { api.runAttempts[actionsAttemptKey{100, 1}].RunAttempt = github.Ptr(2) },
			"inconsistent metadata",
		},
		{
			"missing attempt",
			fakeActionsURL + "100/attempts/9",
			func(*fakeActionsAPI) {},
			"failed to get workflow run 100 attempt 9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := fakeURLActionsAPI()
			tt.change(api)
			opts := urlActionsOptions(t, tt.selector, "200")
			_, err := fakeScanActions(t, api, opts)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || len(api.logIDs) != 0 {
				t.Fatalf("got error %v and logs %v, want %q before logs; calls = %v", err, api.logIDs, tt.wantErr, api.calls)
			}
		})
	}
}

func TestActionsURLSelectionUsesExactAttemptStatus(t *testing.T) {
	t.Run("completed old attempt while latest is running", func(t *testing.T) {
		api := fakeURLActionsAPI()
		api.runs[100].Status = github.Ptr("in_progress")
		opts := urlActionsOptions(t, fakeActionsURL+"100/attempts/1")
		result, err := fakeScanActions(t, api, opts)
		if err != nil || !reflect.DeepEqual(api.logIDs, []int64{1001}) || result.Summary.IncompleteRuns != 0 {
			t.Fatalf("result = %+v, err = %v, logs = %v", result.Summary, err, api.logIDs)
		}
	})
	for _, target := range []string{"100/attempts/1", "100/job/1001"} {
		t.Run(target, func(t *testing.T) {
			api := fakeURLActionsAPI()
			api.runAttempts[actionsAttemptKey{100, 1}].Status = github.Ptr("in_progress")
			opts := urlActionsOptions(t, fakeActionsURL+target)
			_, err := fakeScanActions(t, api, opts)
			if err == nil || !strings.Contains(err.Error(), "not complete") || len(api.logIDs) != 0 {
				t.Fatalf("unfinished attempt was accepted: %v, logs %v", err, api.logIDs)
			}
			opts.AllowInProgress = true
			result, err := fakeScanActions(t, api, opts)
			if err != nil || !reflect.DeepEqual(api.logIDs, []int64{1001}) || result.Summary.IncompleteRuns != 1 || len(result.Warnings) != 1 {
				t.Fatalf("result = %+v, err = %v, logs = %v", result, err, api.logIDs)
			}
		})
	}
}

func TestActionsURLSelectionWorkflowFiltering(t *testing.T) {
	t.Run("exclude implicit URL job", func(t *testing.T) {
		api := fakeURLActionsAPI()
		api.runs[100].Status = github.Ptr("in_progress")
		opts := urlActionsOptions(t, fakeActionsURL+"100/job/1001", "200")
		opts.Workflows = []string{"release.yml"}
		result, err := fakeScanActions(t, api, opts)
		if err != nil || !reflect.DeepEqual(api.logIDs, []int64{2001, 2002}) || result.Summary.Runs != 1 {
			t.Fatalf("result = %+v, err = %v, logs = %v, calls = %v", result, err, api.logIDs, api.calls)
		}
		if indexOfCall(api.calls, "attempt:100:1") >= 0 {
			t.Fatalf("excluded URL job resolved an attempt: %v", api.calls)
		}
	})
	t.Run("explicit numeric job still conflicts", func(t *testing.T) {
		api := fakeURLActionsAPI()
		opts := urlActionsOptions(t, fakeActionsURL+"100/job/1001", "200")
		opts.Workflows, opts.Jobs = []string{"release.yml"}, []string{"1001"}
		_, err := fakeScanActions(t, api, opts)
		if err == nil || !strings.Contains(err.Error(), "selected workflow") || len(api.logIDs) != 0 {
			t.Fatalf("got error %v, logs %v", err, api.logIDs)
		}
	})
}

func TestActionsURLJobAttemptLookupIsCached(t *testing.T) {
	api := fakeURLActionsAPI()
	api.jobs[1002].RunAttempt = nil
	opts := urlActionsOptions(t, fakeActionsURL+"100/attempts/2", fakeActionsURL+"100/attempts/2/job/1002")
	result, err := fakeScanActions(t, api, opts)
	if err != nil || !reflect.DeepEqual(api.logIDs, []int64{1002}) || len(result.Findings) != 1 || result.Findings[0].RunAttempt != 2 {
		t.Fatalf("result = %+v, err = %v, calls = %v", result, err, api.calls)
	}
	count := 0
	for _, call := range api.calls {
		if call == "jobs:100:2" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("attempt jobs requested %d times: %v", count, api.calls)
	}
}

func TestActionsURLJobMissingAttemptRequiresMembership(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			api := fakeURLActionsAPI()
			api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
			api.jobs[1001].RunAttempt = nil
			if !present {
				api.attempts[actionsAttemptKey{100, 1}] = nil
			}
			result, err := fakeScanActions(t, api, urlActionsOptions(t, fakeActionsURL+"100/job/1001"))
			if !present {
				if err == nil || !strings.Contains(err.Error(), "could not determine the attempt") || len(api.logIDs) != 0 {
					t.Fatalf("missing job was attributed to attempt 1: result = %+v, err = %v, calls = %v", result, err, api.calls)
				}
			} else if err != nil || len(result.Findings) != 1 || result.Findings[0].RunAttempt != 1 {
				t.Fatalf("result = %+v, err = %v, calls = %v", result, err, api.calls)
			}
			if indexOfCall(api.calls, "jobs:100:1") < 0 {
				t.Fatalf("attempt membership was not checked: %v", api.calls)
			}
		})
	}
}

func TestActionsExactAttemptJobAfterLatestSnapshot(t *testing.T) {
	api := fakeURLActionsAPI()
	api.runs[100].RunAttempt = github.Ptr(1)
	api.jobs[1002].RunAttempt = nil
	opts := urlActionsOptions(t, fakeActionsURL+"100/attempts/2")
	opts.Jobs = []string{"1002"}
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 1 || result.Findings[0].RunAttempt != 2 || !reflect.DeepEqual(api.logIDs, []int64{1002}) {
		t.Fatalf("result = %+v, err = %v, calls = %v", result, err, api.calls)
	}
}

func TestActionsExactAttemptJobUsesAttemptMetadata(t *testing.T) {
	api := fakeURLActionsAPI()
	sha := strings.Repeat("2", 40)
	api.runAttempts[actionsAttemptKey{100, 2}].HeadSHA = github.Ptr(sha)
	opts := urlActionsOptions(t, fakeActionsURL+"100/attempts/2")
	opts.Jobs = []string{"1002"}
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 1 || result.Findings[0].Commit != sha || result.Findings[0].RunAttempt != 2 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestActionsURLSelectionSnapshotsLatestAttempt(t *testing.T) {
	api := fakeURLActionsAPI()
	opts := urlActionsOptions(t, "100", fakeActionsURL+"100/attempts/3")
	_, err := fakeScanActions(t, api, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"run:100", "jobs:100:3"} {
		count := 0
		for _, call := range api.calls {
			if call == wanted {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s called %d times: %v", wanted, count, api.calls)
		}
	}
	if indexOfCall(api.calls, fmt.Sprintf("jobs:%d:%d", 100, 4)) >= 0 {
		t.Fatalf("latest attempt was not pinned: %v", api.calls)
	}
}
