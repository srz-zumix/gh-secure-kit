package localscan

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/google/go-github/v93/github"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type actionsArchiveFixture struct {
	name, content string
}

func makeActionsArchive(t *testing.T, entries ...actionsArchiveFixture) []byte {
	t.Helper()
	var content bytes.Buffer
	writer := zip.NewWriter(&content)
	for _, entry := range entries {
		file, err := writer.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return content.Bytes()
}

func actionsJobSteps(numbers ...int64) []*github.TaskStep {
	steps := make([]*github.TaskStep, 0, len(numbers))
	for _, number := range numbers {
		steps = append(steps, &github.TaskStep{Number: new(number)})
	}
	return steps
}

func TestActionsLocationURLAtExactStepLine(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 2, "completed", "Build", ".github/workflows/build.yml")
	job := fakeActionsJob(1001, 100, 2, "completed", "Build job")
	job.Steps = actionsJobSteps(1, 27)
	api.jobs[1001] = job
	prefix := "2026-01-02T03:04:05.1234567Z "
	first := prefix + "prepare\n" + prefix + "ready\n"
	second := strings.Repeat(prefix+"ordinary\n", 519) + prefix + "fixture-token-abcdefghij\n"
	api.logs[1001] = first + second
	api.archives[actionsAttemptKey{100, 2}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_Build job.txt", first + second},
		actionsArchiveFixture{"Build job/27_Inspect.txt", second},
		actionsArchiveFixture{"Build job/1_Prepare.txt", first},
		actionsArchiveFixture{"1_Unselected.txt", "fixture-token-zzzzzzzzzz\n"},
		actionsArchiveFixture{"Unselected/1_other.txt", "fixture-token-zzzzzzzzzz\n"},
	)
	opts := urlActionsOptions(t, fakeActionsURL+"100/job/1001")
	opts.LocationURL = true
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 1 || result.Summary.Scanned != 1 {
		t.Fatalf("result = %+v, err = %v, calls = %v", result, err, api.calls)
	}
	want := "https://github.com/example-owner/example-repo/actions/runs/100/job/1001#step:27:520"
	finding := result.Findings[0]
	if finding.LocationURL != want || finding.StartLine != 522 || len(result.Warnings) != 0 {
		t.Fatalf("finding = %+v, warnings = %v", finding, result.Warnings)
	}
	if !reflect.DeepEqual(api.logIDs, []int64{1001}) || indexOfCall(api.calls, "archive:100:2") < 0 {
		t.Fatalf("unexpected selected jobs or archive calls: logs = %v, calls = %v", api.logIDs, api.calls)
	}
	text := render.NewStringRenderer(nil)
	if err := RenderActionsFindings(&text.Renderer, result.Findings); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.Stdout.String(), want) || strings.Contains(text.Stdout.String(), "fixture-token-abcdefghij") {
		t.Fatalf("unexpected text output: %q", text.Stdout.String())
	}
	exported := render.NewStringRenderer(cmdutil.NewJSONExporter())
	if err := RenderActionsFindings(&exported.Renderer, result.Findings); err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(exported.Stdout.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded[0]["location_url"] != want || decoded[0]["start_line"] != float64(522) ||
		strings.Contains(exported.Stdout.String(), "fixture-token-abcdefghij") {
		t.Fatalf("unexpected JSON output: %s", exported.Stdout.String())
	}
}

func TestActionsLocationOnlyDownloadsOnOptInAndFinding(t *testing.T) {
	for _, tt := range []struct {
		name        string
		optIn       bool
		log         string
		wantFinding bool
	}{
		{"default off", false, "fixture-token-abcdefghij\n", true},
		{"opted in but clean", true, "ordinary text\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := newFakeActionsAPI()
			api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
			job := fakeActionsJob(1001, 100, 1, "completed", "Build job")
			job.Steps = actionsJobSteps(1)
			api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{job}
			api.logs[1001] = tt.log
			opts := testActionsOptions()
			opts.Runs, opts.LocationURL = []int64{100}, tt.optIn
			result, err := fakeScanActions(t, api, opts)
			if err != nil || (len(result.Findings) > 0) != tt.wantFinding {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
			if indexOfCall(api.calls, "archive:100:1") >= 0 {
				t.Fatalf("unexpected archive request: %v", api.calls)
			}
			if len(result.Findings) > 0 && result.Findings[0].LocationURL != "" {
				t.Fatalf("unexpected location URL: %+v", result.Findings[0])
			}
			data, err := json.Marshal(result.Findings)
			if err != nil || strings.Contains(string(data), "location_url") {
				t.Fatalf("default JSON changed: %s, %v", data, err)
			}
		})
	}
}

func TestActionsLocationOneArchivePerAttempt(t *testing.T) {
	api := fakeURLActionsAPI()
	for _, item := range []struct {
		id      int64
		number  int64
		content string
	}{
		{1001, 1, "fixture-token-abcdefghij\n"},
		{1002, 2, "fixture-token-klmnopqrst\n"},
		{1003, 3, "fixture-token-uvwxyzabcd\n"},
	} {
		api.jobs[item.id].Steps = actionsJobSteps(item.number)
		api.logs[item.id] = item.content
	}
	api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_old.txt", api.logs[1001]},
		actionsArchiveFixture{"old/1_step.txt", api.logs[1001]},
	)
	api.archives[actionsAttemptKey{100, 2}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_middle.txt", api.logs[1002]},
		actionsArchiveFixture{"middle/2_step.txt", api.logs[1002]},
	)
	api.archives[actionsAttemptKey{100, 3}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_build.txt", api.logs[1003]},
		actionsArchiveFixture{"build/3_step.txt", api.logs[1003]},
	)
	opts := urlActionsOptions(t, fakeActionsURL+"100/attempts/1", fakeActionsURL+"100/attempts/2", fakeActionsURL+"100/job/1003")
	opts.LocationURL = true
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 3 {
		t.Fatalf("result = %+v, err = %v, calls = %v", result, err, api.calls)
	}
	for _, finding := range result.Findings {
		want := fmt.Sprintf("#step:%d:1", finding.RunAttempt)
		if !strings.HasSuffix(finding.LocationURL, want) {
			t.Fatalf("finding = %+v, want suffix %q", finding, want)
		}
	}
	for attempt := 1; attempt <= 3; attempt++ {
		call := fmt.Sprintf("archive:100:%d", attempt)
		count := 0
		for _, got := range api.calls {
			if got == call {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%q occurred %d times: %v", call, count, api.calls)
		}
	}
}

func TestActionsLocationSharesArchiveAcrossJobsAndFindings(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	first := fakeActionsJob(1001, 100, 1, "completed", "first")
	first.Steps = actionsJobSteps(1)
	second := fakeActionsJob(1002, 100, 1, "completed", "second")
	second.Steps = actionsJobSteps(2)
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{first, second}
	api.logs[1001] = "fixture-token-abcdefghij\nfixture-token-klmnopqrst\n"
	api.logs[1002] = "fixture-token-uvwxyzabcd\n"
	api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_first.txt", api.logs[1001]},
		actionsArchiveFixture{"first/1_step.txt", api.logs[1001]},
		actionsArchiveFixture{"1_second.txt", api.logs[1002]},
		actionsArchiveFixture{"second/2_step.txt", api.logs[1002]},
	)
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100}, true
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 3 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	var urls []string
	for _, finding := range result.Findings {
		urls = append(urls, finding.LocationURL)
	}
	want := []string{
		"https://github.com/example-owner/example-repo/actions/runs/100/job/1001#step:1:1",
		"https://github.com/example-owner/example-repo/actions/runs/100/job/1001#step:1:2",
		"https://github.com/example-owner/example-repo/actions/runs/100/job/1002#step:2:1",
	}
	if !reflect.DeepEqual(urls, want) {
		t.Fatalf("URLs = %v, want %v", urls, want)
	}
	count := 0
	for _, call := range api.calls {
		if call == "archive:100:1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("archive requests = %d, calls = %v", count, api.calls)
	}
}

func TestActionsLocationPartialMappingWarnsWithoutGuessing(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	job := fakeActionsJob(1001, 100, 1, "completed", "Build")
	job.Steps = actionsJobSteps(1, 2)
	job.HTMLURL = nil
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{job}
	first := "fixture-token-abcdefghij\n"
	api.logs[1001] = first + "fixture-token-klmnopqrst\n"
	api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_Build.txt", api.logs[1001]},
		actionsArchiveFixture{"Build/1_step.txt", first},
	)
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100}, true
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 2 || len(result.Warnings) != 2 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	base := "https://github.com/example-owner/example-repo/actions/runs/100/job/1001"
	if result.Findings[0].LocationURL != base+"#step:1:1" || result.Findings[1].LocationURL != "" ||
		result.Findings[0].JobURL != base || result.Findings[1].JobURL != base ||
		!strings.Contains(result.Warnings[0], "step log(s) are unavailable") ||
		!strings.Contains(result.Warnings[1], "1 finding") {
		t.Fatalf("findings = %+v, warnings = %v", result.Findings, result.Warnings)
	}
}

func TestActionsLocationFetchesMissingStepMetadata(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	listed := fakeActionsJob(1001, 100, 1, "completed", "Build")
	fetched := fakeActionsJob(1001, 100, 1, "completed", "Build")
	fetched.Steps = actionsJobSteps(1)
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{listed}
	api.jobs[1001] = fetched
	api.logs[1001] = "fixture-token-abcdefghij\n"
	api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_Build.txt", api.logs[1001]},
		actionsArchiveFixture{"Build/1_step.txt", api.logs[1001]},
	)
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100}, true
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 1 || !strings.HasSuffix(result.Findings[0].LocationURL, "#step:1:1") ||
		indexOfCall(api.calls, "job:1001") < indexOfCall(api.calls, "archive:100:1") {
		t.Fatalf("result = %+v, err = %v, calls = %v", result, err, api.calls)
	}
}

func TestActionsLocationStepRanges(t *testing.T) {
	tests := []struct {
		name      string
		log       string
		steps     []actionsArchiveFixture
		numbers   []int64
		wantLines map[int]string
	}{
		{
			name: "CRLF, blank lines, missing final newline and shuffled entries",
			log:  "first\r\n\r\nthird\r\nfourth\r\nlast",
			steps: []actionsArchiveFixture{
				{"Build/4_second.txt", "fourth\r\nlast"},
				{"Build/1_first.txt", "first\r\n\r\nthird\r\n"},
			},
			numbers: []int64{1, 4},
			wantLines: map[int]string{
				1: "1:1", 2: "1:2", 3: "1:3", 4: "4:1", 5: "4:2",
			},
		},
		{
			name: "job-only lines and missing step use unique alignment",
			log:  "header\nfirst\noutside\nsecond\nfooter\n",
			steps: []actionsArchiveFixture{
				{"Build/3_second.txt", "second\n"},
				{"Build/1_first.txt", "first\n"},
			},
			numbers:   []int64{1, 2, 3},
			wantLines: map[int]string{2: "1:1", 4: "3:1"},
		},
		{
			name:      "repeated complete steps use ordered concatenation",
			log:       "same\nsame\n",
			steps:     []actionsArchiveFixture{{"Build/1_a.txt", "same\n"}, {"Build/2_b.txt", "same\n"}},
			numbers:   []int64{1, 2},
			wantLines: map[int]string{1: "1:1", 2: "2:1"},
		},
		{
			name:      "repeated partial steps remain ambiguous",
			log:       "same\nsame\nunique\n",
			steps:     []actionsArchiveFixture{{"Build/1_a.txt", "same\n"}, {"Build/3_c.txt", "unique\n"}},
			numbers:   []int64{1, 2, 3},
			wantLines: map[int]string{3: "3:1"},
		},
		{
			name:      "overlapping repeated partial step remains ambiguous",
			log:       "a\na\na\nextra\n",
			steps:     []actionsArchiveFixture{{"Build/1_a.txt", "a\na\n"}},
			numbers:   []int64{1},
			wantLines: map[int]string{},
		},
		{
			name:      "overlapping partial matches are ambiguous",
			log:       "a\nb\nextra\n",
			steps:     []actionsArchiveFixture{{"Build/1_a.txt", "a\nb\n"}, {"Build/2_b.txt", "b\n"}},
			numbers:   []int64{1, 2},
			wantLines: map[int]string{},
		},
		{
			name:      "duplicate step number is ambiguous",
			log:       "a\nb\n",
			steps:     []actionsArchiveFixture{{"Build/1_a.txt", "a\n"}, {"Build/1_b.txt", "b\n"}},
			numbers:   []int64{1},
			wantLines: map[int]string{},
		},
		{
			name:      "unknown step number is not linked",
			log:       "a\nb\n",
			steps:     []actionsArchiveFixture{{"Build/1_a.txt", "a\n"}, {"Build/2_b.txt", "b\n"}},
			numbers:   []int64{1},
			wantLines: map[int]string{1: "1:1"},
		},
		{
			name:      "bare carriage return is not linked",
			log:       "progress\rupdated\nsafe\n",
			steps:     []actionsArchiveFixture{{"Build/1_a.txt", "progress\rupdated\n"}, {"Build/2_b.txt", "safe\n"}},
			numbers:   []int64{1, 2},
			wantLines: map[int]string{2: "2:1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := append([]actionsArchiveFixture{{"0_Build.txt", tt.log}}, tt.steps...)
			archive, err := newActionsLogArchive(makeActionsArchive(t, entries...))
			if err != nil {
				t.Fatal(err)
			}
			numbers := make(map[int64]bool)
			for _, number := range tt.numbers {
				numbers[number] = true
			}
			target := actionsLocationJob{logSize: int64(len(tt.log)), logHash: sha256.Sum256([]byte(tt.log))}
			ranges, err := archive.jobRanges(t.Context(), target, "Build", numbers)
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[int]string)
			for line := 1; line <= actionsLineCount([]byte(tt.log)); line++ {
				if step, ok := actionsStepForLine(ranges, line); ok {
					got[line] = fmt.Sprintf("%d:%d", step.number, line-step.firstLine+1)
				}
			}
			if !reflect.DeepEqual(got, tt.wantLines) {
				t.Fatalf("locations = %v, want %v; ranges = %+v", got, tt.wantLines, ranges)
			}
		})
	}
}

func TestActionsLocationRejectsAmbiguousJobIdentity(t *testing.T) {
	log := "fixture-token-abcdefghij\n"
	for _, tt := range []struct {
		name    string
		entries []actionsArchiveFixture
	}{
		{
			name: "different jobs have identical logs",
			entries: []actionsArchiveFixture{
				{"0_Build.txt", log}, {"Build/1_step.txt", log}, {"1_Other.txt", log},
			},
		},
		{
			name: "duplicate job paths",
			entries: []actionsArchiveFixture{
				{"0_Build.txt", log}, {"1_Build.txt", log}, {"Build/1_step.txt", log},
			},
		},
		{
			name: "job bytes changed after scanning",
			entries: []actionsArchiveFixture{
				{"0_Build.txt", "fixture-token-zyxwvutsrq\n"}, {"Build/1_step.txt", log},
			},
		},
		{
			name: "other step-only directory has duplicate candidates",
			entries: []actionsArchiveFixture{
				{"0_Build.txt", log}, {"Build/1_step.txt", log},
				{"Other/1_a.txt", log}, {"Other/1_b.txt", "different\n"},
			},
		},
		{
			name: "duplicate steps remain ambiguous even with another whole-job entry",
			entries: []actionsArchiveFixture{
				{"0_Build.txt", log}, {"Build/1_step.txt", log},
				{"1_Other.txt", "different\n"}, {"Other/1_a.txt", log}, {"Other/1_b.txt", "different\n"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			archive, err := newActionsLogArchive(makeActionsArchive(t, tt.entries...))
			if err != nil {
				t.Fatal(err)
			}
			target := actionsLocationJob{logSize: int64(len(log)), logHash: sha256.Sum256([]byte(log))}
			ranges, err := archive.jobRanges(t.Context(), target, "Build", map[int64]bool{1: true})
			if err != nil || len(ranges) != 0 {
				t.Fatalf("ranges = %+v, err = %v", ranges, err)
			}
		})
	}
}

func TestActionsLocationWarnsOnAmbiguousStepDirectory(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	job := fakeActionsJob(1001, 100, 1, "completed", "Build")
	job.Steps = actionsJobSteps(1)
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{job}
	log := "fixture-token-abcdefghij\n"
	api.logs[1001] = log
	api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
		actionsArchiveFixture{"Build/1_step.txt", log},
		actionsArchiveFixture{"Other/1_a.txt", log},
		actionsArchiveFixture{"Other/1_b.txt", "different\n"},
	)
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100}, true
	result, err := fakeScanActions(t, api, opts)
	if err != nil || len(result.Findings) != 1 || result.Findings[0].LocationURL != "" ||
		result.Findings[0].JobURL == "" || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "could not verify") {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestActionsLocationUsesStepOnlyArchivesWhenUnambiguous(t *testing.T) {
	first, second := "first\n", "fixture-token-abcdefghij\n"
	log := first + second
	for _, tt := range []struct {
		name        string
		other       []actionsArchiveFixture
		wantMatched bool
	}{
		{"step logs reconstruct the job", nil, true},
		{"different step-only job", []actionsArchiveFixture{{"Other/1_step.txt", strings.Repeat("x", len(log)-1) + "\n"}}, true},
		{"identical step-only job", []actionsArchiveFixture{{"Other/1_step.txt", log}}, false},
		{"identical whole-job entry", []actionsArchiveFixture{{"1_Other.txt", log}}, false},
		{"ambiguous numbered steps", []actionsArchiveFixture{{"Other/1_a.txt", first}, {"Other/1_b.txt", second}}, false},
		{"duplicate steps exceed job size", []actionsArchiveFixture{{"Other/1_a.txt", log}, {"Other/1_b.txt", "different\n"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entries := append([]actionsArchiveFixture{
				{"Build/2_second.txt", second}, {"Build/1_first.txt", first},
			}, tt.other...)
			archive, err := newActionsLogArchive(makeActionsArchive(t, entries...))
			if err != nil {
				t.Fatal(err)
			}
			target := actionsLocationJob{logSize: int64(len(log)), logHash: sha256.Sum256([]byte(log))}
			ranges, err := archive.jobRanges(t.Context(), target, "Build", map[int64]bool{1: true, 2: true})
			if err != nil {
				t.Fatal(err)
			}
			step, ok := actionsStepForLine(ranges, 2)
			if ok != tt.wantMatched || ok && (step.number != 2 || step.firstLine != 2) {
				t.Fatalf("step = %+v, matched = %v, want %v", step, ok, tt.wantMatched)
			}
		})
	}
}

func TestActionsLocationArchiveFailuresPreserveFindings(t *testing.T) {
	for _, tt := range []struct {
		name       string
		archiveErr error
		archive    []byte
		wantErr    string
		wantWarn   string
	}{
		{"not found", &actionsLogError{stage: "requesting archive", status: http.StatusNotFound}, nil, "", "unavailable"},
		{"gone", &actionsLogError{stage: "requesting archive", status: http.StatusGone}, nil, "", "unavailable"},
		{"forbidden", &actionsLogError{stage: "requesting archive", status: http.StatusForbidden}, nil, "HTTP 403", ""},
		{"rate limited", &actionsLogError{stage: "requesting archive", status: http.StatusTooManyRequests}, nil, "HTTP 429", ""},
		{"malformed ZIP", nil, []byte("not a ZIP"), "invalid ZIP", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := newFakeActionsAPI()
			api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
			job := fakeActionsJob(1001, 100, 1, "completed", "Build")
			job.Steps = actionsJobSteps(1)
			api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{job}
			api.logs[1001] = "fixture-token-abcdefghij\n"
			key := actionsAttemptKey{100, 1}
			api.archiveErrors[key] = tt.archiveErr
			api.archives[key] = tt.archive
			opts := testActionsOptions()
			opts.Runs, opts.LocationURL = []int64{100}, true
			result, err := fakeScanActions(t, api, opts)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if len(result.Findings) != 1 || result.Findings[0].LocationURL != "" {
				t.Fatalf("findings were lost or linked incorrectly: %+v", result.Findings)
			}
			if tt.wantWarn != "" && (len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], tt.wantWarn)) {
				t.Fatalf("warnings = %v, want %q", result.Warnings, tt.wantWarn)
			}
		})
	}
}

func TestActionsLocationUnavailableArchiveUsesJobURL(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	job := fakeActionsJob(1001, 100, 1, "completed", "Build")
	job.Steps = actionsJobSteps(1)
	job.HTMLURL = nil
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{job}
	api.logs[1001] = "fixture-token-abcdefghij\n"
	api.archiveErrors[actionsAttemptKey{100, 1}] = &actionsLogError{stage: "requesting archive", status: http.StatusNotFound}
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100}, true
	result, err := fakeScanActions(t, api, opts)
	want := "https://github.com/example-owner/example-repo/actions/runs/100/job/1001"
	if err != nil || len(result.Findings) != 1 || result.Findings[0].JobURL != want || len(result.Warnings) != 1 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestActionsLocationMasksRepositoryMetadata(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	job := fakeActionsJob(1001, 100, 1, "completed", "Build")
	job.Steps = actionsJobSteps(1)
	job.HTMLURL = nil
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{job}
	api.logs[1001] = "fixture-token-abcdefghij\n"
	api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_Build.txt", api.logs[1001]},
		actionsArchiveFixture{"Build/1_step.txt", api.logs[1001]},
	)
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100}, true
	repo := fakeActionsRepository()
	repo.Owner = "fixture-token-abcdefghij"
	result, err := scanActions(t.Context(), api, repo, opts, fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || len(result.Findings) != 1 || result.Findings[0].LocationURL == "" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	data, err := json.Marshal(result.Findings)
	if err != nil || strings.Contains(string(data), repo.Owner) {
		t.Fatalf("repository metadata leaked: %s, err = %v", data, err)
	}
}

func TestActionsLocationStopsAfterScanError(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	first := fakeActionsJob(1001, 100, 1, "completed", "first")
	first.Steps = actionsJobSteps(1)
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{
		first, fakeActionsJob(1002, 100, 1, "completed", "second"),
	}
	api.logs[1001] = "fixture-token-abcdefghij\n"
	api.logErrors[1002] = &actionsLogError{stage: "job log", status: http.StatusForbidden}
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100}, true
	result, err := fakeScanActions(t, api, opts)
	if err == nil || len(result.Findings) != 1 || len(result.Warnings) != 1 ||
		!strings.Contains(result.Warnings[0], "scanning stopped") || indexOfCall(api.calls, "archive:100:1") >= 0 {
		t.Fatalf("result = %+v, err = %v, calls = %v", result, err, api.calls)
	}
}

func TestActionsLocationContinuesAfterRecoverableErrors(t *testing.T) {
	api := newFakeActionsAPI()
	for _, id := range []int64{100, 200} {
		api.runs[id] = fakeActionsRun(id, 1, 1, "completed", "Build", ".github/workflows/build.yml")
		job := fakeActionsJob(id*10+1, id, 1, "completed", "first")
		job.Steps = actionsJobSteps(1)
		api.attempts[actionsAttemptKey{id, 1}] = []*github.WorkflowJob{job}
		api.logs[id*10+1] = "fixture-token-abcdefghij\n"
	}
	api.archiveErrors[actionsAttemptKey{100, 1}] = &actionsLogError{stage: "run log archive", status: http.StatusBadGateway}
	api.archiveErrors[actionsAttemptKey{200, 1}] = &actionsLogError{stage: "run log archive", status: http.StatusBadGateway}
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100, 200}, true
	result, err := fakeScanActions(t, api, opts)
	if err == nil || !strings.Contains(err.Error(), "2 error(s) occurred") || len(result.Findings) != 2 ||
		indexOfCall(api.calls, "archive:100:1") < 0 || indexOfCall(api.calls, "archive:200:1") < 0 {
		t.Fatalf("result = %+v, err = %v, calls = %v", result, err, api.calls)
	}
}

func TestActionsLocationUsesVerifiedRepositoryHost(t *testing.T) {
	repo := fakeActionsRepository()
	repo.Host = "github.example.invalid:8443"
	got, err := actionsJobLocationURL(repo, 100, 1001, 27, 520)
	want := "https://github.example.invalid:8443/example-owner/example-repo/actions/runs/100/job/1001#step:27:520"
	if err != nil || got != want {
		t.Fatalf("URL = %q, err = %v", got, err)
	}
	repo.Host = "https://example.invalid"
	if _, err := actionsJobLocationURL(repo, 100, 1001, 27, 520); err == nil {
		t.Fatal("invalid host was accepted")
	}
}

func TestActionsLocationJobNameForArchive(t *testing.T) {
	for _, tt := range []struct {
		input, want string
	}{
		{" Build / test: stage ", "Build  test stage"},
		{strings.Repeat("a", 91), strings.Repeat("a", 90)},
		{strings.Repeat("a", 89) + "🙂", strings.Repeat("a", 89) + "�"},
	} {
		if got := actionsArchiveJobName(tt.input); got != tt.want {
			t.Fatalf("name = %q, want %q", got, tt.want)
		}
	}
}

func TestActionsLocationReadHonorsCancellation(t *testing.T) {
	archive, err := newActionsLogArchive(makeActionsArchive(t, actionsArchiveFixture{"0_Build.txt", "abc"}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := archive.read(ctx, archive.jobs["Build"][0]); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func TestActionsLocationArchiveLimitBoundaries(t *testing.T) {
	if err := validateActionsArchiveSize(maxActionsArchiveBytes); err != nil {
		t.Fatal(err)
	}
	if err := validateActionsArchiveSize(maxActionsArchiveBytes + 1); err == nil {
		t.Fatal("archive above the byte limit was accepted")
	}
	if err := validateActionsArchiveEntries(maxActionsArchiveEntries); err != nil {
		t.Fatal(err)
	}
	if err := validateActionsArchiveEntries(maxActionsArchiveEntries + 1); err == nil {
		t.Fatal("archive above the entry count limit was accepted")
	}
	if err := validateActionsArchiveEntry(uint64(maxActionsArchiveEntryBytes), maxActionsArchiveExpandedBytes); err != nil {
		t.Fatal(err)
	}
	if err := validateActionsArchiveEntry(uint64(maxActionsArchiveEntryBytes+1), maxActionsArchiveExpandedBytes); err == nil {
		t.Fatal("entry above the byte limit was accepted")
	}
	if err := validateActionsArchiveEntry(5, 5); err != nil {
		t.Fatal(err)
	}
	if err := validateActionsArchiveEntry(6, 5); err == nil {
		t.Fatal("entry above the remaining expanded-byte budget was accepted")
	}
	remaining := maxActionsArchiveSearchBytes
	if err := reserveActionsArchiveSearch(maxActionsArchiveSearchBytes/2, &remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining search budget = %d, err = %v", remaining, err)
	}
	if err := reserveActionsArchiveSearch(1, &remaining); err == nil {
		t.Fatal("search above the byte budget was accepted")
	}
}

func TestActionsLocationArchiveReadEnforcesProcessingBudget(t *testing.T) {
	archive, err := newActionsLogArchive(makeActionsArchive(t,
		actionsArchiveFixture{"0_Build.txt", "12345"},
		actionsArchiveFixture{"1_Other.txt", "6"},
	))
	if err != nil {
		t.Fatal(err)
	}
	archive.remaining = 5
	if content, err := archive.read(t.Context(), archive.jobs["Build"][0]); err != nil || string(content) != "12345" || archive.remaining != 0 {
		t.Fatalf("content = %q, remaining = %d, err = %v", content, archive.remaining, err)
	}
	if _, err := archive.read(t.Context(), archive.jobs["Other"][0]); err == nil || !strings.Contains(err.Error(), "processing limit") {
		t.Fatalf("expected processing-limit error, got %v", err)
	}
	archive.remaining = maxActionsArchiveExpandedBytes
	archive.jobs["Other"][0].UncompressedSize64 = uint64(maxActionsArchiveEntryBytes + 1)
	if _, err := archive.read(t.Context(), archive.jobs["Other"][0]); err == nil || !strings.Contains(err.Error(), "entry exceeds") {
		t.Fatalf("expected entry-limit error, got %v", err)
	}
}

func TestActionsLocationArchiveEntryCount(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a large synthetic ZIP directory")
	}
	for _, tt := range []struct {
		count   int
		wantErr bool
	}{
		{maxActionsArchiveEntries, false},
		{maxActionsArchiveEntries + 1, true},
	} {
		t.Run(fmt.Sprint(tt.count), func(t *testing.T) {
			var data bytes.Buffer
			writer := zip.NewWriter(&data)
			for i := 0; i < tt.count; i++ {
				if _, err := writer.CreateHeader(&zip.FileHeader{Name: "0_Build.txt", Method: zip.Store}); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			_, err := newActionsLogArchive(data.Bytes())
			if (err != nil) != tt.wantErr || tt.wantErr && !strings.Contains(err.Error(), "entry limit") {
				t.Fatalf("count = %d, err = %v", tt.count, err)
			}
		})
	}
}

func TestActionsLocationFallbackSearchBudget(t *testing.T) {
	const logSize = 1 << 20
	log := bytes.Repeat([]byte{'a'}, logSize)
	stepsAtLimit := int(maxActionsArchiveSearchBytes / (2 * logSize))
	for _, tt := range []struct {
		steps   int
		wantErr bool
	}{
		{stepsAtLimit, false},
		{stepsAtLimit + 1, true},
	} {
		t.Run(fmt.Sprint(tt.steps), func(t *testing.T) {
			entries := make([]actionsArchiveFixture, 0, tt.steps)
			for i := 1; i <= tt.steps; i++ {
				entries = append(entries, actionsArchiveFixture{fmt.Sprintf("Build/%d_step.txt", i), "z\n"})
			}
			archive, err := newActionsLogArchive(makeActionsArchive(t, entries...))
			if err != nil {
				t.Fatal(err)
			}
			_, err = archive.stepRanges(t.Context(), log, sortedActionsArchiveSteps(archive.steps["Build"]), nil)
			if (err != nil) != tt.wantErr || tt.wantErr && !strings.Contains(err.Error(), "search limit") {
				t.Fatalf("steps = %d, err = %v", tt.steps, err)
			}
		})
	}
}

type actionsCancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *actionsCancelReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.cancel()
	return n, err
}

func TestActionsLocationReadHonorsMidStreamCancellation(t *testing.T) {
	content := makeActionsArchive(t, actionsArchiveFixture{"0_Build.txt", strings.Repeat("data", 1024)})
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader.RegisterDecompressor(zip.Deflate, func(source io.Reader) io.ReadCloser {
		return &actionsCancelReadCloser{ReadCloser: flate.NewReader(source), cancel: cancel}
	})
	archive := &actionsLogArchive{remaining: maxActionsArchiveExpandedBytes}
	if _, err := archive.read(ctx, reader.File[0]); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation during decompression", err)
	}
}

type cancelActionsArchiveAPI struct {
	*fakeActionsAPI
	cancel context.CancelFunc
}

func (a *cancelActionsArchiveAPI) getRunLogArchive(ctx context.Context, runID, attempt int64) ([]byte, error) {
	content, err := a.fakeActionsAPI.getRunLogArchive(ctx, runID, attempt)
	a.cancel()
	return content, err
}

func TestActionsLocationCancellationPreservesFindings(t *testing.T) {
	api := newFakeActionsAPI()
	api.runs[100] = fakeActionsRun(100, 1, 1, "completed", "Build", ".github/workflows/build.yml")
	job := fakeActionsJob(1001, 100, 1, "completed", "Build")
	job.Steps = actionsJobSteps(1)
	api.attempts[actionsAttemptKey{100, 1}] = []*github.WorkflowJob{job}
	api.logs[1001] = "fixture-token-abcdefghij\n"
	api.archives[actionsAttemptKey{100, 1}] = makeActionsArchive(t,
		actionsArchiveFixture{"0_Build.txt", api.logs[1001]},
		actionsArchiveFixture{"Build/1_step.txt", api.logs[1001]},
	)
	opts := testActionsOptions()
	opts.Runs, opts.LocationURL = []int64{100}, true
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result, err := scanActions(ctx, &cancelActionsArchiveAPI{fakeActionsAPI: api, cancel: cancel},
		fakeActionsRepository(), opts, fakeActionsScanner(t, false), newActionsRateLimiter(0, nil))
	if err != nil || !result.Interrupted || len(result.Findings) != 1 || result.Findings[0].LocationURL != "" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestActionsLocationStepOnlyJobCanExceedEntryLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("requires processing a large synthetic log")
	}
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	hash := sha256.New()
	chunk := bytes.Repeat([]byte{'a'}, 64<<10)
	partSize := maxActionsArchiveEntryBytes / 2
	for _, name := range []string{"Build/1_first.txt", "Build/2_second.txt"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		output := io.MultiWriter(entry, hash)
		for written := int64(0); written < partSize; {
			block := chunk
			if remaining := partSize - written; remaining < int64(len(block)) {
				block = block[:remaining]
			}
			if _, err := output.Write(block); err != nil {
				t.Fatal(err)
			}
			written += int64(len(block))
		}
		if _, err := output.Write([]byte("\n")); err != nil {
			t.Fatal(err)
		}
		chunk[0] = 'b'
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive, err := newActionsLogArchive(data.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	target := actionsLocationJob{logSize: 2 * (partSize + 1)}
	copy(target.logHash[:], hash.Sum(nil))
	ranges, err := archive.jobRanges(t.Context(), target, "Build", map[int64]bool{1: true, 2: true})
	if err != nil {
		t.Fatal(err)
	}
	step, ok := actionsStepForLine(ranges, 2)
	if !ok || step.number != 2 || step.firstLine != 2 {
		t.Fatalf("ranges = %+v, step = %+v, matched = %v", ranges, step, ok)
	}
}
