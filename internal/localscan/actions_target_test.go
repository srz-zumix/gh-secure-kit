package localscan

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/repository"
)

func TestParseActionsRunTargets(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		runs    []int64
		targets []ActionsRunTarget
		repo    *repository.Repository
	}{
		{
			name:    "repeated and comma-separated IDs",
			input:   []string{"12,34", "34", "56"},
			runs:    []int64{12, 34, 56},
			targets: []ActionsRunTarget{{RunID: 12}, {RunID: 34}, {RunID: 56}},
		},
		{
			name:    "run attempt and job URLs with query and fragment",
			input:   []string{"https://github.com/example-owner/example-repo/actions/runs/12?values=one,two#logs", "https://GitHub.com:443/example-owner/example-repo/actions/runs/12/attempts/2", "https://github.com/example-owner/example-repo/actions/runs/34/job/345", "https://github.com/example-owner/example-repo/actions/runs/34/attempts/3/job/346"},
			runs:    []int64{12, 34},
			targets: []ActionsRunTarget{{RunID: 12}, {RunID: 12, Attempt: 2}, {RunID: 34, JobID: 345}, {RunID: 34, Attempt: 3, JobID: 346}},
			repo:    &repository.Repository{Host: "github.com", Owner: "example-owner", Name: "example-repo"},
		},
		{
			name:    "enterprise port and case-insensitive repository",
			input:   []string{"HTTPS://GitHub.Example.invalid:8443/Example-Owner/Example-Repo/actions/runs/99/", "https://github.example.invalid:8443/example-owner/example-repo/actions/runs/99/job/991"},
			runs:    []int64{99},
			targets: []ActionsRunTarget{{RunID: 99}, {RunID: 99, JobID: 991}},
			repo:    &repository.Repository{Host: "github.example.invalid:8443", Owner: "Example-Owner", Name: "Example-Repo"},
		},
		{
			name:    "numeric and URL targets deduplicate",
			input:   []string{"12", "https://github.com/example-owner/example-repo/actions/runs/12", "https://github.com/example-owner/example-repo/actions/runs/12/job/121", "https://github.com/example-owner/example-repo/actions/runs/12/job/121"},
			runs:    []int64{12},
			targets: []ActionsRunTarget{{RunID: 12}, {RunID: 12, JobID: 121}},
			repo:    &repository.Repository{Host: "github.com", Owner: "example-owner", Name: "example-repo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseActionsRunTargets(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Runs, tt.runs) || !reflect.DeepEqual(got.Targets, tt.targets) || !reflect.DeepEqual(got.Repository, tt.repo) {
				t.Fatalf("got %+v, want runs %v, targets %v, repository %+v", got, tt.runs, tt.targets, tt.repo)
			}
		})
	}
}

func TestParseActionsRunTargetsRejectsInvalidInputs(t *testing.T) {
	const base = "https://github.com/example-owner/example-repo/actions/runs/"
	const secret = "synthetic-sensitive-value"
	tests := []struct {
		name  string
		input []string
	}{
		{"empty", []string{""}},
		{"empty comma item", []string{"12,,34"}},
		{"zero run", []string{"0"}},
		{"negative run", []string{"-3"}},
		{"overflow run", []string{"9223372036854775808"}},
		{"invalid scheme", []string{"http://github.com/example-owner/example-repo/actions/runs/12?" + secret}},
		{"userinfo", []string{"https://user:" + secret + "@github.com/example-owner/example-repo/actions/runs/12"}},
		{"malformed URL", []string{base + "12%zz?" + secret}},
		{"wrong path", []string{"https://github.com/example-owner/example-repo/pull/12?" + secret}},
		{"extra path", []string{base + "12/other?" + secret}},
		{"zero URL run", []string{base + "0?" + secret}},
		{"overflow URL run", []string{base + "9223372036854775808?" + secret}},
		{"zero attempt", []string{base + "12/attempts/0?" + secret}},
		{"overflow attempt", []string{base + "12/attempts/9223372036854775808?" + secret}},
		{"zero job", []string{base + "12/job/0?" + secret}},
		{"overflow job", []string{base + "12/job/9223372036854775808?" + secret}},
		{"encoded separator", []string{base + "12%2fjob%2f123?" + secret}},
		{"double-encoded separator", []string{base + "12%252fjob%252f123?" + secret}},
		{"encoded backslash", []string{base + "12%5cjob%5c123?" + secret}},
		{"double slash", []string{"https://github.com/example-owner//example-repo/actions/runs/12?" + secret}},
		{"path traversal", []string{"https://github.com/example-owner/%2e%2e/actions/runs/12?" + secret}},
		{"invalid port", []string{"https://github.com:99999/example-owner/example-repo/actions/runs/12?" + secret}},
		{"different repository", []string{base + "12", "https://github.com/example-owner/other-repo/actions/runs/34?" + secret}},
		{"different host", []string{base + "12", "https://github.example.invalid/example-owner/example-repo/actions/runs/34?" + secret}},
		{"same job in different runs", []string{base + "12/job/123", base + "34/job/123?" + secret}},
		{"same job in different attempts", []string{base + "12/attempts/1/job/123", base + "12/attempts/2/job/123?" + secret}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseActionsRunTargets(tt.input)
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error disclosed URL data: %v", err)
			}
		})
	}
}

func TestResolveActionsRepository(t *testing.T) {
	t.Setenv("GH_HOST", "github.com")
	inferred := &repository.Repository{Host: "github.com", Owner: "example-owner", Name: "example-repo"}
	tests := []struct {
		name     string
		input    string
		inferred *repository.Repository
		want     repository.Repository
		wantErr  bool
	}{
		{"URL without explicit repository", "", inferred, *inferred, false},
		{"case-insensitive explicit repository", "GitHub.com/Example-Owner/Example-Repo", inferred, *inferred, false},
		{"default port", "github.com:443/example-owner/example-repo", inferred, *inferred, false},
		{"default host", "example-owner/example-repo", inferred, *inferred, false},
		{"different repository", "github.com/example-owner/other", inferred, repository.Repository{}, true},
		{"different host", "github.example.invalid/example-owner/example-repo", inferred, repository.Repository{}, true},
		{"no URL", "github.com/example-owner/example-repo", nil, *inferred, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveActionsRepository(tt.input, tt.inferred)
			if (err != nil) != tt.wantErr || err == nil && got != tt.want {
				t.Fatalf("got %+v, err %v, want %+v, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestActionsRunTargetValidation(t *testing.T) {
	tests := []struct {
		name    string
		runs    []int64
		targets []ActionsRunTarget
		wantErr bool
	}{
		{"valid", []int64{12}, []ActionsRunTarget{{RunID: 12, Attempt: 2, JobID: 123}}, false},
		{"run missing", nil, []ActionsRunTarget{{RunID: 12}}, true},
		{"different run", []int64{12}, []ActionsRunTarget{{RunID: 34}}, true},
		{"negative attempt", []int64{12}, []ActionsRunTarget{{RunID: 12, Attempt: -1}}, true},
		{"negative job", []int64{12}, []ActionsRunTarget{{RunID: 12, JobID: -1}}, true},
		{"job in two runs", []int64{12, 34}, []ActionsRunTarget{{RunID: 12, JobID: 123}, {RunID: 34, JobID: 123}}, true},
		{"job in two attempts", []int64{12}, []ActionsRunTarget{{RunID: 12, Attempt: 1, JobID: 123}, {RunID: 12, Attempt: 2, JobID: 123}}, true},
		{"specified and unspecified attempt", []int64{12}, []ActionsRunTarget{{RunID: 12, JobID: 123}, {RunID: 12, Attempt: 2, JobID: 123}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testActionsOptions()
			opts.Runs, opts.RunTargets = tt.runs, tt.targets
			if err := opts.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("got %v, want error %v", err, tt.wantErr)
			}
		})
	}
}
