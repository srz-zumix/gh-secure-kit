package localscan

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

func TestGroupedFindingRendering(t *testing.T) {
	for name, renderFindings := range map[string]func(*render.Renderer, []Finding) error{
		"local": RenderLocalFindings, "copilot": RenderCopilotFindings,
	} {
		t.Run(name, func(t *testing.T) {
			output := render.NewStringRenderer(nil)
			findings := []Finding{
				{SessionID: "session-example", SessionName: "Example\nsession", Commit: "0123456789abcdef", File: "events.jsonl", StartLine: 9, PatternID: "example", Secret: "masked\r\nvalue", Validity: ValidityInactive, Date: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
				{SessionID: "session-example", Commit: "0123456789abcdef", File: "events.jsonl", StartLine: 2, PatternID: "example", Secret: "masked-other"},
			}
			if err := renderFindings(&output.Renderer, findings); err != nil {
				t.Fatal(err)
			}
			text := output.Stdout.String()
			for _, want := range []string{"2 findings in 1 ", "masked\\r\\nvalue", "[inactive]"} {
				if !strings.Contains(text, want) {
					t.Fatalf("missing %q in %q", want, text)
				}
			}
			if strings.Count(text, "events.jsonl") != 1 || strings.Index(text, "masked-other") > strings.Index(text, "masked\\r\\nvalue") {
				t.Fatalf("files were not grouped with sorted lines: %q", text)
			}
			if findings[0].StartLine != 9 || strings.Contains(text, "\x1b[") {
				t.Fatal("rendering changed input order or added non-TTY ANSI escapes")
			}
		})
	}
}

func TestCopilotFindingGroups(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	findings := []Finding{
		{SessionID: "session-b", SessionName: "Older", Source: "cli-sessions", File: "old.jsonl", Secret: "old", Date: older},
		{SessionID: "session-a", File: filepath.Join(home, "first.jsonl"), StartLine: 9, Secret: "last-line", Date: older},
		{SessionID: "session-a", SessionName: "Latest\nsession", Source: "vscode-chat", Workspace: filepath.Join(home, "project"), File: filepath.Join(home, "second.jsonl"), Secret: "second-file", Date: newer},
		{SessionID: "session-a", File: filepath.Join(home, "first.jsonl"), StartLine: 2, Secret: "first-line", Date: older},
		{SessionID: "session-c", File: "tie.jsonl", Secret: "tie", Date: newer},
	}
	original := slices.Clone(findings)
	output := render.NewStringRenderer(nil)
	if err := RenderCopilotFindings(&output.Renderer, findings); err != nil {
		t.Fatal(err)
	}
	text := output.Stdout.String()
	for _, want := range []string{
		"* Latest\\nsession", "Session: session-a", "Source: vscode-chat",
		"Workspace: ~/project", "Updated: 2026-01-01 01:00:00 UTC", "~/first.jsonl",
		"* (no name)", "5 findings in 3 sessions",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	previous := -1
	for _, want := range []string{"session-a", "~/first.jsonl", "first-line", "last-line", "~/second.jsonl", "session-c", "session-b"} {
		position := strings.Index(text, want)
		if position <= previous {
			t.Fatalf("incorrect group, file or line order for %q in %q", want, text)
		}
		previous = position
	}
	if strings.Contains(text, home) || strings.Count(text, "Session: session-a") != 1 || !reflect.DeepEqual(findings, original) {
		t.Fatal("home path was not shortened, metadata was repeated, or input changed")
	}
}

func TestMissingFindingGroups(t *testing.T) {
	for name, renderFindings := range map[string]func(*render.Renderer, []Finding) error{
		"local": RenderLocalFindings, "copilot": RenderCopilotFindings,
	} {
		t.Run(name, func(t *testing.T) {
			output := render.NewStringRenderer(nil)
			findings := []Finding{
				{File: "first.txt", PatternID: "example", Secret: "masked"},
				{File: "second.txt", PatternID: "example", Secret: "masked"},
				{File: "first.txt", PatternID: "example", Secret: "masked-other"},
			}
			if err := renderFindings(&output.Renderer, findings); err != nil {
				t.Fatal(err)
			}
			text := output.Stdout.String()
			want := "3 findings in 2 files"
			if name == "copilot" {
				want = "3 findings in 2 sessionless files"
				if strings.Count(text, "Session: (no session)") != 2 {
					t.Fatalf("sessionless files were combined: %q", text)
				}
			}
			if !strings.Contains(text, want) || strings.Contains(text, "Commit") || strings.Count(text, "first.txt") != 1 {
				t.Fatalf("unexpected fallback output: %q", text)
			}
		})
	}
}

func TestLocalCommitFindingGroups(t *testing.T) {
	output := render.NewStringRenderer(nil)
	findings := []Finding{
		{Commit: "abcdef0123451111", Author: "Example\rauthor", Date: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), File: "first.txt", Secret: "first"},
		{Commit: "abcdef0123452222", File: "second.txt", Secret: "second"},
		{Commit: "abcdef0123451111", File: "first.txt", Secret: "same-commit"},
		{File: "staged.txt", Secret: "staged"},
	}
	if err := RenderLocalFindings(&output.Renderer, findings); err != nil {
		t.Fatal(err)
	}
	text := output.Stdout.String()
	for _, want := range []string{"Author: Example\\rauthor", "Date: 2026-01-01 00:00:00 UTC", "4 findings in 2 commits and 1 uncommitted file"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	if strings.Count(text, "* Commit abcdef012345\n") != 2 || strings.Contains(text, "1111") || strings.Contains(text, "2222") {
		t.Fatalf("full commit IDs were not grouped independently: %q", text)
	}
	if strings.Index(text, "same-commit") > strings.Index(text, "second.txt") {
		t.Fatalf("commit groups did not preserve first-appearance order: %q", text)
	}
}

func TestFindingExportsUnchanged(t *testing.T) {
	for name, renderFindings := range map[string]func(*render.Renderer, []Finding) error{
		"local": RenderLocalFindings, "copilot": RenderCopilotFindings,
	} {
		t.Run(name, func(t *testing.T) {
			for _, findings := range [][]Finding{
				nil, {},
				{
					{SessionID: "session-z", SessionName: "First\nsession", File: "last.txt", Commit: "abcdef0123456789", TokenType: "example_type", StartLine: 9, Secret: "masked\nvalue", Validity: ValidityInactive, rawSecret: "private-value"},
					{SessionID: "session-a", File: "first.txt", StartLine: 1, Secret: "masked-other"},
				},
			} {
				output := render.NewStringRenderer(cmdutil.NewJSONExporter())
				if err := renderFindings(&output.Renderer, findings); err != nil {
					t.Fatal(err)
				}
				if findings == nil {
					findings = []Finding{}
				}
				want, err := json.Marshal(findings)
				if err != nil {
					t.Fatal(err)
				}
				if got := strings.TrimSpace(output.Stdout.String()); got != string(want) {
					t.Fatalf("export changed: got %s, want %s", got, want)
				}
			}
		})
	}
}

type findingErrorWriter struct{}

func (findingErrorWriter) Fd() uintptr {
	return 0
}

func (findingErrorWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestFindingEmptyOutputAndWriteError(t *testing.T) {
	for name, renderFindings := range map[string]func(*render.Renderer, []Finding) error{
		"local": RenderLocalFindings, "copilot": RenderCopilotFindings,
	} {
		t.Run(name, func(t *testing.T) {
			output := render.NewStringRenderer(nil)
			if err := renderFindings(&output.Renderer, nil); err != nil || output.Stdout.Len() != 0 {
				t.Fatalf("unexpected empty result: %q, %v", output.Stdout.String(), err)
			}
			output.Renderer.IO.Out = findingErrorWriter{}
			if err := renderFindings(&output.Renderer, []Finding{{File: "example.txt"}}); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("write error was not propagated: %v", err)
			}
		})
	}
}
