package localscan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/srz-zumix/go-gh-extension/pkg/copilotext"
)

const testSessionID = "11111111-2222-3333-4444-555555555555"

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCopilotSourceDecodesJSONAndReadsRawLogs(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, "session-state", testSessionID, "events.jsonl"),
		`{"text":"`+testGitHubToken+`"}`+"\n")
	writeTestFile(t, filepath.Join(home, "logs", "process-1-2.log"), "token "+testGitHubToken+"\n")

	frags, err := NewCopilotSource(copilotext.LogOptions{
		CopilotHome:   home,
		VSCodeUserDir: filepath.Join(home, "no-vscode"),
	}).Fragments()
	if err != nil {
		t.Fatalf("Fragments() error = %v", err)
	}

	var jsonFrag, rawFrag *Fragment
	for i := range frags {
		switch {
		case frags[i].Content == `"text": "`+testGitHubToken+`"`:
			jsonFrag = &frags[i]
		case frags[i].Source == copilotext.LogSourceCLILogs:
			rawFrag = &frags[i]
		}
	}
	if jsonFrag == nil || jsonFrag.Source != copilotext.LogSourceCLISessions || jsonFrag.SessionID != testSessionID || jsonFrag.Line != 1 {
		t.Errorf("JSON fragment = %+v, want a decoded value from session %s line 1", jsonFrag, testSessionID)
	}
	if rawFrag == nil || rawFrag.Line != 0 || rawFrag.SessionID != "" {
		t.Errorf("raw log fragment = %+v, want whole-file content without a fixed line", rawFrag)
	}
}

func TestCopilotSourceSkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "blob.log"), "\x00"+testGitHubToken)

	frags, err := NewCopilotSource(copilotext.LogOptions{Paths: []string{dir}}).Fragments()
	if err != nil || len(frags) != 0 {
		t.Fatalf("Fragments() = %v, %v; want no fragments and no error", frags, err)
	}
}

func TestCopilotSourceMissingPathIsAnError(t *testing.T) {
	_, err := NewCopilotSource(copilotext.LogOptions{Paths: []string{filepath.Join(t.TempDir(), "missing")}}).Fragments()
	if err == nil {
		t.Fatal("expected error for a missing path, got nil")
	}
}

func TestCopilotSourceIncludesSessionContext(t *testing.T) {
	for _, kind := range []string{"cli", "cli-summary", "vscode", "vscode-json", "empty-window", "malformed", "missing"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, testSessionID)
			switch kind {
			case "cli":
				writeTestFile(t, filepath.Join(dir, "workspace.yaml"), "cwd: /example/project\nname: Saved task\nsummary: Generated task\n")
			case "cli-summary":
				writeTestFile(t, filepath.Join(dir, "workspace.yaml"), "cwd: /example/project\nsummary: Saved task\n")
			case "vscode", "vscode-json":
				workspace := filepath.Join(root, "workspaceStorage", "example-workspace")
				writeTestFile(t, filepath.Join(workspace, "workspace.json"), `{"folder":"file:///example/project"}`)
				if kind == "vscode-json" {
					writeTestFile(t, filepath.Join(workspace, "chatSessions", testSessionID+".json"), `{"customTitle":"Saved task"}`)
				} else {
					writeTestFile(t, filepath.Join(workspace, "chatSessions", testSessionID+".jsonl"), "{\"kind\":0,\"v\":{\"customTitle\":\"Old task\"}}\n{\"kind\":1,\"k\":[\"customTitle\"],\"v\":\"Saved task\"}\n")
				}
				dir = filepath.Join(workspace, "GitHub.copilot-chat", "debug-logs", testSessionID)
			case "empty-window":
				dir = filepath.Join(root, "User", "globalStorage", "github.copilot-chat", "debug-logs", testSessionID)
				writeTestFile(t, filepath.Join(root, "User", "globalStorage", "emptyWindowChatSessions", testSessionID+".json"), `{"customTitle":"Saved task"}`)
			case "malformed":
				writeTestFile(t, filepath.Join(dir, "workspace.yaml"), "name: [invalid\n")
			}
			writeTestFile(t, filepath.Join(dir, "events.jsonl"), `{"text":"`+testGitHubToken+`"}`)
			scanner, err := NewScanner(nil, false)
			if err != nil {
				t.Fatal(err)
			}
			findings, err := Scan(NewCopilotSource(copilotext.LogOptions{Paths: []string{root}}), scanner)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			wantWorkspace := "/example/project"
			wantName := "Saved task"
			if kind == "missing" || kind == "malformed" || kind == "empty-window" {
				wantWorkspace = ""
			}
			if kind == "missing" || kind == "malformed" {
				wantName = ""
			}
			finding := findings[0]
			if finding.Workspace != wantWorkspace || finding.SessionID != testSessionID || finding.Date.IsZero() || finding.SessionName != wantName {
				t.Fatal("session context was not preserved")
			}
		})
	}
}

func TestCopilotSessionNameRedaction(t *testing.T) {
	for _, showSecret := range []bool{false, true} {
		scanner, err := NewScanner(nil, showSecret)
		if err != nil {
			t.Fatal(err)
		}
		findings := scanner.ScanFragment(Fragment{Content: testGitHubToken, SessionName: "Investigate " + testGitHubToken})
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		want := "Investigate " + redact(testGitHubToken)
		if showSecret {
			want = "Investigate " + testGitHubToken
		}
		if findings[0].SessionName != want {
			t.Fatalf("incorrect session name redaction with showSecret=%v", showSecret)
		}
	}
}
