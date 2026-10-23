package localscan

import (
	"encoding/json"
	"strings"
	"testing"
)

const testGitHubToken = "ghp_0123456789abcdefghijABCDEFGHIJ012345"

func collectJSONFragments(t *testing.T, content string, jsonl bool) []Fragment {
	t.Helper()
	var got []Fragment
	base := Fragment{FilePath: "log", Source: "src", SessionID: "sid"}
	err := streamJSONFragments(content, jsonl, base, func(f Fragment) error {
		got = append(got, f)
		return nil
	})
	if err != nil {
		t.Fatalf("streamJSONFragments() error = %v", err)
	}
	return got
}

func TestStreamJSONFragmentsDecodesEscapedPrivateKey(t *testing.T) {
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("A", 64) + "\n-----END RSA PRIVATE KEY-----"
	doc, err := json.Marshal(map[string]string{"text": key})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewScanner(nil, true)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}

	var findings []Finding
	for _, f := range collectJSONFragments(t, string(doc), true) {
		findings = append(findings, s.ScanFragment(f)...)
	}
	if len(findings) != 1 || findings[0].PatternID != "rsa_private_key" {
		t.Fatalf("findings = %+v, want one rsa_private_key", findings)
	}
}

func TestStreamJSONFragmentsReportsJSONLLine(t *testing.T) {
	content := `{"a":"nothing"}` + "\n\n" + `{"b":{"c":"` + testGitHubToken + `"}}` + "\n"
	s, err := NewScanner(nil, true)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	var findings []Finding
	for _, f := range collectJSONFragments(t, content, true) {
		findings = append(findings, s.ScanFragment(f)...)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].StartLine != 3 {
		t.Errorf("StartLine = %d, want 3", findings[0].StartLine)
	}
	if findings[0].Source != "src" || findings[0].SessionID != "sid" {
		t.Errorf("source/session not propagated: %+v", findings[0])
	}
}

func TestStreamJSONFragmentsReportsJSONLineFromOffset(t *testing.T) {
	content := "{\n  \"a\": \"x\",\n  \"b\": \"" + testGitHubToken + "\"\n}\n"
	frags := collectJSONFragments(t, content, false)
	var line int
	for _, f := range frags {
		if strings.Contains(f.Content, testGitHubToken) {
			line = f.Line
		}
	}
	if line != 3 {
		t.Errorf("Line = %d, want 3", line)
	}
}

func TestStreamJSONFragmentsFallsBackToRawText(t *testing.T) {
	t.Run("jsonl invalid line", func(t *testing.T) {
		content := "{\"a\":\"ok\"}\nnot json " + testGitHubToken + "\n"
		frags := collectJSONFragments(t, content, true)
		var raw *Fragment
		for i := range frags {
			if strings.Contains(frags[i].Content, "not json") {
				raw = &frags[i]
			}
		}
		if raw == nil || raw.Line != 2 {
			t.Fatalf("raw line fragment = %+v, want Line 2", raw)
		}
	})
	t.Run("json invalid document", func(t *testing.T) {
		content := "{broken " + testGitHubToken
		frags := collectJSONFragments(t, content, false)
		if len(frags) != 1 || frags[0].Content != content || frags[0].Line != 0 {
			t.Fatalf("fragments = %+v, want the raw content once", frags)
		}
	})
}

func TestStreamJSONFragmentsSkipsEncryptedContent(t *testing.T) {
	token := "AIza" + strings.Repeat("B", 35)
	for _, jsonl := range []bool{false, true} {
		for _, plaintext := range []bool{false, true} {
			doc := map[string]any{
				"encryptedContent": "prefix" + token + "suffix",
				"reasoningBlocks": map[string]any{"blocks": []any{
					map[string]string{"encrypted_content": "prefix" + token + "suffix"},
				}},
				"text": "No credentials here",
			}
			if plaintext {
				doc["text"] = token
			}
			content, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			scanner, err := NewScanner(nil, false)
			if err != nil {
				t.Fatal(err)
			}
			var findings []Finding
			for _, fragment := range collectJSONFragments(t, string(content), jsonl) {
				findings = append(findings, scanner.ScanFragment(fragment)...)
			}
			want := 0
			if plaintext {
				want = 1
			}
			if len(findings) != want {
				t.Fatalf("jsonl=%v, plaintext=%v: got %d findings, want %d", jsonl, plaintext, len(findings), want)
			}
		}
	}
}

func TestStreamJSONFragmentsSkipsVSCodeEncryptedThinking(t *testing.T) {
	token := "AIza" + strings.Repeat("C", 35)
	for _, jsonl := range []bool{false, true} {
		for _, plaintext := range []bool{false, true} {
			thinking := map[string]string{
				"encrypted": "prefix" + token + "suffix",
				"text":      "No credentials here",
			}
			if plaintext {
				thinking["text"] = token
			}
			doc := map[string]any{
				"kind": 1,
				"v": map[string]any{
					"metadata": map[string]any{
						"toolCallRounds": []any{map[string]any{"thinking": thinking}},
					},
				},
			}
			content, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			scanner, err := NewScanner(nil, false)
			if err != nil {
				t.Fatal(err)
			}
			var findings []Finding
			for _, fragment := range collectJSONFragments(t, string(content), jsonl) {
				findings = append(findings, scanner.ScanFragment(fragment)...)
			}
			want := 0
			if plaintext {
				want = 1
			}
			if len(findings) != want {
				t.Fatalf("jsonl=%v, plaintext=%v: got %d findings, want %d", jsonl, plaintext, len(findings), want)
			}
		}
	}
}

func TestStreamJSONFragmentsKeepsKeyContext(t *testing.T) {
	secret := "0123456789abcdefghijABCDEFGHIJ0123456789"
	content := "{\"AWS_SECRET_ACCESS_KEY\":\"" + secret + "\"}"
	for _, jsonl := range []bool{false, true} {
		s, err := NewScanner(nil, true)
		if err != nil {
			t.Fatalf("NewScanner() error = %v", err)
		}
		var findings []Finding
		for _, f := range collectJSONFragments(t, content, jsonl) {
			findings = append(findings, s.ScanFragment(f)...)
		}
		if len(findings) != 1 || findings[0].PatternID != "aws_secret_access_key" {
			t.Fatalf("jsonl=%v: findings = %+v, want one aws_secret_access_key", jsonl, findings)
		}
		if findings[0].StartLine != 1 {
			t.Errorf("jsonl=%v: StartLine = %d, want 1", jsonl, findings[0].StartLine)
		}
	}
}

func TestStreamJSONFragmentsKeepsNumericValues(t *testing.T) {
	content := `{"access_code":123456789012345678901234567890}`
	for _, jsonl := range []bool{false, true} {
		got := collectJSONFragments(t, content, jsonl)
		want := `"access_code": 123456789012345678901234567890`
		if len(got) != 1 || got[0].Content != want {
			t.Fatalf("jsonl=%v: fragments = %+v, want one %q", jsonl, got, want)
		}
	}
}
