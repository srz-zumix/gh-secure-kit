package localscan

import "testing"

func TestFindingTextEscapesControlCharacters(t *testing.T) {
	got := findingText("a\x1b]0;x\x07b\u009bc\r\n\t")
	if want := `a\x1b]0;x\x07b\x9bc\r\n\t`; got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}
