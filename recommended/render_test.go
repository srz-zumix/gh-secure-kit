package recommended
package recommended

import "testing"

func TestWrapText(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		want  string
	}{
		{"empty", "", 10, ""},
		{"short", "hello world", 20, "hello world"},
		{"wrap", "aaa bbb ccc ddd", 7, "aaa bbb\nccc ddd"},
		{"long word", "abcdefghij kl", 5, "abcdefghij\nkl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wrapText(tt.in, tt.width); got != tt.want {
				t.Errorf("wrapText(%q, %d) = %q, want %q", tt.in, tt.width, got, tt.want)
			}
		})
	}
}
