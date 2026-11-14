package localscan

import (
	"strings"
	"testing"
)

func TestContainsAnyKeywordBytesParity(t *testing.T) {
	boundary := strings.Repeat("x", keywordChunkSize-3) + "SeCrEtKey" + strings.Repeat("y", 10)
	cases := []struct {
		content  string
		keywords []string
	}{
		{"hello TOKEN world", []string{"token"}},
		{"hello world", []string{"token"}},
		{"ÄBC", []string{"äbc"}},
		{boundary, []string{"secretkey"}},
		{boundary, []string{"missing"}},
	}
	for _, c := range cases {
		want := containsAnyKeyword(c.content, c.keywords)
		if got := containsAnyKeywordBytes([]byte(c.content), c.keywords); got != want {
			t.Errorf("keywords %v: got %v, want %v", c.keywords, got, want)
		}
	}
}
