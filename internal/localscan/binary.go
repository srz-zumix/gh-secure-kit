package localscan

// isBinaryString reports whether content looks like binary data, using a
// simple NUL-byte heuristic over a bounded prefix.
func isBinaryString(content string) bool {
	limit := len(content)
	if limit > 8000 {
		limit = 8000
	}
	for i := 0; i < limit; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}
