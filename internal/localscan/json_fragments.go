package localscan

import (
	"strings"

	"github.com/srz-zumix/go-gh-extension/pkg/ioutil"
)

// streamJSONFragments yields fragments for the string values of a JSON
// document, or of each line of a JSON Lines document, so escaped content
// such as "\n" inside a PEM key is scanned in its decoded form. Content that
// does not parse as JSON is yielded as raw text instead. base supplies the
// fragment metadata (file path, source, session).
func streamJSONFragments(content string, jsonl bool, base Fragment, yield func(Fragment) error) error {
	emit := func(s ioutil.JSONString) error {
		f := base
		f.Content = s.Value
		f.Line = s.Line
		return yield(f)
	}

	if !jsonl {
		strs, err := ioutil.JSONStrings(content, 1, "encryptedContent", "encrypted_content")
		if err != nil {
			f := base
			f.Content = content
			return yield(f)
		}
		for _, s := range strs {
			if err := emit(s); err != nil {
				return err
			}
		}
		return nil
	}

	lineNo := 0
	for rest := content; rest != ""; {
		var line string
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			line, rest = rest, ""
		}
		lineNo++
		if strings.TrimSpace(line) == "" {
			continue
		}
		strs, err := ioutil.JSONStrings(line, lineNo, "encryptedContent", "encrypted_content")
		if err != nil {
			if err := emit(ioutil.JSONString{Value: line, Line: lineNo}); err != nil {
				return err
			}
			continue
		}
		for _, s := range strs {
			if err := emit(s); err != nil {
				return err
			}
		}
	}
	return nil
}
