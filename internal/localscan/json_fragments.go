package localscan

import (
	"encoding/json"
	"io"
	"slices"
	"strings"
)

// ignoredJSONKeys lists object keys whose values (including nested values)
// are opaque ciphertext and are never scanned.
var ignoredJSONKeys = []string{"encryptedContent", "encrypted_content"}

// jsonString is a decoded string from a JSON document and the line it ends on.
type jsonString struct {
	Value string
	Line  int
}

// streamJSONFragments yields fragments for the string values of a JSON
// document, or of each line of a JSON Lines document, so escaped content
// such as "\n" inside a PEM key is scanned in its decoded form. A string
// value of an object member is yielded together with its key as
// `"key": "value"` so detectors that need the key context (e.g.
// aws_secret_access_key) still match. Content that does not parse as JSON is
// yielded as raw text instead. base supplies the fragment metadata (file
// path, source, session).
func streamJSONFragments(content string, jsonl bool, base Fragment, yield func(Fragment) error) error {
	emit := func(s jsonString) error {
		f := base
		f.Content = s.Value
		f.Line = s.Line
		return yield(f)
	}

	if !jsonl {
		strs, err := jsonStrings(content, 1)
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
		strs, err := jsonStrings(line, lineNo)
		if err != nil {
			if err := emit(jsonString{Value: line, Line: lineNo}); err != nil {
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

// jsonStrings decodes the non-empty strings in text, which may hold several
// concatenated JSON values. firstLine is the line number of text's first
// line. An object member with a string value is returned as a single
// `"key": "value"` entry; other keys and strings are returned on their own.
// Values under ignoredJSONKeys are omitted. It returns an error when text is
// not valid JSON.
func jsonStrings(text string, firstLine int) ([]jsonString, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var out []jsonString
	line := firstLine
	var prev int64
	type container struct {
		object    bool
		expectKey bool
		skip      bool
		key       string
		keyLine   int
	}
	var stack []container
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			// Token reports a truncated document as a clean EOF.
			if len(stack) != 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		off := dec.InputOffset()
		line += strings.Count(text[prev:off], "\n")
		prev = off

		var parent *container
		if len(stack) > 0 {
			parent = &stack[len(stack)-1]
		}
		if parent != nil && parent.object && parent.expectKey {
			if key, ok := tok.(string); ok {
				parent.expectKey = false
				parent.key, parent.keyLine = key, line
				continue
			}
		}

		// Resolve the member key (if any) that this value belongs to.
		skip := parent != nil && parent.skip
		key, keyLine, member := "", 0, false
		if parent != nil && parent.object {
			key, keyLine, member = parent.key, parent.keyLine, true
			skip = skip || slices.Contains(ignoredJSONKeys, key)
			if d, ok := tok.(json.Delim); !ok || d == '{' || d == '[' {
				parent.expectKey = true
			}
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			continue
		}

		switch v := tok.(type) {
		case json.Delim:
			if member && key != "" && !skip {
				out = append(out, jsonString{Value: key, Line: keyLine})
			}
			stack = append(stack, container{object: v == '{', expectKey: v == '{', skip: skip})
		case string:
			if skip {
				continue
			}
			switch {
			case member && key != "":
				out = append(out, jsonString{Value: `"` + key + `": "` + v + `"`, Line: line})
			case v != "":
				out = append(out, jsonString{Value: v, Line: line})
			}
		case json.Number:
			// Numeric values may hold credentials such as numeric codes,
			// so scan their literal text with the key context.
			if skip {
				continue
			}
			if member && key != "" {
				out = append(out, jsonString{Value: `"` + key + `": ` + v.String(), Line: line})
			} else {
				out = append(out, jsonString{Value: v.String(), Line: line})
			}
		default:
			if member && key != "" && !skip {
				out = append(out, jsonString{Value: key, Line: keyLine})
			}
		}
	}
}
