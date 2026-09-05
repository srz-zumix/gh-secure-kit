package rules

import "embed"

// RulesFS embeds the per-rule Markdown documentation shipped with the binary,
// so `gh secure-kit recommended explain <ID>` works without needing the
// source repository to be present at runtime.
//
//go:embed *.md
var RulesFS embed.FS
