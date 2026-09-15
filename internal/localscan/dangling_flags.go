package localscan

import (
	"errors"
	"fmt"
)

// danglingLocalOnlyFlags are the flags that only make sense when inspecting
// pull requests, so they conflict with the local-ref scanning mode.
var danglingLocalOnlyFlags = []string{
	"pr",
	"limit",
	"no-squash-merge",
	"no-force-push",
	"no-closed",
	"reachability-check",
	"no-cache",
	"clear-cache",
	"pr-concurrency",
}

// ValidateDanglingModeFlags rejects flag combinations that Cobra itself cannot
// express: --no-reflogs only applies to the local-ref mode, and the
// pull-request-only flags conflict with it. changed reports whether the user
// explicitly set the named flag, mirroring cobra's FlagSet.Changed.
func ValidateDanglingModeFlags(local bool, changed func(name string) bool) error {
	if !local {
		if changed("no-reflogs") {
			return errors.New("--no-reflogs only applies to --local")
		}
		return nil
	}
	for _, name := range danglingLocalOnlyFlags {
		if changed(name) {
			return fmt.Errorf("--%s does not apply to --local, which inspects local refs instead of pull requests", name)
		}
	}
	return nil
}
