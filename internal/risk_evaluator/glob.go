package riskevaluator

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Glob semantics (docs/risk-policy.md, "Matching"; P03 D8). A pattern and a path are split on `/`.
// A `**` segment matches any number of segments, none included; every other segment is matched by
// the standard library's path.Match, so `*` and `?` never cross a `/`. Patterns are anchored at
// the repository root. ASCII letters compare case-insensitively on both sides.

// validPattern refuses at load anything that would silently never match or be ambiguous: an empty
// pattern, a leading or trailing `/`, an empty, `.` or `..` segment, `**` inside a segment, and a
// segment path.Match calls malformed (it checks the whole segment even when a name fails early).
func validPattern(p string) error {
	if p == "" {
		return errors.New("empty pattern")
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("pattern %q starts or ends with /: patterns are anchored at the root already", p)
	}
	for _, seg := range strings.Split(lowerASCII(p), "/") {
		switch {
		case seg == "" || seg == "." || seg == "..":
			return fmt.Errorf("pattern %q has an empty, . or .. segment", p)
		case seg == "**":
			continue
		case strings.Contains(seg, "**"):
			return fmt.Errorf("pattern %q has ** inside a segment; ** must be a whole segment", p)
		}
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("pattern %q: %w", p, err)
		}
	}
	return nil
}

// matchPath reports whether a repository path matches a pattern validPattern accepted.
func matchPath(pattern, name string) bool {
	return matchSegments(strings.Split(lowerASCII(pattern), "/"), strings.Split(lowerASCII(name), "/"))
}

func matchSegments(ps, ns []string) bool {
	for len(ps) > 0 {
		if ps[0] == "**" {
			for len(ps) > 0 && ps[0] == "**" {
				ps = ps[1:]
			}
			if len(ps) == 0 {
				return true
			}
			for i := 0; i <= len(ns); i++ {
				if matchSegments(ps, ns[i:]) {
					return true
				}
			}
			return false
		}
		if len(ns) == 0 {
			return false
		}
		if ok, err := path.Match(ps[0], ns[0]); err != nil || !ok {
			return false
		}
		ps, ns = ps[1:], ns[1:]
	}
	return len(ns) == 0
}

// lowerASCII lower-cases ASCII letters only; every other byte is left alone.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
