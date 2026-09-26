// Package gomod parses go.mod files well enough to audit their replace,
// require, exclude and retract directives.
//
// It is a hand-written, purpose-built parser rather than a wrapper around
// golang.org/x/mod/modfile: this project takes no third-party runtime
// dependency (see the root README), so the same guarantee has to extend to
// its own go.mod parsing. The go.mod line grammar is small and documented at
// https://go.dev/ref/mod#go-mod-file, and this file implements exactly the
// subset that grammar defines: line and block directives, "//" line
// comments, double-quoted and backtick-quoted tokens, and the "// indirect"
// convention on require lines.
//
// Block comments ("/* ... */") are not supported. They are valid in the
// go.mod grammar but gofmt and "go mod edit" never emit them and none of the
// real-world go.mod files checked while building this parser (see
// testdata/real) contain one; see the root README for the full list of
// deliberate limitations.
package gomod

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Require is one requirement: a module path pinned to a version.
type Require struct {
	Path     string
	Version  string
	Indirect bool // set by a trailing "// indirect" comment
	Line     int
}

// Replace is one replace directive: OldPath (at OldVersion, or every version
// if OldVersion is empty) is replaced by NewPath (at NewVersion, or by a
// local filesystem path if NewVersion is empty).
type Replace struct {
	OldPath    string
	OldVersion string
	NewPath    string
	NewVersion string
	Line       int
}

// IsLocal reports whether the replacement target is a filesystem path
// rather than a module path, per the go.mod rule: the target is a local
// path if and only if it is absolute or begins with "./" or "../".
func (r Replace) IsLocal() bool { return IsLocalPath(r.NewPath) }

// IsFork reports whether the replacement points at a different module path
// than the one being replaced. A same-path replace only repins a version;
// a different-path replace redirects the module entirely.
func (r Replace) IsFork() bool { return !r.IsLocal() && r.NewPath != r.OldPath }

// Key identifies a replace directive for base/head matching: Go allows at
// most one replace per (OldPath, OldVersion) pair, so that pair is the
// natural identity.
func (r Replace) Key() string {
	if r.OldVersion == "" {
		return r.OldPath
	}
	return r.OldPath + "@" + r.OldVersion
}

// Exclude is one exclude directive.
type Exclude struct {
	Path    string
	Version string
	Line    int
}

// Retract is one retract directive: a single version (Low == High) or an
// inclusive range [Low, High]. Rationale is the trailing comment, which by
// convention explains why the version(s) were retracted.
type Retract struct {
	Low       string
	High      string
	Rationale string
	Line      int
}

// IsRange reports whether this retraction covers a range rather than a
// single version.
func (r Retract) IsRange() bool { return r.Low != r.High }

// File is a parsed go.mod file.
type File struct {
	Module    string
	Go        string
	Toolchain string
	Require   []Require
	Replace   []Replace
	Exclude   []Exclude
	Retract   []Retract
}

// IsLocalPath reports whether a replace target is a filesystem path per the
// go.mod rule (https://go.dev/ref/mod#go-mod-file-replace): absolute, or
// starting with "./" or "../". Everything else is a module path.
func IsLocalPath(path string) bool {
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return true
	}
	if path == "." || path == ".." {
		return true
	}
	if strings.HasPrefix(path, "/") {
		return true
	}
	// Windows-style absolute path, e.g. C:\foo or C:/foo.
	if len(path) >= 3 && isASCIILetter(rune(path[0])) && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		return true
	}
	return false
}

func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// LooksLikeGoMod reports whether data looks like a go.mod file, independent
// of any filename. It is intentionally permissive: a file is treated as
// go.mod content when it parses cleanly under this package's grammar and
// contains at least one recognizable directive (module/go/toolchain, or a
// require/replace/exclude/retract entry). Callers should use this to decide
// how to treat a file discovered by content rather than by name — see the
// "detect format from content" requirement in the project README.
func LooksLikeGoMod(data []byte) bool {
	f, err := Parse(data)
	if err != nil {
		return false
	}
	if strings.TrimSpace(string(data)) == "" {
		return false
	}
	return f.Module != "" || f.Go != "" || f.Toolchain != "" ||
		len(f.Require) > 0 || len(f.Replace) > 0 || len(f.Exclude) > 0 || len(f.Retract) > 0
}

// Parse parses go.mod file content.
func Parse(data []byte) (*File, error) {
	f := &File{}
	lines := strings.Split(string(data), "\n")

	blockVerb := ""      // one of require/replace/exclude/retract while inside its block
	skipUnknown := false // inside a block for a directive this parser doesn't model
	for i, raw := range lines {
		lineNo := i + 1
		content, comment := splitLineComment(raw)
		content = strings.TrimSpace(content)
		comment = strings.TrimSpace(comment)

		if skipUnknown {
			if content == ")" {
				skipUnknown = false
			}
			continue
		}

		if blockVerb != "" {
			if content == ")" {
				blockVerb = ""
				continue
			}
			if content == "" {
				continue
			}
			toks := fields(content)
			if err := f.applyEntry(blockVerb, toks, comment, lineNo); err != nil {
				return nil, err
			}
			continue
		}

		if content == "" {
			continue
		}
		toks := fields(content)
		verb := toks[0]
		rest := toks[1:]

		if len(rest) == 1 && rest[0] == "(" {
			switch verb {
			case "require", "replace", "exclude", "retract":
				blockVerb = verb
			default:
				// A block for a directive kind this parser doesn't need to
				// understand (godebug, tool, ignore, and any future
				// addition) — consume it without erroring, matching how
				// unknown single-line directives below are handled.
				skipUnknown = true
			}
			continue
		}

		switch verb {
		case "module":
			if len(rest) < 1 {
				return nil, fmt.Errorf("go.mod:%d: malformed module directive", lineNo)
			}
			f.Module = unquote(rest[0])
		case "go":
			if len(rest) < 1 {
				return nil, fmt.Errorf("go.mod:%d: malformed go directive", lineNo)
			}
			f.Go = rest[0]
		case "toolchain":
			if len(rest) < 1 {
				return nil, fmt.Errorf("go.mod:%d: malformed toolchain directive", lineNo)
			}
			f.Toolchain = rest[0]
		case "require", "replace", "exclude", "retract":
			if err := f.applyEntry(verb, rest, comment, lineNo); err != nil {
				return nil, err
			}
		default:
			// Unknown/newer directive (godebug, tool, ignore, ...). Skip
			// gracefully rather than failing the whole parse: this tool's
			// job is auditing replace/require/exclude/retract, and Go adds
			// new directive kinds over time that don't affect that audit.
		}
	}
	if blockVerb != "" {
		return nil, fmt.Errorf("go.mod: unterminated %s block", blockVerb)
	}
	if skipUnknown {
		return nil, fmt.Errorf("go.mod: unterminated block")
	}
	return f, nil
}

func (f *File) applyEntry(verb string, toks []string, comment string, line int) error {
	switch verb {
	case "require":
		if len(toks) < 2 {
			return fmt.Errorf("go.mod:%d: malformed require entry", line)
		}
		f.Require = append(f.Require, Require{
			Path:     unquote(toks[0]),
			Version:  toks[1],
			Indirect: isIndirectComment(comment),
			Line:     line,
		})
	case "replace":
		idx := indexOf(toks, "=>")
		if idx < 0 {
			return fmt.Errorf("go.mod:%d: malformed replace entry (no =>)", line)
		}
		left, right := toks[:idx], toks[idx+1:]
		if len(left) < 1 || len(left) > 2 {
			return fmt.Errorf("go.mod:%d: malformed replace entry (left side)", line)
		}
		if len(right) < 1 || len(right) > 2 {
			return fmt.Errorf("go.mod:%d: malformed replace entry (right side)", line)
		}
		r := Replace{OldPath: unquote(left[0]), NewPath: unquote(right[0]), Line: line}
		if len(left) == 2 {
			r.OldVersion = left[1]
		}
		if len(right) == 2 {
			r.NewVersion = right[1]
		}
		f.Replace = append(f.Replace, r)
	case "exclude":
		if len(toks) < 2 {
			return fmt.Errorf("go.mod:%d: malformed exclude entry", line)
		}
		f.Exclude = append(f.Exclude, Exclude{Path: unquote(toks[0]), Version: toks[1], Line: line})
	case "retract":
		joined := strings.TrimSpace(strings.Join(toks, " "))
		if joined == "" {
			return fmt.Errorf("go.mod:%d: malformed retract entry", line)
		}
		ret := Retract{Rationale: comment, Line: line}
		if strings.HasPrefix(joined, "[") {
			inner := strings.TrimSuffix(strings.TrimPrefix(joined, "["), "]")
			parts := strings.SplitN(inner, ",", 2)
			if len(parts) != 2 {
				return fmt.Errorf("go.mod:%d: malformed retract range", line)
			}
			ret.Low = strings.TrimSpace(parts[0])
			ret.High = strings.TrimSpace(parts[1])
		} else {
			ret.Low = joined
			ret.High = joined
		}
		f.Retract = append(f.Retract, ret)
	}
	return nil
}

// isIndirectComment reports whether a require line's trailing comment marks
// it "// indirect". The canonical form produced by "go mod tidy" is exactly
// "indirect", but real-world go.mod files also append further
// semicolon-separated annotations after it (e.g.
// "// indirect; @team/owner"), which "go mod edit -json" still treats as
// indirect — so only the leading, semicolon-delimited token is checked.
func isIndirectComment(comment string) bool {
	first, _, _ := strings.Cut(comment, ";")
	return strings.TrimSpace(first) == "indirect"
}

func indexOf(toks []string, s string) int {
	for i, t := range toks {
		if t == s {
			return i
		}
	}
	return -1
}

// splitLineComment splits a raw source line into (content, comment) at the
// first "//" that appears outside a quoted string. Quoting follows Go
// string-literal rules for double quotes (backslash escapes) and raw-string
// rules for backticks.
func splitLineComment(line string) (content, comment string) {
	runes := []rune(line)
	inDouble, inBacktick := false, false
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case inDouble:
			if c == '\\' && i+1 < len(runes) {
				i++
				continue
			}
			if c == '"' {
				inDouble = false
			}
		case inBacktick:
			if c == '`' {
				inBacktick = false
			}
		default:
			switch c {
			case '"':
				inDouble = true
			case '`':
				inBacktick = true
			case '/':
				if i+1 < len(runes) && runes[i+1] == '/' {
					return string(runes[:i]), string(runes[i+2:])
				}
			}
		}
	}
	return line, ""
}

// fields splits content into whitespace-separated tokens, treating a
// double-quoted or backtick-quoted span as a single token even if it
// contains whitespace.
func fields(s string) []string {
	var out []string
	var cur strings.Builder
	inDouble, inBacktick := false, false
	runes := []rune(s)

	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}

	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case inDouble:
			cur.WriteRune(c)
			if c == '\\' && i+1 < len(runes) {
				i++
				cur.WriteRune(runes[i])
				continue
			}
			if c == '"' {
				inDouble = false
			}
		case inBacktick:
			cur.WriteRune(c)
			if c == '`' {
				inBacktick = false
			}
		default:
			if unicode.IsSpace(c) {
				flush()
				continue
			}
			switch c {
			case '"':
				inDouble = true
				cur.WriteRune(c)
			case '`':
				inBacktick = true
				cur.WriteRune(c)
			case '(', ')':
				flush()
				out = append(out, string(c))
			default:
				cur.WriteRune(c)
			}
		}
	}
	flush()
	return out
}

func unquote(tok string) string {
	if len(tok) >= 2 && tok[0] == '"' && tok[len(tok)-1] == '"' {
		if u, err := strconv.Unquote(tok); err == nil {
			return u
		}
	}
	if len(tok) >= 2 && tok[0] == '`' && tok[len(tok)-1] == '`' {
		return tok[1 : len(tok)-1]
	}
	return tok
}
