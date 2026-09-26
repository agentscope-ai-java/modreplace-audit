// Package gosum parses go.sum files: a flat, line-oriented format that
// needs nothing more than a whitespace split, documented at
// https://go.dev/ref/mod#go-sum-files. Each line is either
//
//	module version hash
//
// or
//
//	module version/go.mod hash
//
// the second recording the hash of that version's go.mod file rather than
// its full module tree.
package gosum

import (
	"fmt"
	"strings"
)

// Entry is one go.sum line.
type Entry struct {
	Module  string
	Version string
	IsGoMod bool // true for a "<version>/go.mod" line
	Hash    string
	Line    int
}

// File is a parsed go.sum file.
type File struct {
	Entries []Entry
}

// Parse parses go.sum file content.
func Parse(data []byte) (*File, error) {
	f := &File{}
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("go.sum:%d: expected 3 fields, got %d", i+1, len(fields))
		}
		e := Entry{Module: fields[0], Version: fields[1], Hash: fields[2], Line: i + 1}
		if strings.HasSuffix(e.Version, "/go.mod") {
			e.IsGoMod = true
			e.Version = strings.TrimSuffix(e.Version, "/go.mod")
		}
		f.Entries = append(f.Entries, e)
	}
	return f, nil
}

// Has reports whether the go.sum content has a (non-go.mod) hash entry for
// module@version.
func (f *File) Has(module, version string) bool {
	if f == nil {
		return false
	}
	for _, e := range f.Entries {
		if !e.IsGoMod && e.Module == module && e.Version == version {
			return true
		}
	}
	return false
}

// Hash returns the (non-go.mod) hash recorded for module@version, if any.
func (f *File) Hash(module, version string) (string, bool) {
	if f == nil {
		return "", false
	}
	for _, e := range f.Entries {
		if !e.IsGoMod && e.Module == module && e.Version == version {
			return e.Hash, true
		}
	}
	return "", false
}
