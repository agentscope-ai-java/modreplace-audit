package gomod

import (
	"strconv"
	"strings"
)

// Order is the result of comparing two Go module versions.
type Order int

const (
	// Incomparable means at least one of the two version strings could not
	// be parsed as a Go module version, so no ordering claim is made.
	Incomparable Order = iota
	Lower
	Equal
	Higher
)

// parsedVersion holds the pieces of a Go module version string:
// "v" MAJOR "." MINOR "." PATCH [ "-" PRERELEASE ] [ "+" BUILD ].
// Pseudo-versions (e.g. v0.0.0-20200101000000-abcdef123456, or
// v1.2.4-0.20200101000000-abcdef123456 following a tag) are ordinary
// prerelease versions under this grammar; no special-casing is needed for
// them to sort correctly, because their prerelease identifiers are a
// fixed-width numeric timestamp that already compares correctly under
// standard semver precedence rules.
type parsedVersion struct {
	major, minor, patch int
	prerelease          string // without leading "-"; "" means no prerelease
}

// ParseVersion parses a Go module version string. It accepts the 1, 2 and
// 3-numeric-segment forms Go allows (v1, v1.2, v1.2.3) and build metadata,
// though build metadata is parsed and then ignored, per semver precedence
// rules.
func ParseVersion(s string) (parsedVersion, bool) {
	var v parsedVersion
	if !strings.HasPrefix(s, "v") {
		return v, false
	}
	s = s[1:]

	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i] // build metadata never affects precedence
	}

	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core = s[:i]
		v.prerelease = s[i+1:]
	}

	parts := strings.Split(core, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return v, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		nums[i] = n
	}
	v.major, v.minor, v.patch = nums[0], nums[1], nums[2]
	return v, true
}

// Compare orders two Go module version strings using standard semver
// precedence: major, then minor, then patch, numerically; a version with no
// prerelease outranks one with a prerelease; prerelease identifiers are
// compared dot-segment by dot-segment, numeric segments compared as
// integers and always sorting below non-numeric segments, non-numeric
// segments compared as ASCII strings.
func Compare(a, b string) Order {
	va, ok1 := ParseVersion(a)
	vb, ok2 := ParseVersion(b)
	if !ok1 || !ok2 {
		return Incomparable
	}

	if c := compareInt(va.major, vb.major); c != Equal {
		return c
	}
	if c := compareInt(va.minor, vb.minor); c != Equal {
		return c
	}
	if c := compareInt(va.patch, vb.patch); c != Equal {
		return c
	}

	if va.prerelease == "" && vb.prerelease == "" {
		return Equal
	}
	if va.prerelease == "" {
		return Higher // no prerelease outranks having one
	}
	if vb.prerelease == "" {
		return Lower
	}
	return comparePrerelease(va.prerelease, vb.prerelease)
}

func compareInt(a, b int) Order {
	switch {
	case a < b:
		return Lower
	case a > b:
		return Higher
	default:
		return Equal
	}
}

func comparePrerelease(a, b string) Order {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		an, aErr := strconv.Atoi(as[i])
		bn, bErr := strconv.Atoi(bs[i])
		switch {
		case aErr == nil && bErr == nil:
			return compareInt(an, bn)
		case aErr == nil:
			return Lower // numeric identifiers sort before non-numeric
		case bErr == nil:
			return Higher
		default:
			if as[i] < bs[i] {
				return Lower
			}
			return Higher
		}
	}
	return compareInt(len(as), len(bs)) // more identifiers outranks fewer, all-else-equal
}
