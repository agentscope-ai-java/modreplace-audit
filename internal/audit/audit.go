// Package audit compares two parsed go.mod files (and, optionally, their
// go.sum files) and produces a prioritised list of Signals: the changes
// that matter for the specific supply-chain risk a "replace" directive
// creates — see the root README for why that risk exists and why no
// existing tool flags it.
package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/__GH_OWNER__/modreplace-audit/internal/gomod"
	"github.com/__GH_OWNER__/modreplace-audit/internal/gosum"
)

// Kind identifies what a Signal is about. A single Signal can carry more
// than one Kind (e.g. a brand-new replace to a fork at a lower version is
// simultaneously "replace", "fork" and "downgrade"); --fail-on matches on
// any of them.
type Kind string

const (
	KindFork      Kind = "fork"       // replace redirects to a different module entirely
	KindLocalPath Kind = "local-path" // replace target is a filesystem path
	KindDowngrade Kind = "downgrade"  // replace target version is lower than the original
	KindReplace   Kind = "replace"    // any added/changed replace (base tag)
	KindRemoved   Kind = "removed"    // a replace directive was removed
	KindExclude   Kind = "exclude"    // exclude directive added or removed
	KindRetract   Kind = "retract"    // retract directive added or removed
	KindSum       Kind = "sum"        // go.sum entry missing/inconsistent for a replaced module
	KindGoFlags   Kind = "goflags"    // GOFLAGS=-mod=mod or a stale vendor directory
)

// priority ranks Kinds for sort order and for the documented --fail-on
// order: lower sorts first. It mirrors the order signals are listed in the
// project spec, most consequential first.
var priority = map[Kind]int{
	KindFork:      0,
	KindLocalPath: 1,
	KindDowngrade: 2,
	KindReplace:   3,
	KindExclude:   4,
	KindRetract:   4,
	KindSum:       5,
	KindRemoved:   6,
	KindGoFlags:   7,
}

// AllFailOnKinds lists every Kind usable with --fail-on, in priority order.
var AllFailOnKinds = []Kind{KindFork, KindLocalPath, KindDowngrade, KindReplace, KindExclude, KindRetract, KindSum, KindRemoved, KindGoFlags}

// Signal is one reportable finding.
type Signal struct {
	Kinds   []Kind
	Path    string // the module path the signal is about
	Message string // one-line human-readable description
}

// HasKind reports whether the signal carries the given Kind.
func (s Signal) HasKind(k Kind) bool {
	for _, kk := range s.Kinds {
		if kk == k {
			return true
		}
	}
	return false
}

func (s Signal) rank() int {
	best := 1 << 30
	for _, k := range s.Kinds {
		if p, ok := priority[k]; ok && p < best {
			best = p
		}
	}
	return best
}

// Options carries inputs that come from the environment rather than from
// the two go.mod files themselves.
type Options struct {
	// GoFlags is the raw GOFLAGS environment value at HEAD, or "" if unset.
	GoFlags string
	// VendorModulesTxt is the content of vendor/modules.txt next to the
	// HEAD go.mod, or nil if there is no vendor directory to check.
	VendorModulesTxt []byte
}

// Result is the full audit outcome.
type Result struct {
	Signals []Signal
	// Counts of replace directives for the summary line.
	ReplaceAdded, ReplaceChanged, ReplaceRemoved, ReplaceUnchanged int
}

// Run audits head against base. baseSum/headSum may be nil when a go.sum
// was not supplied.
func Run(base, head *gomod.File, baseSum, headSum *gosum.File, opts Options) Result {
	var res Result
	res.Signals = append(res.Signals, replaceSignals(base, head, headSum, &res)...)
	res.Signals = append(res.Signals, excludeSignals(base, head)...)
	res.Signals = append(res.Signals, retractSignals(base, head)...)
	res.Signals = append(res.Signals, envSignals(head, opts)...)

	sort.SliceStable(res.Signals, func(i, j int) bool {
		return res.Signals[i].rank() < res.Signals[j].rank()
	})
	return res
}

func replaceByKey(f *gomod.File) map[string]gomod.Replace {
	m := make(map[string]gomod.Replace, len(f.Replace))
	for _, r := range f.Replace {
		m[r.Key()] = r
	}
	return m
}

func requiredVersion(f *gomod.File, path string) (string, bool) {
	for _, r := range f.Require {
		if r.Path == path {
			return r.Version, true
		}
	}
	return "", false
}

func replaceSignals(base, head *gomod.File, headSum *gosum.File, res *Result) []Signal {
	var out []Signal
	baseR := replaceByKey(base)
	headR := replaceByKey(head)

	for key, hr := range headR {
		br, existed := baseR[key]
		switch {
		case !existed:
			res.ReplaceAdded++
			out = append(out, newOrChangedReplaceSignal(head, hr, nil, headSum))
		case !sameTarget(br, hr):
			res.ReplaceChanged++
			old := br
			out = append(out, newOrChangedReplaceSignal(head, hr, &old, headSum))
		default:
			res.ReplaceUnchanged++
		}
	}
	for key, br := range baseR {
		if _, stillThere := headR[key]; !stillThere {
			res.ReplaceRemoved++
			out = append(out, Signal{
				Kinds:   []Kind{KindRemoved},
				Path:    br.OldPath,
				Message: fmt.Sprintf("replace removed: %s%s no longer redirected to %s", br.OldPath, versionSuffix(br.OldVersion), replaceTarget(br)),
			})
		}
	}
	return out
}

func newOrChangedReplaceSignal(head *gomod.File, r gomod.Replace, prev *gomod.Replace, headSum *gosum.File) Signal {
	kinds := []Kind{KindReplace}
	var notes []string

	if r.IsLocal() {
		kinds = append(kinds, KindLocalPath)
		notes = append(notes, "target is a local filesystem path, not a module — fine in development, a broken (or unreviewable) build if it ships in a release")
	} else if r.IsFork() {
		kinds = append(kinds, KindFork)
		notes = append(notes, fmt.Sprintf("redirects to a different module path (%s) instead of a version of %s — verify this is an intentional fork, not a tamper", r.NewPath, r.OldPath))
	}

	if !r.IsLocal() && r.NewVersion != "" {
		if orig, ok := requiredVersion(head, r.OldPath); ok {
			switch gomod.Compare(r.NewVersion, orig) {
			case gomod.Lower:
				kinds = append(kinds, KindDowngrade)
				notes = append(notes, fmt.Sprintf("replacement version %s is LOWER than the required %s — this can silently reintroduce a fixed vulnerability", r.NewVersion, orig))
			case gomod.Incomparable:
				notes = append(notes, fmt.Sprintf("could not compare replacement version %s against required %s", r.NewVersion, orig))
			}
		}
	}

	if !r.IsLocal() && r.NewVersion != "" && headSum != nil {
		if !headSum.Has(r.NewPath, r.NewVersion) {
			kinds = append(kinds, KindSum)
			notes = append(notes, fmt.Sprintf("go.sum has no entry for %s@%s — build will need to fetch and verify it, or will fail with no network", r.NewPath, r.NewVersion))
		}
	}
	if r.IsLocal() && headSum != nil {
		if old, ok := requiredVersion(head, r.OldPath); ok && headSum.Has(r.OldPath, old) {
			notes = append(notes, fmt.Sprintf("go.sum still carries a now-unused entry for %s@%s (harmless, but worth pruning with `go mod tidy`)", r.OldPath, old))
		}
	}

	verb := "NEW"
	target := replaceTarget(r)
	if prev != nil {
		verb = "CHANGED"
		target = fmt.Sprintf("%s (was %s)", target, replaceTarget(*prev))
	}

	msg := fmt.Sprintf("%s replace %s%s => %s", verb, r.OldPath, versionSuffix(r.OldVersion), target)
	if len(notes) > 0 {
		msg += " — " + strings.Join(notes, "; ")
	}

	return Signal{Kinds: kinds, Path: r.OldPath, Message: msg}
}

// sameTarget compares two replace directives on their meaning only (which
// module/path they redirect to, and at what version), ignoring the source
// Line, which naturally differs between base and head even when nothing
// meaningful changed.
func sameTarget(a, b gomod.Replace) bool {
	return a.OldPath == b.OldPath && a.OldVersion == b.OldVersion &&
		a.NewPath == b.NewPath && a.NewVersion == b.NewVersion
}

func replaceTarget(r gomod.Replace) string {
	if r.NewVersion == "" {
		return r.NewPath
	}
	return r.NewPath + " " + r.NewVersion
}

func versionSuffix(v string) string {
	if v == "" {
		return ""
	}
	return " " + v
}

func excludeSignals(base, head *gomod.File) []Signal {
	key := func(e gomod.Exclude) string { return e.Path + "@" + e.Version }
	baseSet := map[string]bool{}
	for _, e := range base.Exclude {
		baseSet[key(e)] = true
	}
	headSet := map[string]bool{}
	for _, e := range head.Exclude {
		headSet[key(e)] = true
	}

	var out []Signal
	for _, e := range head.Exclude {
		if !baseSet[key(e)] {
			msg := fmt.Sprintf("exclude added: %s %s", e.Path, e.Version)
			out = append(out, Signal{Kinds: []Kind{KindExclude}, Path: e.Path, Message: msg})
		}
	}
	for _, e := range base.Exclude {
		if !headSet[key(e)] {
			msg := fmt.Sprintf("exclude removed: %s %s", e.Path, e.Version)
			out = append(out, Signal{Kinds: []Kind{KindExclude}, Path: e.Path, Message: msg})
		}
	}
	return out
}

// retractSignals reports changes to this module's own retract directives.
//
// Note the scope limit: go.mod only ever contains retract directives for
// the module it belongs to (a module retracts its own bad versions for the
// benefit of its dependents), never for the modules it requires. Seeing
// "retract in a module you depend on" therefore requires reading that
// dependency's own go.mod at its resolved version — a network fetch this
// tool deliberately never makes. What this function can and does check is
// whether the go.mod under audit changed what it retracts, which matters
// when auditing a go.mod that others will depend on.
func retractSignals(base, head *gomod.File) []Signal {
	key := func(r gomod.Retract) string { return r.Low + ".." + r.High }
	baseSet := map[string]bool{}
	for _, r := range base.Retract {
		baseSet[key(r)] = true
	}
	headSet := map[string]bool{}
	for _, r := range head.Retract {
		headSet[key(r)] = true
	}

	var out []Signal
	for _, r := range head.Retract {
		if !baseSet[key(r)] {
			out = append(out, Signal{Kinds: []Kind{KindRetract}, Message: retractMessage("added", r)})
		}
	}
	for _, r := range base.Retract {
		if !headSet[key(r)] {
			out = append(out, Signal{Kinds: []Kind{KindRetract}, Message: retractMessage("removed", r)})
		}
	}
	return out
}

func retractMessage(verb string, r gomod.Retract) string {
	target := r.Low
	if r.IsRange() {
		target = fmt.Sprintf("[%s, %s]", r.Low, r.High)
	}
	msg := fmt.Sprintf("retract %s: %s", verb, target)
	if r.Rationale != "" {
		msg += " (" + r.Rationale + ")"
	}
	return msg
}

func envSignals(head *gomod.File, opts Options) []Signal {
	var out []Signal
	if strings.Contains(opts.GoFlags, "-mod=mod") {
		out = append(out, Signal{
			Kinds:   []Kind{KindGoFlags},
			Message: "GOFLAGS contains -mod=mod: a build in this environment can silently rewrite go.mod/go.sum instead of failing when they're out of sync with source — the reviewed files may not be the ones that actually built",
		})
	}

	if opts.VendorModulesTxt != nil {
		out = append(out, vendorSignals(head, opts.VendorModulesTxt)...)
	}
	return out
}

// vendorSignals compares vendor/modules.txt's recorded versions against
// go.mod's requirements (after applying replace), flagging any module
// whose vendored version doesn't match what go.mod says should build. A
// stale vendor directory is picked up by "go build -mod=vendor" (the
// default whenever a vendor directory is present, Go >=1.14) silently,
// unless -mod=mod overrides it — so this is the other half of the same
// "which source actually builds" question as the GOFLAGS check above.
func vendorSignals(head *gomod.File, modulesTxt []byte) []Signal {
	effective := map[string]string{} // module path -> version go.mod says should build
	for _, r := range head.Require {
		effective[r.Path] = r.Version
	}
	for _, r := range head.Replace {
		if r.IsLocal() {
			delete(effective, r.OldPath) // no version to compare against
			continue
		}
		if r.NewVersion != "" {
			effective[r.OldPath] = r.NewVersion
		}
	}

	vendored := parseVendorModulesTxt(modulesTxt)

	var out []Signal
	for path, wantVersion := range effective {
		gotVersion, ok := vendored[path]
		if !ok {
			continue // not vendored (e.g. stdlib-only build, or module not reached); not this check's concern
		}
		if gotVersion != wantVersion {
			out = append(out, Signal{
				Kinds: []Kind{KindGoFlags},
				Path:  path,
				Message: fmt.Sprintf(
					"vendor/modules.txt has %s@%s but go.mod resolves it to %s — `go build -mod=vendor` (the default with a vendor directory present) will use the stale vendored copy",
					path, gotVersion, wantVersion),
			})
		}
	}
	return out
}

// parseVendorModulesTxt extracts the "# module version" lines that
// vendor/modules.txt records for each vendored module. See
// https://go.dev/ref/mod#vendoring.
func parseVendorModulesTxt(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "v") {
			continue // "## explicit" / "## explicit; go 1.x" annotation lines, etc.
		}
		out[fields[0]] = fields[1]
	}
	return out
}
