package audit

import (
	"strings"
	"testing"

	"github.com/__GH_OWNER__/modreplace-audit/internal/gomod"
	"github.com/__GH_OWNER__/modreplace-audit/internal/gosum"
)

func mustParse(t *testing.T, src string) *gomod.File {
	t.Helper()
	f, err := gomod.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func findSignal(t *testing.T, sigs []Signal, kind Kind) *Signal {
	t.Helper()
	for i := range sigs {
		if sigs[i].HasKind(kind) {
			return &sigs[i]
		}
	}
	return nil
}

// --- Signal 1: a newly added replace pointing at a fork ---

func TestSignal_NewReplaceToFork(t *testing.T) {
	base := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.5.0
`)
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.5.0

replace github.com/real/pkg => github.com/attacker/pkg v1.5.0
`)
	res := Run(base, head, nil, nil, Options{})

	sig := findSignal(t, res.Signals, KindFork)
	if sig == nil {
		t.Fatalf("expected a fork signal, got: %+v", res.Signals)
	}
	if !sig.HasKind(KindReplace) {
		t.Errorf("fork signal should also carry KindReplace")
	}
	if !strings.Contains(sig.Message, "github.com/attacker/pkg") {
		t.Errorf("message should name the fork target: %s", sig.Message)
	}
	if res.ReplaceAdded != 1 {
		t.Errorf("ReplaceAdded = %d, want 1", res.ReplaceAdded)
	}
}

// --- Signal 2: replace to a local filesystem path ---

func TestSignal_LocalPathReplace(t *testing.T) {
	base := mustParse(t, `module m

go 1.22
`)
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.5.0

replace github.com/real/pkg => ../local/pkg
`)
	res := Run(base, head, nil, nil, Options{})

	sig := findSignal(t, res.Signals, KindLocalPath)
	if sig == nil {
		t.Fatalf("expected a local-path signal, got: %+v", res.Signals)
	}
	if sig.HasKind(KindFork) {
		t.Errorf("a local path replace is not a fork")
	}
}

// --- Signal 3: replace to a lower version (silent downgrade) ---

func TestSignal_VersionDowngrade(t *testing.T) {
	base := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.9.0
`)
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.9.0

replace github.com/real/pkg => github.com/real/pkg v1.2.0
`)
	res := Run(base, head, nil, nil, Options{})

	sig := findSignal(t, res.Signals, KindDowngrade)
	if sig == nil {
		t.Fatalf("expected a downgrade signal, got: %+v", res.Signals)
	}
	if sig.HasKind(KindFork) {
		t.Errorf("same module path is not a fork")
	}
	if !strings.Contains(sig.Message, "v1.9.0") || !strings.Contains(sig.Message, "v1.2.0") {
		t.Errorf("message should mention both versions: %s", sig.Message)
	}
}

func TestSignal_VersionUpgradeIsNotDowngrade(t *testing.T) {
	base := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.2.0
`)
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.2.0

replace github.com/real/pkg => github.com/real/pkg v1.9.0
`)
	res := Run(base, head, nil, nil, Options{})
	if sig := findSignal(t, res.Signals, KindDowngrade); sig != nil {
		t.Errorf("higher pinned version should not be flagged as downgrade: %+v", sig)
	}
}

// --- Signal 4: exclude / retract directives ---

func TestSignal_ExcludeAdded(t *testing.T) {
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, `module m

go 1.22

exclude github.com/foo/bar v1.1.5
`)
	res := Run(base, head, nil, nil, Options{})
	if sig := findSignal(t, res.Signals, KindExclude); sig == nil {
		t.Fatalf("expected an exclude signal, got: %+v", res.Signals)
	}
}

func TestSignal_RetractAddedInOwnModule(t *testing.T) {
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, `module m

go 1.22

retract v1.0.0 // accidental publish
`)
	res := Run(base, head, nil, nil, Options{})
	sig := findSignal(t, res.Signals, KindRetract)
	if sig == nil {
		t.Fatalf("expected a retract signal, got: %+v", res.Signals)
	}
	if !strings.Contains(sig.Message, "accidental publish") {
		t.Errorf("message should carry the rationale: %s", sig.Message)
	}
}

// --- Signal 5: missing go.sum entry for a replaced module ---

func TestSignal_SumMissingForReplacementModule(t *testing.T) {
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.5.0

replace github.com/real/pkg => github.com/real/pkg v1.6.0
`)
	// go.sum was never updated for the new target.
	sum, err := gosum.Parse([]byte("github.com/real/pkg v1.5.0 h1:aaaa=\ngithub.com/real/pkg v1.5.0/go.mod h1:bbbb=\n"))
	if err != nil {
		t.Fatal(err)
	}
	res := Run(base, head, nil, sum, Options{})
	sig := findSignal(t, res.Signals, KindSum)
	if sig == nil {
		t.Fatalf("expected a sum signal, got: %+v", res.Signals)
	}
	if !strings.Contains(sig.Message, "v1.6.0") {
		t.Errorf("message should name the missing version: %s", sig.Message)
	}
}

func TestSignal_SumPresentNoSignal(t *testing.T) {
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.5.0

replace github.com/real/pkg => github.com/real/pkg v1.6.0
`)
	sum, err := gosum.Parse([]byte("github.com/real/pkg v1.6.0 h1:cccc=\ngithub.com/real/pkg v1.6.0/go.mod h1:dddd=\n"))
	if err != nil {
		t.Fatal(err)
	}
	res := Run(base, head, nil, sum, Options{})
	if sig := findSignal(t, res.Signals, KindSum); sig != nil {
		t.Errorf("go.sum has the entry, should not be flagged: %+v", sig)
	}
}

func TestSignal_LocalPathHasNoSumByDesign(t *testing.T) {
	// A local-path replace target has no go.sum entry at all — that's
	// expected, not a bug, and should show up as context on the
	// local-path signal, not as a separate "missing sum" problem signal.
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.5.0

replace github.com/real/pkg => ../local/pkg
`)
	sum, err := gosum.Parse([]byte("github.com/real/pkg v1.5.0 h1:aaaa=\n"))
	if err != nil {
		t.Fatal(err)
	}
	res := Run(base, head, nil, sum, Options{})
	if sig := findSignal(t, res.Signals, KindSum); sig != nil {
		t.Errorf("a local path replace's missing sum is expected, not a KindSum signal: %+v", sig)
	}
	local := findSignal(t, res.Signals, KindLocalPath)
	if local == nil {
		t.Fatalf("expected a local-path signal")
	}
	if !strings.Contains(local.Message, "now-unused entry") {
		t.Errorf("expected local-path message to note the leftover go.sum entry: %s", local.Message)
	}
}

// --- Signal 6: GOFLAGS=-mod=mod / vendor inconsistency ---

func TestSignal_GoFlagsModMod(t *testing.T) {
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, "module m\n\ngo 1.22\n")
	res := Run(base, head, nil, nil, Options{GoFlags: "-mod=mod"})
	if sig := findSignal(t, res.Signals, KindGoFlags); sig == nil {
		t.Fatalf("expected a goflags signal, got: %+v", res.Signals)
	}
}

func TestSignal_GoFlagsOtherValueNoSignal(t *testing.T) {
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, "module m\n\ngo 1.22\n")
	res := Run(base, head, nil, nil, Options{GoFlags: "-mod=readonly"})
	if sig := findSignal(t, res.Signals, KindGoFlags); sig != nil {
		t.Errorf("mod=readonly should not be flagged: %+v", sig)
	}
}

func TestSignal_VendorStale(t *testing.T) {
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.9.0
`)
	modulesTxt := "# github.com/real/pkg v1.5.0\n## explicit; go 1.20\ngithub.com/real/pkg\n"
	res := Run(base, head, nil, nil, Options{VendorModulesTxt: []byte(modulesTxt)})
	sig := findSignal(t, res.Signals, KindGoFlags)
	if sig == nil {
		t.Fatalf("expected a vendor-staleness signal, got: %+v", res.Signals)
	}
	if !strings.Contains(sig.Message, "v1.5.0") || !strings.Contains(sig.Message, "v1.9.0") {
		t.Errorf("message should mention both versions: %s", sig.Message)
	}
}

func TestSignal_VendorConsistentNoSignal(t *testing.T) {
	base := mustParse(t, "module m\n\ngo 1.22\n")
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.9.0
`)
	modulesTxt := "# github.com/real/pkg v1.9.0\n## explicit; go 1.20\ngithub.com/real/pkg\n"
	res := Run(base, head, nil, nil, Options{VendorModulesTxt: []byte(modulesTxt)})
	if sig := findSignal(t, res.Signals, KindGoFlags); sig != nil {
		t.Errorf("consistent vendor dir should not be flagged: %+v", sig)
	}
}

// --- replace removed / unchanged bookkeeping ---

func TestReplaceRemovedAndUnchanged(t *testing.T) {
	base := mustParse(t, `module m

go 1.22

replace github.com/foo/a => ./local/a
replace github.com/foo/b => github.com/foo/b v1.0.0
`)
	head := mustParse(t, `module m

go 1.22

replace github.com/foo/b => github.com/foo/b v1.0.0
`)
	res := Run(base, head, nil, nil, Options{})
	if res.ReplaceRemoved != 1 {
		t.Errorf("ReplaceRemoved = %d, want 1", res.ReplaceRemoved)
	}
	if res.ReplaceUnchanged != 1 {
		t.Errorf("ReplaceUnchanged = %d, want 1", res.ReplaceUnchanged)
	}
	if sig := findSignal(t, res.Signals, KindRemoved); sig == nil {
		t.Errorf("expected a removed signal")
	}
}

// --- priority ordering ---

func TestSignalsAreSortedByPriority(t *testing.T) {
	base := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.9.0
`)
	head := mustParse(t, `module m

go 1.22

require github.com/real/pkg v1.9.0

replace github.com/real/pkg => github.com/attacker/pkg v1.0.0

exclude github.com/other/pkg v1.0.0
`)
	res := Run(base, head, nil, nil, Options{GoFlags: "-mod=mod"})
	if len(res.Signals) < 2 {
		t.Fatalf("expected multiple signals, got %+v", res.Signals)
	}
	// fork (rank 0) must sort before exclude (rank 4) and goflags (rank 7).
	forkIdx, excludeIdx, flagsIdx := -1, -1, -1
	for i, s := range res.Signals {
		if s.HasKind(KindFork) {
			forkIdx = i
		}
		if s.HasKind(KindExclude) {
			excludeIdx = i
		}
		if s.HasKind(KindGoFlags) {
			flagsIdx = i
		}
	}
	if forkIdx == -1 || excludeIdx == -1 || flagsIdx == -1 {
		t.Fatalf("missing expected signals: %+v", res.Signals)
	}
	if !(forkIdx < excludeIdx && excludeIdx < flagsIdx) {
		t.Errorf("expected order fork < exclude < goflags, got indices %d, %d, %d", forkIdx, excludeIdx, flagsIdx)
	}
}
