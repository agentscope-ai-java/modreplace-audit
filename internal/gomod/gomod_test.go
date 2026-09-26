package gomod

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestParseBasics(t *testing.T) {
	src := `module github.com/example/thing

go 1.22

require github.com/foo/bar v1.2.3
require github.com/foo/baz v0.0.0-20240102030405-abcdef123456 // indirect
`
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Module != "github.com/example/thing" {
		t.Errorf("Module = %q", f.Module)
	}
	if f.Go != "1.22" {
		t.Errorf("Go = %q", f.Go)
	}
	if len(f.Require) != 2 {
		t.Fatalf("Require = %d entries, want 2", len(f.Require))
	}
	if f.Require[0].Indirect {
		t.Errorf("first require should not be indirect")
	}
	if !f.Require[1].Indirect {
		t.Errorf("second require should be indirect (has // indirect comment)")
	}
	if f.Require[1].Version != "v0.0.0-20240102030405-abcdef123456" {
		t.Errorf("pseudo-version = %q", f.Require[1].Version)
	}
}

func TestParseRequireBlockWithComments(t *testing.T) {
	src := `module m

go 1.22

require (
	// a leading comment on its own line
	github.com/a/a v1.0.0
	github.com/b/b v2.0.0 // indirect
	github.com/c/c v3.0.0
)
`
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []Require{
		{Path: "github.com/a/a", Version: "v1.0.0"},
		{Path: "github.com/b/b", Version: "v2.0.0", Indirect: true},
		{Path: "github.com/c/c", Version: "v3.0.0"},
	}
	if len(f.Require) != len(want) {
		t.Fatalf("got %d requires, want %d", len(f.Require), len(want))
	}
	for i, w := range want {
		got := f.Require[i]
		if got.Path != w.Path || got.Version != w.Version || got.Indirect != w.Indirect {
			t.Errorf("require[%d] = %+v, want %+v", i, got, w)
		}
	}
}

func TestParseReplaceForms(t *testing.T) {
	src := `module m

go 1.22

replace github.com/foo/bar => github.com/attacker/bar v1.2.3

replace github.com/foo/baz v1.0.0 => github.com/foo/baz v0.9.0

replace github.com/foo/qux => ../local/qux

replace (
	github.com/one/one => ../vendor/one
	github.com/two/two v1.0.0 => github.com/two/two v1.0.1
)
`
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.Replace) != 5 {
		t.Fatalf("got %d replace entries, want 5", len(f.Replace))
	}

	r0 := f.Replace[0]
	if r0.OldPath != "github.com/foo/bar" || r0.NewPath != "github.com/attacker/bar" || r0.NewVersion != "v1.2.3" {
		t.Errorf("replace[0] = %+v", r0)
	}
	if !r0.IsFork() {
		t.Errorf("replace[0] should be detected as a fork (different module path)")
	}
	if r0.IsLocal() {
		t.Errorf("replace[0] should not be local")
	}

	r1 := f.Replace[1]
	if r1.OldVersion != "v1.0.0" || r1.NewVersion != "v0.9.0" {
		t.Errorf("replace[1] = %+v", r1)
	}
	if r1.IsFork() {
		t.Errorf("replace[1] is a same-path version pin, not a fork")
	}

	r2 := f.Replace[2]
	if !r2.IsLocal() {
		t.Errorf("replace[2] (../local/qux) should be local")
	}
	if r2.NewVersion != "" {
		t.Errorf("local replace should have no version, got %q", r2.NewVersion)
	}

	r3 := f.Replace[3]
	if !r3.IsLocal() || r3.NewPath != "../vendor/one" {
		t.Errorf("replace[3] = %+v", r3)
	}

	r4 := f.Replace[4]
	if r4.OldVersion != "v1.0.0" || r4.NewVersion != "v1.0.1" {
		t.Errorf("replace[4] = %+v", r4)
	}
}

func TestParseExcludeAndRetract(t *testing.T) {
	src := `module m

go 1.22

exclude (
	github.com/a/a v1.1.5 // has breaking changes
	github.com/a/a v1.1.6
)

retract (
	v1.0.0 // published accidentally
	[v1.1.0, v1.2.0] // security issue, see CVE-xxxx
)

retract v0.9.0
`
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.Exclude) != 2 {
		t.Fatalf("got %d excludes, want 2", len(f.Exclude))
	}
	if f.Exclude[0].Version != "v1.1.5" || f.Exclude[1].Version != "v1.1.6" {
		t.Errorf("excludes = %+v", f.Exclude)
	}

	if len(f.Retract) != 3 {
		t.Fatalf("got %d retracts, want 3", len(f.Retract))
	}
	if f.Retract[0].Low != "v1.0.0" || f.Retract[0].IsRange() {
		t.Errorf("retract[0] = %+v", f.Retract[0])
	}
	if f.Retract[0].Rationale != "published accidentally" {
		t.Errorf("retract[0].Rationale = %q", f.Retract[0].Rationale)
	}
	if !f.Retract[1].IsRange() || f.Retract[1].Low != "v1.1.0" || f.Retract[1].High != "v1.2.0" {
		t.Errorf("retract[1] = %+v", f.Retract[1])
	}
	if f.Retract[2].Low != "v0.9.0" || f.Retract[2].IsRange() {
		t.Errorf("retract[2] = %+v", f.Retract[2])
	}
}

func TestParseQuotedTokens(t *testing.T) {
	src := "module \"github.com/example/thing with space\"\n\ngo 1.22\n"
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Module != "github.com/example/thing with space" {
		t.Errorf("Module = %q", f.Module)
	}
}

func TestParseIgnoresUnknownDirectives(t *testing.T) {
	// godebug and tool are newer directives this tool doesn't need to
	// understand; the parser must not choke on them.
	src := `module m

go 1.24

godebug (
	winsymlink=0
)

tool github.com/x/y/cmd/z

require github.com/a/a v1.0.0
`
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.Require) != 1 {
		t.Errorf("Require = %+v", f.Require)
	}
}

func TestLooksLikeGoMod(t *testing.T) {
	if !LooksLikeGoMod([]byte("module m\n\ngo 1.22\n")) {
		t.Errorf("valid go.mod content not recognized")
	}
	if LooksLikeGoMod([]byte(`{"name": "not-a-go-mod"}`)) {
		t.Errorf("JSON content should not be recognized as go.mod")
	}
	if LooksLikeGoMod([]byte("")) {
		t.Errorf("empty content should not be recognized as go.mod")
	}
}

func TestIsLocalPath(t *testing.T) {
	cases := map[string]bool{
		"./foo":                 true,
		"../foo/bar":            true,
		".":                     true,
		"..":                    true,
		"/abs/path":             true,
		`C:\foo\bar`:            true,
		"github.com/foo/bar":    false,
		"github.com/foo/../bar": false, // does not start with ./ or ../
	}
	for in, want := range cases {
		if got := IsLocalPath(in); got != want {
			t.Errorf("IsLocalPath(%q) = %v, want %v", in, got, want)
		}
	}
}

// --- Cross-check against `go mod edit -json`, the toolchain's own parser ---
//
// This never shells out from the tool itself (see the package doc and the
// project README for why); it's only used here, in tests, to confirm this
// hand-written parser agrees with the real thing on real go.mod files.

type editJSON struct {
	Module struct {
		Path string
	}
	Go      string
	Require []struct {
		Path     string
		Version  string
		Indirect bool
	}
	Replace []struct {
		Old struct {
			Path    string
			Version string
		}
		New struct {
			Path    string
			Version string
		}
	}
	Exclude []struct {
		Path    string
		Version string
	}
}

func runGoModEditJSON(t *testing.T, data []byte) editJSON {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), data, 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	cmd := exec.Command("go", "mod", "edit", "-json")
	cmd.Dir = dir
	// Force use of whatever toolchain is already installed and never let a
	// go-directive mismatch trigger a network download; a real go.mod's own
	// "go"/"toolchain" directive is irrelevant to what's being cross-checked
	// here (parsing require/replace/exclude), so no download should ever be
	// needed, but these two env vars make that a guarantee, not a hope.
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go mod edit -json: %v: %s", err, ee.Stderr)
		}
		t.Fatalf("go mod edit -json: %v", err)
	}
	var ej editJSON
	if err := json.Unmarshal(out, &ej); err != nil {
		t.Fatalf("unmarshal go mod edit -json output: %v", err)
	}
	return ej
}

func TestRealFixturesAgainstGoModEdit(t *testing.T) {
	entries, err := os.ReadDir("../../testdata/real")
	if err != nil {
		t.Fatalf("read testdata/real: %v", err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		found++
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../testdata/real", name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			// The point of these fixtures is that they are NOT named
			// go.mod on disk, yet this parser must still treat them as
			// go.mod content (see the project's "detect format from
			// content, not filename" requirement).
			if filepath.Ext(name) == ".mod" || name == "go.mod" {
				t.Fatalf("fixture %q defeats the point: it must not be named like a go.mod file", name)
			}
			if !LooksLikeGoMod(data) {
				t.Fatalf("LooksLikeGoMod(%q) = false", name)
			}

			got, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			want := runGoModEditJSON(t, data)

			if got.Module != want.Module.Path {
				t.Errorf("Module = %q, want %q", got.Module, want.Module.Path)
			}

			gotReq := map[string]Require{}
			for _, r := range got.Require {
				gotReq[r.Path] = r
			}
			if len(got.Require) != len(want.Require) {
				t.Errorf("Require count = %d, want %d", len(got.Require), len(want.Require))
			}
			for _, w := range want.Require {
				g, ok := gotReq[w.Path]
				if !ok {
					t.Errorf("missing require %s", w.Path)
					continue
				}
				if g.Version != w.Version || g.Indirect != w.Indirect {
					t.Errorf("require %s = {%s indirect=%v}, want {%s indirect=%v}",
						w.Path, g.Version, g.Indirect, w.Version, w.Indirect)
				}
			}

			if len(got.Replace) != len(want.Replace) {
				t.Errorf("Replace count = %d, want %d", len(got.Replace), len(want.Replace))
			}
			gotRep := map[string]Replace{}
			for _, r := range got.Replace {
				gotRep[r.Key()] = r
			}
			for _, w := range want.Replace {
				key := w.Old.Path
				if w.Old.Version != "" {
					key = w.Old.Path + "@" + w.Old.Version
				}
				g, ok := gotRep[key]
				if !ok {
					t.Errorf("missing replace for %s", key)
					continue
				}
				if g.NewPath != w.New.Path || g.NewVersion != w.New.Version {
					t.Errorf("replace %s => {%s %s}, want {%s %s}",
						key, g.NewPath, g.NewVersion, w.New.Path, w.New.Version)
				}
			}

			if len(got.Exclude) != len(want.Exclude) {
				t.Errorf("Exclude count = %d, want %d", len(got.Exclude), len(want.Exclude))
			}
			gotExc := map[string]bool{}
			for _, e := range got.Exclude {
				gotExc[e.Path+"@"+e.Version] = true
			}
			for _, w := range want.Exclude {
				if !gotExc[w.Path+"@"+w.Version] {
					t.Errorf("missing exclude %s@%s", w.Path, w.Version)
				}
			}
		})
	}
	if found == 0 {
		t.Fatal("no real fixtures found in testdata/real")
	}
	t.Logf("cross-checked %d real go.mod fixtures against `go mod edit -json`", found)
}

func TestCompareVersionsAgainstGoListSort(t *testing.T) {
	// A second, independent cross-check: `go list -m` (via `go mod edit
	// -json` isn't suitable for ordering) is overkill here, so this test
	// instead pins down documented Go semver precedence examples plus a
	// pseudo-version pair, and additionally sorts a slice with Compare and
	// checks it against a manually-verified expected order.
	versions := []string{
		"v1.2.3",
		"v1.2.3-beta",
		"v1.2.3-alpha.1",
		"v1.2.3-alpha.10",
		"v1.2.3-alpha.2",
		"v1.0.0",
		"v2.0.0",
		"v0.0.0-20200101000000-aaaaaaaaaaaa",
		"v0.0.0-20240101000000-bbbbbbbbbbbb",
	}
	want := []string{
		"v0.0.0-20200101000000-aaaaaaaaaaaa",
		"v0.0.0-20240101000000-bbbbbbbbbbbb",
		"v1.0.0",
		"v1.2.3-alpha.1",
		"v1.2.3-alpha.2",
		"v1.2.3-alpha.10",
		"v1.2.3-beta",
		"v1.2.3",
		"v2.0.0",
	}
	got := append([]string(nil), versions...)
	sort.Slice(got, func(i, j int) bool {
		return Compare(got[i], got[j]) == Lower
	})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sorted = %v\nwant   = %v", got, want)
	}
}
