// Command modreplace-audit flags what changed in a go.mod's replace,
// exclude and retract directives between two revisions — the one
// Go-specific supply-chain redirection mechanism that dependency-review
// tools built around resolved dependency sets don't look at. See the
// project README for why that gap exists.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/agentscope-ai-java/modreplace-audit/internal/audit"
	"github.com/agentscope-ai-java/modreplace-audit/internal/gomod"
	"github.com/agentscope-ai-java/modreplace-audit/internal/gosum"
)

const usageTemplate = `modreplace-audit — flag what changed in a go.mod's replace/exclude/retract directives

Usage:
  modreplace-audit [go.mod path] --base <ref-or-path>   # git ref (default HEAD), or a file path
  modreplace-audit <base-file> <head-file>              # two files directly, no git required

Flags:
  --base <ref-or-path>   What to diff against (default "HEAD"). A git ref resolved via
                          "git show <ref>:<path>", or a literal file path if one exists on disk.
                          Ignored (and an error) if two positional files are given.
  --json                  Print the full result as JSON instead of the text summary.
  --fail-on <signals>     Comma-separated signal kinds that make the exit code 1. Default: none.
  --help                  Print this message.

Signal kinds, in priority order: %s

Exit codes: 0 clean run (nothing matched --fail-on), 1 a --fail-on signal was found, 2 usage or read/parse error.
`

func usage() string {
	kinds := make([]string, len(audit.AllFailOnKinds))
	for i, k := range audit.AllFailOnKinds {
		kinds[i] = string(k)
	}
	return fmt.Sprintf(usageTemplate, strings.Join(kinds, ", "))
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type args struct {
	positional []string
	base       string
	baseSet    bool
	jsonOut    bool
	failOn     []string
	help       bool
}

func parseArgs(raw []string) (args, error) {
	a := args{base: "HEAD"}
	for i := 0; i < len(raw); i++ {
		tok := raw[i]
		switch {
		case tok == "--help" || tok == "-h":
			a.help = true
		case tok == "--json":
			a.jsonOut = true
		case tok == "--base":
			i++
			if i >= len(raw) {
				return a, fmt.Errorf("--base requires a value")
			}
			a.base, a.baseSet = raw[i], true
		case strings.HasPrefix(tok, "--base="):
			a.base, a.baseSet = strings.TrimPrefix(tok, "--base="), true
		case tok == "--fail-on":
			i++
			if i >= len(raw) {
				return a, fmt.Errorf("--fail-on requires a value")
			}
			a.failOn = splitCSV(raw[i])
		case strings.HasPrefix(tok, "--fail-on="):
			a.failOn = splitCSV(strings.TrimPrefix(tok, "--fail-on="))
		case strings.HasPrefix(tok, "-"):
			return a, fmt.Errorf("unknown flag %q", tok)
		default:
			a.positional = append(a.positional, tok)
		}
	}
	return a, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func run(rawArgs []string, stdout, stderr io.Writer) int {
	a, err := parseArgs(rawArgs)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, usage())
		return 2
	}
	if a.help {
		fmt.Fprint(stdout, usage())
		return 0
	}
	if len(a.positional) > 2 {
		fmt.Fprintln(stderr, "too many arguments")
		fmt.Fprint(stderr, usage())
		return 2
	}

	var headPath string
	var headData, baseData []byte
	var baseDescr string

	switch len(a.positional) {
	case 2:
		if a.baseSet {
			fmt.Fprintln(stderr, "--base is not used with two file arguments")
			return 2
		}
		baseFile, headFile := a.positional[0], a.positional[1]
		baseData, err = os.ReadFile(baseFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		headData, err = os.ReadFile(headFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		headPath = headFile
		baseDescr = baseFile
	case 0, 1:
		headPath = "go.mod"
		if len(a.positional) == 1 {
			headPath = a.positional[0]
		}
		headData, err = os.ReadFile(headPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		baseData, baseDescr, err = resolveBase(a.base, headPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}

	headMod, err := gomod.Parse(headData)
	if err != nil || !gomod.LooksLikeGoMod(headData) {
		fmt.Fprintf(stderr, "%s does not look like a go.mod file", headPath)
		if err != nil {
			fmt.Fprintf(stderr, ": %v", err)
		}
		fmt.Fprintln(stderr)
		return 2
	}
	baseMod, err := gomod.Parse(baseData)
	if err != nil || !gomod.LooksLikeGoMod(baseData) {
		fmt.Fprintf(stderr, "%s does not look like a go.mod file", baseDescr)
		if err != nil {
			fmt.Fprintf(stderr, ": %v", err)
		}
		fmt.Fprintln(stderr)
		return 2
	}

	var headSum *gosum.File
	if len(a.positional) != 2 {
		if data, err := os.ReadFile(filepath.Join(filepath.Dir(headPath), "go.sum")); err == nil {
			if parsed, err := gosum.Parse(data); err == nil {
				headSum = parsed
			}
		}
	} else {
		if data, err := os.ReadFile(filepath.Join(filepath.Dir(a.positional[1]), "go.sum")); err == nil {
			if parsed, err := gosum.Parse(data); err == nil {
				headSum = parsed
			}
		}
	}

	opts := audit.Options{GoFlags: os.Getenv("GOFLAGS")}
	vendorPath := filepath.Join(filepath.Dir(headPath), "vendor", "modules.txt")
	if len(a.positional) == 2 {
		vendorPath = filepath.Join(filepath.Dir(a.positional[1]), "vendor", "modules.txt")
	}
	if data, err := os.ReadFile(vendorPath); err == nil {
		opts.VendorModulesTxt = data
	}

	result := audit.Run(baseMod, headMod, nil, headSum, opts)

	failSet := map[audit.Kind]bool{}
	for _, f := range a.failOn {
		failSet[audit.Kind(f)] = true
	}
	failed := false
	for _, sig := range result.Signals {
		for _, k := range sig.Kinds {
			if failSet[k] {
				failed = true
			}
		}
	}

	if a.jsonOut {
		printJSON(stdout, result, a.failOn, failed)
	} else {
		printText(stdout, result, baseDescr)
	}

	if failed {
		return 1
	}
	return 0
}

func resolveBase(base, path string) (data []byte, descr string, err error) {
	if info, statErr := os.Stat(base); statErr == nil && !info.IsDir() {
		data, err = os.ReadFile(base)
		return data, base, err
	}
	data, err = gitShow(base, path)
	return data, base + ":" + path, err
}

func gitShow(ref, path string) ([]byte, error) {
	cmd := exec.Command("git", "show", ref+":"+path)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git show %s:%s: %w: %s", ref, path, err, strings.TrimSpace(errBuf.String()))
	}
	return out.Bytes(), nil
}

func printText(w io.Writer, res audit.Result, baseDescr string) {
	total := res.ReplaceAdded + res.ReplaceChanged + res.ReplaceRemoved + res.ReplaceUnchanged
	fmt.Fprintf(w, "replace directives: %d total (%d added, %d changed, %d removed, %d unchanged) vs %s\n\n",
		total, res.ReplaceAdded, res.ReplaceChanged, res.ReplaceRemoved, res.ReplaceUnchanged, baseDescr)

	if len(res.Signals) == 0 {
		fmt.Fprintln(w, "no signals")
		return
	}
	for _, sig := range res.Signals {
		fmt.Fprintf(w, "%-16s %s\n", labelOf(sig), sig.Message)
	}
}

func labelOf(sig audit.Signal) string {
	labels := make([]string, len(sig.Kinds))
	for i, k := range sig.Kinds {
		labels[i] = strings.ToUpper(string(k))
	}
	sort.Strings(labels)
	return strings.Join(labels, "+")
}

type jsonSignal struct {
	Kinds   []string `json:"kinds"`
	Path    string   `json:"path,omitempty"`
	Message string   `json:"message"`
}

type jsonReport struct {
	Signals []jsonSignal `json:"signals"`
	Counts  struct {
		ReplaceAdded     int `json:"replaceAdded"`
		ReplaceChanged   int `json:"replaceChanged"`
		ReplaceRemoved   int `json:"replaceRemoved"`
		ReplaceUnchanged int `json:"replaceUnchanged"`
	} `json:"counts"`
	FailOn []string `json:"failOn,omitempty"`
	Failed bool     `json:"failed"`
}

func printJSON(w io.Writer, res audit.Result, failOn []string, failed bool) {
	var rep jsonReport
	for _, s := range res.Signals {
		ks := make([]string, len(s.Kinds))
		for i, k := range s.Kinds {
			ks[i] = string(k)
		}
		rep.Signals = append(rep.Signals, jsonSignal{Kinds: ks, Path: s.Path, Message: s.Message})
	}
	rep.Counts.ReplaceAdded = res.ReplaceAdded
	rep.Counts.ReplaceChanged = res.ReplaceChanged
	rep.Counts.ReplaceRemoved = res.ReplaceRemoved
	rep.Counts.ReplaceUnchanged = res.ReplaceUnchanged
	rep.FailOn = failOn
	rep.Failed = failed

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // messages contain "=>"; no HTML context to protect here
	_ = enc.Encode(rep)
}
