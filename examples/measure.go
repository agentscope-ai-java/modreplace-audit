// Command measure runs modreplace-audit against a real-world go.mod pair —
// prometheus/prometheus's actual go.mod (264 lines, 150+ requires across
// four require blocks) with three routine patch bumps and one attacker-style
// replace added — and prints how many lines a raw diff makes a reviewer
// read versus how many lines this tool surfaces.
//
// Run with: go run ./examples
package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/agentscope-ai-java/modreplace-audit/internal/audit"
	"github.com/agentscope-ai-java/modreplace-audit/internal/gomod"
)

func main() {
	baseData, err := os.ReadFile("examples/testdata/base.gomod")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	headData, err := os.ReadFile("examples/testdata/head.gomod")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	base, err := gomod.Parse(baseData)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	head, err := gomod.Parse(headData)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	res := audit.Run(base, head, nil, nil, audit.Options{})

	diffLines := 0
	if out, err := exec.Command("diff", "-u", "examples/testdata/base.gomod", "examples/testdata/head.gomod").CombinedOutput(); err == nil || len(out) > 0 {
		for _, b := range out {
			if b == '\n' {
				diffLines++
			}
		}
	}

	baseLines := countLines(baseData)

	fmt.Printf("base go.mod: %d lines (real prometheus/prometheus go.mod)\n", baseLines)
	fmt.Printf("head go.mod: 3 routine patch bumps + 1 replace added\n\n")
	fmt.Printf("raw diff:               %d lines\n", diffLines)
	fmt.Printf("modreplace-audit output: %d signal line(s)\n\n", len(res.Signals))

	for _, sig := range res.Signals {
		fmt.Printf("  %s\n", sig.Message)
	}
}

func countLines(data []byte) int {
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	return n
}
