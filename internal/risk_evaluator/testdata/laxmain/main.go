// laxmain is built by TestLaxPathRefusedOutsideTests: a binary that is not a test binary, calling
// the lax policy loader, which must refuse it (P03 red team round 2, R4).
package main

import (
	"fmt"
	"os"

	riskevaluator "github.com/ryanymt/mercurio-project/internal/risk_evaluator"
)

func main() {
	_, err := riskevaluator.LoadTestPolicy("foreman", []byte(
		"version: 1\nfail_closed: true\nrules:\n  - id: size\n    reason: r\n    match:\n      files_changed_gt: 1\n"))
	if err == nil {
		fmt.Println("the lax path ran")
		os.Exit(0)
	}
	fmt.Println("refused:", err)
	os.Exit(3)
}
