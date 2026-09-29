// protomain is built by TestTestProtocolsRefusedOutsideTests: a binary that is not a test binary,
// asking git to allow the file protocol, which must be refused (P04 D12).
package main

import (
	"fmt"
	"os"

	riskevaluator "github.com/ryanymt/mercurio-project/internal/risk_evaluator"
)

func main() {
	_, err := riskevaluator.NewGit(riskevaluator.DefaultGitTimeout, riskevaluator.DefaultGitMaxOutput).AllowProtocolsForTests("file")
	if err == nil {
		fmt.Println("the file protocol was allowed")
		os.Exit(0)
	}
	fmt.Println("refused:", err)
	os.Exit(3)
}
