// Command echo-runner is P05's runner (internal/runner): started by the dispatcher as a Cloud Run
// job execution, it takes one claimed dev ticket to review with an echo commit and no model, or to
// escalated when the ticket's title asks, storing its transcript in the artifacts bucket (P06). Its
// configuration is its environment (runner.FromEnv); it logs JSON to standard error and exits 0
// when the commit was submitted or escalated, 1 when the run stopped, and 2 when it could not
// start.
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ryanymt/mercurio-project/internal/runner"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Getenv, os.Stderr))
}

func run(ctx context.Context, getenv func(string) string, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := runner.FromEnv(getenv)
	if err != nil {
		log.Error("the echo runner cannot start", "error", err)
		return 2
	}
	cfg.Log = log
	if err := runner.Run(ctx, cfg); err != nil {
		log.Error("the echo runner stopped", "ticket", cfg.Request.TicketID, "error", err)
		return 1
	}
	return 0
}
