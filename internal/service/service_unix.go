//go:build !windows

package service

import (
	"context"
	"os/signal"
	"syscall"
)

func isService() bool { return false }

func run(fn RunFunc) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return fn(ctx)
}
