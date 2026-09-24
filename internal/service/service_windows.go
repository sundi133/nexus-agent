//go:build windows

package service

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/sys/windows/svc"
)

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

func run(fn RunFunc) error {
	if !isService() {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return fn(ctx)
	}
	h := &handler{fn: fn}
	if err := svc.Run(Name, h); err != nil {
		return err
	}
	return h.err
}

type handler struct {
	fn  RunFunc
	err error
}

// Execute implements svc.Handler.
func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
			h.err = err
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				// Non-zero exit lets SCM recovery actions restart the service
				// (configured by the MSI), e.g. after a self-update.
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				h.err = <-done
				return false, 0
			}
		}
	}
}
