package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sundi133/nexus-agent/internal/api"
)

const (
	maxOsqueryRows    = 5000
	maxNotifyTitle    = 80
	maxNotifyMessage  = 500
	executedRetention = 24 * time.Hour
)

// pollCommands fetches and executes pending commands.
func (a *Agent) pollCommands(ctx context.Context) error {
	cmds, err := a.client.FetchCommands(ctx)
	if err != nil {
		return a.handleAuthError(ctx, err)
	}
	a.markSync("commands")
	for _, cmd := range cmds {
		if a.alreadyExecuted(cmd.ID) {
			continue
		}
		res := a.execute(ctx, cmd)
		res.Finished = time.Now().UTC()
		a.log.Info("command finished", "id", cmd.ID, "type", cmd.Type, "status", res.Status, "err", res.Error)
		if err := a.client.ReportCommandResult(ctx, cmd.ID, res); err != nil {
			a.log.Warn("report command result failed", "id", cmd.ID, "err", err)
		}
	}
	return nil
}

// alreadyExecuted provides at-most-once execution even if a result report
// fails and the cloud re-sends the command.
func (a *Agent) alreadyExecuted(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, t := range a.executed {
		if now.Sub(t) > executedRetention {
			delete(a.executed, k)
		}
	}
	if _, ok := a.executed[id]; ok {
		return true
	}
	a.executed[id] = now
	return false
}

// execute dispatches a command from the fixed allow-list. There is
// intentionally no "run shell command" type.
func (a *Agent) execute(ctx context.Context, cmd api.Command) api.CommandResult {
	if !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt) {
		return api.CommandResult{Status: "rejected", Error: "command expired"}
	}
	var (
		out any
		err error
	)
	switch cmd.Type {
	case api.CmdCollectTelemetry:
		trigger(a.kickTelemetry)
	case api.CmdRefreshPolicy:
		trigger(a.kickPolicy)
	case api.CmdCheckUpdate:
		trigger(a.kickUpdate)
	case api.CmdOsqueryQuery:
		out, err = a.cmdOsquery(ctx, cmd.Args)
	case api.CmdLockScreen:
		err = a.plat.LockScreen(ctx)
	case api.CmdNotifyUser:
		err = a.cmdNotify(ctx, cmd.Args)
	default:
		return api.CommandResult{Status: "rejected", Error: fmt.Sprintf("unsupported command type %q", cmd.Type)}
	}
	if err != nil {
		return api.CommandResult{Status: "error", Error: err.Error()}
	}
	res := api.CommandResult{Status: "ok"}
	if out != nil {
		res.Output, _ = json.Marshal(out)
	}
	return res
}

func (a *Agent) cmdOsquery(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		SQL string `json:"sql"`
	}
	if err := json.Unmarshal(raw, &args); err != nil || args.SQL == "" {
		return nil, errors.New(`args must be {"sql": "SELECT ..."}`)
	}
	rows, err := a.osq.Query(ctx, args.SQL)
	if err != nil {
		return nil, err
	}
	truncated := false
	if len(rows) > maxOsqueryRows {
		rows, truncated = rows[:maxOsqueryRows], true
	}
	return map[string]any{"rows": rows, "truncated": truncated}, nil
}

func (a *Agent) cmdNotify(ctx context.Context, raw json.RawMessage) error {
	var args struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &args); err != nil || args.Message == "" {
		return errors.New(`args must be {"title": "...", "message": "..."}`)
	}
	if args.Title == "" {
		args.Title = "Votal"
	}
	return a.plat.Notify(ctx, truncate(args.Title, maxNotifyTitle), truncate(args.Message, maxNotifyMessage))
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
