package agent

import (
	"context"
	"time"
)

const uploadBatchSize = 200

// collectAndUpload gathers a full snapshot and ships everything queued.
func (a *Agent) collectAndUpload(ctx context.Context) error {
	start := time.Now()
	res := a.collector.Collect(ctx, a.DeviceID())
	a.mu.Lock()
	a.aiAgents = res.AIAgents
	a.mu.Unlock()
	a.buffer.Add(res.Events...)
	a.log.Debug("telemetry collected", "events", len(res.Events), "ai_agents", len(res.AIAgents), "took", time.Since(start))
	if err := a.flushTelemetry(ctx); err != nil {
		return err
	}
	a.markSync("telemetry")
	return nil
}

// flushTelemetry uploads queued events in batches; failed batches are
// requeued for the next attempt.
func (a *Agent) flushTelemetry(ctx context.Context) error {
	deviceID := a.DeviceID()
	if deviceID == "" {
		return nil
	}
	for a.buffer.Len() > 0 {
		batch := a.buffer.Take(uploadBatchSize)
		// Decisions made before enrollment finished were queued without an ID.
		for i := range batch {
			if batch[i].DeviceID == "" {
				batch[i].DeviceID = deviceID
			}
		}
		uctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err := a.client.SendTelemetry(uctx, batch)
		cancel()
		if err != nil {
			a.buffer.Requeue(batch)
			return a.handleAuthError(ctx, err)
		}
	}
	return nil
}
