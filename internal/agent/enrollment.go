package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sundi133/nexus-agent/internal/api"
	"github.com/sundi133/nexus-agent/internal/version"
)

// Identity is the device credential issued at enrollment. It is stored in
// the state directory with 0600 permissions (root/SYSTEM only).
type Identity struct {
	DeviceID   string    `json:"device_id"`
	AgentToken string    `json:"agent_token"`
	OrgID      string    `json:"org_id,omitempty"`
	ServerURL  string    `json:"server_url"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

func (a *Agent) identityPath() string { return filepath.Join(a.cfg.StateDir, "identity.json") }

func (a *Agent) loadIdentity() (*Identity, error) {
	b, err := os.ReadFile(a.identityPath())
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("corrupt identity file: %w", err)
	}
	if id.DeviceID == "" || id.AgentToken == "" {
		return nil, errors.New("identity file is incomplete")
	}
	// An identity issued by a different server is not valid here.
	if id.ServerURL != "" && id.ServerURL != a.cfg.ServerURL {
		return nil, fmt.Errorf("identity belongs to %s, not %s", id.ServerURL, a.cfg.ServerURL)
	}
	return &id, nil
}

func (a *Agent) saveIdentity(id *Identity) error {
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(a.identityPath(), b, 0o600)
}

// hashedHardwareID avoids sending the raw machine GUID/UUID; the cloud only
// needs a stable, unique value to de-duplicate re-enrollments.
func hashedHardwareID(raw string) string {
	sum := sha256.Sum256([]byte("votal:" + raw))
	return hex.EncodeToString(sum[:])
}

// Enroll loads an existing identity or registers with the cloud. It retries
// with backoff until it succeeds or ctx is cancelled.
func (a *Agent) Enroll(ctx context.Context) error {
	if id, err := a.loadIdentity(); err == nil {
		a.setIdentity(id)
		a.log.Info("using existing enrollment", "device_id", id.DeviceID)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		a.log.Warn("ignoring stored identity", "err", err)
	}
	if a.cfg.EnrollmentToken == "" {
		return errors.New("device is not enrolled and no enrollment_token is configured")
	}

	backoff := newBackoff(2*time.Second, 5*time.Minute)
	for {
		err := a.enrollOnce(ctx)
		if err == nil {
			return nil
		}
		if errors.Is(err, api.ErrUnauthorized) {
			// A bad token will not fix itself; surface it immediately.
			return fmt.Errorf("enrollment rejected: check enrollment_token: %w", err)
		}
		wait := backoff.next()
		a.log.Warn("enrollment failed; retrying", "err", err, "in", wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (a *Agent) enrollOnce(ctx context.Context) error {
	info, err := a.plat.DeviceInfo(ctx)
	if err != nil {
		return fmt.Errorf("device info: %w", err)
	}
	hw, err := a.plat.HardwareID(ctx)
	if err != nil {
		// Fall back to hostname; the cloud can merge duplicates later.
		a.log.Warn("hardware id unavailable; falling back to hostname", "err", err)
		hw = "hostname:" + info.Hostname
	}
	resp, err := a.client.Enroll(ctx, api.EnrollRequest{
		EnrollmentToken: a.cfg.EnrollmentToken,
		HardwareID:      hashedHardwareID(hw),
		Device:          info,
		AgentVersion:    version.Version,
	})
	if err != nil {
		return err
	}
	id := &Identity{
		DeviceID:   resp.DeviceID,
		AgentToken: resp.AgentToken,
		OrgID:      resp.OrgID,
		ServerURL:  a.cfg.ServerURL,
		EnrolledAt: time.Now().UTC(),
	}
	if err := a.saveIdentity(id); err != nil {
		return fmt.Errorf("persist identity: %w", err)
	}
	a.setIdentity(id)
	a.log.Info("enrolled", "device_id", id.DeviceID, "org_id", id.OrgID)
	return nil
}

func (a *Agent) setIdentity(id *Identity) {
	a.mu.Lock()
	a.identity = id
	a.mu.Unlock()
	a.client.SetCredentials(id.DeviceID, id.AgentToken)
}

// DeviceID returns the enrolled device ID ("" before enrollment).
func (a *Agent) DeviceID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.identity == nil {
		return ""
	}
	return a.identity.DeviceID
}

// reenroll discards a revoked identity and enrolls again.
func (a *Agent) reenroll(ctx context.Context) error {
	a.log.Warn("agent credentials rejected; re-enrolling")
	if err := os.Remove(a.identityPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return a.Enroll(ctx)
}
