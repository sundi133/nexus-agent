package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sundi133/nexus-agent/internal/version"
)

const maxUpdateBytes = 256 << 20

// checkUpdate downloads, verifies and stages a new agent binary.
//
// Security model: the cloud tells us *where* the update is, but the agent
// only installs a binary whose SHA-256 digest is signed by the release key
// pinned in config (update_public_key). A compromised API or CDN therefore
// cannot push code to endpoints. Without a pinned key, updates are disabled
// and the OS package manager / MDM is expected to upgrade the agent.
func (a *Agent) checkUpdate(ctx context.Context) error {
	if a.cfg.UpdatePublicKey == "" {
		return nil
	}
	pub, err := base64.StdEncoding.DecodeString(a.cfg.UpdatePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("update_public_key is not a base64 ed25519 public key")
	}
	info, err := a.client.CheckUpdate(ctx, runtime.GOOS, runtime.GOARCH, version.Version)
	if err != nil {
		return a.handleAuthError(ctx, err)
	}
	a.markSync("updates")
	if !info.Available || info.Version == "" || compareVersions(info.Version, version.Version) <= 0 {
		return nil // never downgrade
	}
	a.log.Info("update available", "current", version.Version, "new", info.Version)

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	staged, err := a.downloadVerified(ctx, info.URL, info.SHA256, info.Signature, ed25519.PublicKey(pub), filepath.Dir(exe))
	if err != nil {
		return fmt.Errorf("update %s: %w", info.Version, err)
	}
	if err := replaceExecutable(exe, staged); err != nil {
		os.Remove(staged)
		return fmt.Errorf("install update: %w", err)
	}
	a.log.Info("update installed; restarting", "version", info.Version)
	trigger(a.restart)
	return nil
}

// downloadVerified downloads into dir (same filesystem as the executable, so
// the final rename is atomic) and verifies digest and signature.
func (a *Agent) downloadVerified(ctx context.Context, url, wantHex, sigB64 string, pub ed25519.PublicKey, dir string) (string, error) {
	want, err := hex.DecodeString(strings.ToLower(wantHex))
	if err != nil || len(want) != sha256.Size {
		return "", errors.New("invalid sha256 in update manifest")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", errors.New("invalid signature in update manifest")
	}
	// Check the signature over the manifest digest before downloading anything.
	if !ed25519.Verify(pub, want, sig) {
		return "", errors.New("update signature verification failed")
	}

	f, err := os.CreateTemp(dir, ".votal-agent-update-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	h := sha256.New()
	err = a.client.Download(ctx, url, io.MultiWriter(f, h), maxUpdateBytes)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	if got := h.Sum(nil); !equalBytes(got, want) {
		os.Remove(name)
		return "", fmt.Errorf("sha256 mismatch: got %x", got)
	}
	if err := os.Chmod(name, 0o755); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// replaceExecutable swaps the running binary. Renaming a running executable
// is permitted on macOS, Linux and Windows; the old file is kept as .old for
// rollback and removed on the next successful update.
func replaceExecutable(exe, staged string) error {
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(staged, exe); err != nil {
		_ = os.Rename(old, exe) // roll back
		return err
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
