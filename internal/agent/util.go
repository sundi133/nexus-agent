package agent

import (
	"context"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// backoff is a capped exponential backoff with full jitter.
type backoff struct {
	base, max, cur time.Duration
}

func newBackoff(base, max time.Duration) *backoff { return &backoff{base: base, max: max} }

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.base
	} else {
		b.cur *= 2
	}
	if b.cur > b.max {
		b.cur = b.max
	}
	return b.cur/2 + time.Duration(rand.Int64N(int64(b.cur/2)+1))
}

func (b *backoff) reset() { b.cur = 0 }

// jitter spreads a fleet's requests so thousands of agents do not hit the
// cloud in lockstep: returns d ± 10%.
func jitter(d time.Duration) time.Duration {
	spread := int64(d) / 10
	if spread <= 0 {
		return d
	}
	return d - time.Duration(spread) + time.Duration(rand.Int64N(2*spread+1))
}

// loop runs fn immediately, then every interval (jittered), or early when
// kick fires. Errors switch to backoff, capped at the interval.
func (a *Agent) loop(ctx context.Context, name string, interval time.Duration, kick <-chan struct{}, fn func(context.Context) error) {
	bo := newBackoff(5*time.Second, interval)
	for {
		wait := jitter(interval)
		if err := fn(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			wait = bo.next()
			a.log.Warn("loop iteration failed", "loop", name, "err", err, "retry_in", wait.Round(time.Second))
		} else {
			bo.reset()
		}
		select {
		case <-ctx.Done():
			return
		case <-kick:
		case <-time.After(wait):
		}
	}
}

// trigger performs a non-blocking send on a kick channel.
func trigger(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// compareVersions compares dotted numeric versions ("1.10.2" > "1.9.9").
// A leading "v" and any pre-release suffix ("-rc1") are ignored.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var parts []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		parts = append(parts, n)
	}
	return parts
}
