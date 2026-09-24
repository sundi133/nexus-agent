package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// ErrUnauthorized is returned when the cloud rejects the agent credentials.
var ErrUnauthorized = errors.New("unauthorized")

// ErrNotModified is returned by FetchPolicy when the ETag matches.
var ErrNotModified = errors.New("not modified")

// HTTPError is a non-2xx response from the cloud.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("http %d: %s", e.Status, e.Body) }

// Client talks to the Votal cloud API.
type Client struct {
	baseURL   string
	http      *http.Client
	userAgent string

	mu       sync.RWMutex
	deviceID string
	token    string
}

// Options configures a Client.
type Options struct {
	BaseURL   string
	CAFile    string
	UserAgent string
	Timeout   time.Duration
}

// NewClient builds a client. TLS 1.2+ is enforced.
func NewClient(opts Options) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL:   opts.BaseURL,
		http:      &http.Client{Transport: tr, Timeout: timeout},
		userAgent: opts.UserAgent,
	}, nil
}

// SetCredentials sets the device identity used for authenticated calls.
func (c *Client) SetCredentials(deviceID, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deviceID, c.token = deviceID, token
}

func (c *Client) creds() (string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.deviceID, c.token
}

func (c *Client) devicePath(suffix string) (string, error) {
	id, _ := c.creds()
	if id == "" {
		return "", errors.New("agent is not enrolled")
	}
	return "/v1/devices/" + url.PathEscape(id) + suffix, nil
}

// do performs a JSON request. in may be nil; out may be nil.
func (c *Client) do(ctx context.Context, method, path string, auth bool, hdr http.Header, in, out any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if auth {
		_, tok := c.creds()
		if tok == "" {
			return nil, errors.New("agent is not enrolled")
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return resp, ErrNotModified
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return resp, ErrUnauthorized
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp, &HTTPError{Status: resp.StatusCode, Body: string(b)}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		// Cap response size to protect the agent from a misbehaving server.
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return resp, fmt.Errorf("decode response: %w", err)
		}
	}
	return resp, nil
}

// Enroll registers this device. It does not require prior credentials.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if _, err := c.do(ctx, http.MethodPost, "/v1/enroll", false, nil, req, &out); err != nil {
		return nil, err
	}
	if out.DeviceID == "" || out.AgentToken == "" {
		return nil, errors.New("enroll: server returned empty device_id or agent_token")
	}
	return &out, nil
}

// Heartbeat reports liveness.
func (c *Client) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	p, err := c.devicePath("/heartbeat")
	if err != nil {
		return nil, err
	}
	var out HeartbeatResponse
	if _, err := c.do(ctx, http.MethodPost, p, true, nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendTelemetry uploads a batch of events.
func (c *Client) SendTelemetry(ctx context.Context, events []Event) error {
	p, err := c.devicePath("/telemetry")
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, p, true, nil, TelemetryBatch{Events: events}, nil)
	return err
}

// FetchPolicy downloads the policy bundle. If etag matches the server's
// current version, ErrNotModified is returned.
func (c *Client) FetchPolicy(ctx context.Context, etag string) (*PolicyResponse, string, error) {
	p, err := c.devicePath("/policy")
	if err != nil {
		return nil, "", err
	}
	hdr := http.Header{}
	if etag != "" {
		hdr.Set("If-None-Match", etag)
	}
	var out PolicyResponse
	resp, err := c.do(ctx, http.MethodGet, p, true, hdr, nil, &out)
	if err != nil {
		return nil, etag, err
	}
	return &out, resp.Header.Get("ETag"), nil
}

// FetchCommands returns pending commands for this device.
func (c *Client) FetchCommands(ctx context.Context) ([]Command, error) {
	p, err := c.devicePath("/commands")
	if err != nil {
		return nil, err
	}
	var out struct {
		Commands []Command `json:"commands"`
	}
	if _, err := c.do(ctx, http.MethodGet, p, true, nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Commands, nil
}

// ReportCommandResult acknowledges a command.
func (c *Client) ReportCommandResult(ctx context.Context, commandID string, res CommandResult) error {
	p, err := c.devicePath("/commands/" + url.PathEscape(commandID) + "/result")
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, p, true, nil, res, nil)
	return err
}

// CheckUpdate asks whether a newer agent build exists.
func (c *Client) CheckUpdate(ctx context.Context, goos, goarch, current string) (*UpdateInfo, error) {
	q := url.Values{"os": {goos}, "arch": {goarch}, "version": {current}}
	var out UpdateInfo
	if _, err := c.do(ctx, http.MethodGet, "/v1/agent/update?"+q.Encode(), true, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Download streams a URL into w, capped at maxBytes. Relative URLs are
// resolved against the server base URL and carry the agent token; absolute
// URLs (e.g. a CDN) are fetched without credentials.
func (c *Client) Download(ctx context.Context, rawURL string, w io.Writer, maxBytes int64) error {
	target := rawURL
	sameOrigin := false
	if u, err := url.Parse(rawURL); err == nil && !u.IsAbs() {
		target = c.baseURL + rawURL
		sameOrigin = true
	}
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && !sameOrigin {
		return errors.New("refusing non-https download")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	if sameOrigin {
		if _, tok := c.creds(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{Status: resp.StatusCode}
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if n > maxBytes {
		return fmt.Errorf("download exceeds %d bytes", maxBytes)
	}
	return nil
}
