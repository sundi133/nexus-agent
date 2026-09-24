package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadExample(t *testing.T) *Bundle {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle Bundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	return &bundle
}

func TestProductionDatabaseScenario(t *testing.T) {
	b := loadExample(t)
	env := Environment{OS: "macos"}
	cases := []struct {
		name    string
		req     Request
		want    string
		policy  string
		monitor bool
	}{
		{"engineer AI read prod", Request{User: "alice", AgentType: "ai_coding_agent", Resource: "production_database", Action: "read"}, Allow, "pol_prod_db", false},
		{"engineer AI write prod", Request{User: "alice", AgentType: "ai_coding_agent", Resource: "production_database", Action: "write"}, Deny, "pol_prod_db", false},
		{"engineer AI delete prod (case-insensitive)", Request{User: "alice", AgentType: "ai_assistant", Resource: "PRODUCTION_DATABASE", Action: "DELETE"}, Deny, "pol_prod_db", false},
		{"wildcard resource", Request{User: "alice", AgentType: "local_llm", Resource: "db:prod/customers", Action: "export"}, Deny, "pol_prod_db", false},
		{"non-AI caller unaffected", Request{User: "alice", Resource: "production_database", Action: "write"}, Allow, "", false},
		{"other group falls to default", Request{User: "bob", AgentType: "ai_coding_agent", Resource: "production_database", Action: "write"}, Allow, "", false},
		{"monitor mode does not block", Request{User: "alice", AgentType: "ai_coding_agent", Tool: "github.create_pr", Resource: "github:acme/api", Action: "merge"}, Allow, "", true},
		{"monitor ignores other agent types", Request{User: "alice", AgentType: "ai_assistant", Tool: "github.create_pr", Resource: "github:acme/api", Action: "merge"}, Allow, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(b, env, tc.req)
			if got.Decision != tc.want || got.PolicyID != tc.policy || got.MonitorDeny != tc.monitor {
				t.Fatalf("got %+v", got)
			}
			if got.BundleVersion != b.Version {
				t.Errorf("bundle version not reported")
			}
		})
	}
}

func TestUnmanagedDeviceBlocksAllAI(t *testing.T) {
	b := loadExample(t)
	b.Device.Managed = false
	got := Evaluate(b, Environment{}, Request{User: "alice", AgentType: "ai_coding_agent", Resource: "anything", Action: "read"})
	if got.Decision != Deny || got.PolicyID != "pol_unmanaged_block" {
		t.Fatalf("got %+v", got)
	}
}

func TestDenyWinsOverAllowRegardlessOfOrder(t *testing.T) {
	b := &Bundle{Version: "1", Policies: []Policy{
		{ID: "allow_all", Actions: []string{"*"}},
		{ID: "deny_write", Resources: []string{"secrets/*"}, Deny: []string{"write"}},
	}}
	got := Evaluate(b, Environment{}, Request{Resource: "secrets/prod", Action: "write"})
	if got.Decision != Deny || got.PolicyID != "deny_write" {
		t.Fatalf("got %+v", got)
	}
}

func TestDefaultDenyAndFailClosed(t *testing.T) {
	b := &Bundle{Version: "1", DefaultDecision: Deny}
	if got := Evaluate(b, Environment{}, Request{Resource: "x", Action: "read"}); got.Decision != Deny {
		t.Fatalf("default deny: %+v", got)
	}
	if got := Evaluate(nil, Environment{}, Request{Resource: "x", Action: "read"}); got.Decision != Deny {
		t.Fatalf("nil bundle must deny: %+v", got)
	}
	if got := Evaluate(&Bundle{}, Environment{}, Request{Action: "read"}); got.Decision != Deny {
		t.Fatalf("missing resource must deny: %+v", got)
	}
}

func TestConditions(t *testing.T) {
	maxRisk := 50
	b := &Bundle{
		Device:    DeviceContext{Managed: true, Groups: []string{"laptops"}, RiskScore: 80},
		Directory: map[string][]string{"carol": {"sre"}},
		Policies: []Policy{
			{ID: "risky", Conditions: Conditions{Device: &DeviceConditions{MaxRiskScore: &maxRisk}}, Actions: []string{"read"}},
			{ID: "os", Conditions: Conditions{Device: &DeviceConditions{OS: []string{"windows"}}}, Deny: []string{"read"}},
			{ID: "sre", Conditions: Conditions{User: &UserConditions{Groups: []string{"sre"}}, Agent: &AgentConditions{IDs: []string{"cursor"}}}, Actions: []string{"deploy"}},
		},
		DefaultDecision: Deny,
	}
	// Risk 80 > 50 so "risky" does not apply; on macOS "os" does not apply.
	if got := Evaluate(b, Environment{OS: "macos"}, Request{Resource: "r", Action: "read"}); got.Decision != Deny || got.PolicyID != "" {
		t.Fatalf("risk condition: %+v", got)
	}
	if got := Evaluate(b, Environment{OS: "windows"}, Request{Resource: "r", Action: "read"}); got.PolicyID != "os" {
		t.Fatalf("os condition: %+v", got)
	}
	if got := Evaluate(b, Environment{}, Request{User: "carol", AgentID: "cursor", Resource: "k8s", Action: "deploy"}); got.Decision != Allow {
		t.Fatalf("group+agent id: %+v", got)
	}
	// Groups come from the directory, never from the request.
	if got := Evaluate(b, Environment{}, Request{User: "mallory", AgentID: "cursor", Resource: "k8s", Action: "deploy"}); got.Decision != Deny {
		t.Fatalf("unknown user must not match group: %+v", got)
	}
}

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true},
		{"github:*", "github:acme/api", true},
		{"db:prod/*", "db:prod/users", true},
		{"db:prod/*", "db:staging/users", false},
		{"*.internal", "pg.db.internal", true},
		{"file?.txt", "file1.txt", true},
		{"file?.txt", "file10.txt", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
	}
	for _, c := range cases {
		if got := wildcardMatch(c.p, c.s); got != c.want {
			t.Errorf("wildcardMatch(%q,%q)=%v want %v", c.p, c.s, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := []Bundle{
		{DefaultDecision: "maybe"},
		{Policies: []Policy{{Actions: []string{"read"}}}},
		{Policies: []Policy{{ID: "a", Actions: []string{"r"}}, {ID: "a", Actions: []string{"r"}}}},
		{Policies: []Policy{{ID: "a", Mode: "audit", Actions: []string{"r"}}}},
		{Policies: []Policy{{ID: "a"}}},
		{Policies: []Policy{{ID: "a", Actions: []string{"r"}, Resources: []string{" "}}}},
	}
	for i, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestStorePersistsAndRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := s.Get(); b != nil {
		t.Fatal("expected empty store")
	}
	good := &Bundle{Version: "v1", Policies: []Policy{{ID: "p", Actions: []string{"read"}}}}
	if err := s.Set(good, `"v1"`); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(&Bundle{DefaultDecision: "nope"}, `"v2"`); err == nil {
		t.Fatal("invalid bundle accepted")
	}
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	b, etag := s2.Get()
	if b == nil || b.Version != "v1" || etag != `"v1"` {
		t.Fatalf("reload: %+v %q", b, etag)
	}
	if st, _ := os.Stat(path); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("policy cache is group/world readable: %v", st.Mode())
	}
	// Corrupt cache must not break startup.
	os.WriteFile(path, []byte("{garbage"), 0o600)
	if _, err := NewStore(path); err != nil {
		t.Fatalf("corrupt cache: %v", err)
	}
}
