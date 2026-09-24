package osquery

import (
	"context"
	"errors"
	"testing"
)

func TestValidateQuery(t *testing.T) {
	ok := []string{
		"SELECT name, version FROM apps",
		"select pid, name from processes;",
		"WITH x AS (SELECT 1) SELECT * FROM x",
		"SELECT replace(name, 'a', 'b') FROM apps",
		"SELECT auto_update FROM chrome_extensions",
	}
	for _, q := range ok {
		if err := ValidateQuery(q); err != nil {
			t.Errorf("%q rejected: %v", q, err)
		}
	}
	bad := []string{
		"",
		"DELETE FROM carves",
		"SELECT 1; DROP TABLE x",
		"ATTACH '/tmp/x.db' AS x",
		"select * from x where 1; select 2",
		"INSERT INTO t VALUES (1)",
		"PRAGMA table_info(apps)",
	}
	for _, q := range bad {
		if err := ValidateQuery(q); err == nil {
			t.Errorf("%q accepted", q)
		}
	}
}

func TestDisabled(t *testing.T) {
	m := New("disabled")
	if m.Available() {
		t.Fatal("disabled manager reports available")
	}
	if _, err := m.Query(context.Background(), "SELECT 1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}
