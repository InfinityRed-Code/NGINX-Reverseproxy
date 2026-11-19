package audit_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/testutil"
)

func appendN(t *testing.T, st *store.Store, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		err := st.Write(ctx, func(q *dbq.Queries) error {
			_, err := audit.Append(ctx, q, audit.Entry{RequestID: "r", ActorType: "local", ActorID: "uid=0",
				Action: "host.create", ResourceType: "host", ResourceID: "a.example.com", After: map[string]any{"i": i}})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func verify(t *testing.T, st *store.Store) audit.VerifyResult {
	t.Helper()
	res, err := audit.Verify(context.Background(), st.Read())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// raw oeffnet die Datei direkt, um Manipulationen an der DB zu simulieren.
func raw(t *testing.T, st *store.Store, query string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(st.Path(), `\`, "/")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestHashChain(t *testing.T) {
	st := testutil.Store(t)
	if res := verify(t, st); !res.OK || res.Entries != 0 {
		t.Fatalf("leere Kette: %+v", res)
	}
	appendN(t, st, 5)
	res := verify(t, st)
	if !res.OK || res.Entries != 5 || res.FirstSeq != 1 || res.LastSeq != 5 {
		t.Fatalf("intakte Kette: %+v", res)
	}

	t.Run("veraenderter Eintrag", func(t *testing.T) {
		st := testutil.Store(t)
		appendN(t, st, 5)
		raw(t, st, `UPDATE audit_log SET actor_id = 'mallory' WHERE seq = 3`)
		if res := verify(t, st); res.OK || res.BrokenAt == nil || *res.BrokenAt != 3 {
			t.Fatalf("Manipulation nicht erkannt: %+v", res)
		}
	})
	t.Run("geloeschter Eintrag in der Mitte", func(t *testing.T) {
		st := testutil.Store(t)
		appendN(t, st, 5)
		raw(t, st, `DELETE FROM audit_log WHERE seq = 3`)
		if res := verify(t, st); res.OK || *res.BrokenAt != 4 {
			t.Fatalf("Loeschung nicht erkannt: %+v", res)
		}
	})
	t.Run("abgeschnittener Anfang ohne prune", func(t *testing.T) {
		st := testutil.Store(t)
		appendN(t, st, 5)
		raw(t, st, `DELETE FROM audit_log WHERE seq <= 2`)
		if res := verify(t, st); res.OK || *res.BrokenAt != 3 {
			t.Fatalf("fehlender Anfang nicht erkannt: %+v", res)
		}
	})
}

func TestPruneKeepsChainVerifiable(t *testing.T) {
	st := testutil.Store(t)
	ctx := context.Background()
	appendN(t, st, 4)
	time.Sleep(15 * time.Millisecond)
	cut := time.Now()
	time.Sleep(15 * time.Millisecond)
	appendN(t, st, 3)

	var deleted int64
	err := st.Write(ctx, func(q *dbq.Queries) (err error) {
		deleted, _, _, err = audit.Prune(ctx, q, cut, audit.Entry{RequestID: "r", ActorType: "local", ActorID: "uid=0"})
		return err
	})
	if err != nil || deleted != 4 {
		t.Fatalf("Prune = %d, %v", deleted, err)
	}
	res := verify(t, st)
	if !res.OK || res.Entries != 4 || res.FirstSeq != 5 { // 3 alte + der prune-Eintrag
		t.Fatalf("Kette nach prune: %+v", res)
	}
	// Ohne den prune-Eintrag ist der fehlende Anfang nicht mehr gedeckt.
	raw(t, st, `DELETE FROM audit_log WHERE action = 'audit.prune'`)
	if res := verify(t, st); res.OK {
		t.Fatalf("entfernter prune-Eintrag nicht erkannt: %+v", res)
	}
}

func TestRedact(t *testing.T) {
	in := map[string]any{
		"name": "home", "psk": "c2VjcmV0", "nested": map[string]any{"private_key": "abc", "key_pem": "-----BEGIN", "port": 51820},
		"list": []any{map[string]any{"token_secret": "x"}}, "key_enc": "blob", "empty_secret": map[string]any{"secret": ""},
	}
	out := audit.Redact(in)
	if out == nil {
		t.Fatal("Redact lieferte nil")
	}
	for _, leak := range []string{"c2VjcmV0", `"abc"`, "-----BEGIN", `"x"`, `"blob"`} {
		if strings.Contains(*out, leak) {
			t.Errorf("Geheimnis %q steht im Audit-JSON: %s", leak, *out)
		}
	}
	for _, keep := range []string{`"name":"home"`, `"port":51820`, "[redacted:sha256:"} {
		if !strings.Contains(*out, keep) {
			t.Errorf("%q fehlt: %s", keep, *out)
		}
	}
	// Gleicher Wert -> gleicher Kurz-Hash, anderer Wert -> anderer.
	a, b, c := audit.Redact(map[string]any{"psk": "one"}), audit.Redact(map[string]any{"psk": "one"}), audit.Redact(map[string]any{"psk": "two"})
	if *a != *b || *a == *c {
		t.Errorf("Kurz-Hash nicht stabil/unterscheidbar: %s %s %s", *a, *b, *c)
	}
	if audit.Redact(nil) != nil {
		t.Error("Redact(nil) sollte nil sein")
	}
}
