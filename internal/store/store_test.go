package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/testutil"
)

func insertHost(ctx context.Context, q *dbq.Queries, fqdn string) error {
	now := store.Now()
	return q.InsertHost(ctx, dbq.InsertHostParams{Fqdn: fqdn, UpstreamScheme: "http", UpstreamAddress: "10.0.0.1",
		UpstreamPort: 8080, ExternalPort: 443, Status: domain.HostPending, CreatedAt: now, UpdatedAt: now})
}

func TestMigrationsUpDownUp(t *testing.T) {
	ctx := context.Background()
	st := testutil.Store(t)
	cur, target, err := st.SchemaVersion(ctx)
	if err != nil || cur != target || cur == 0 {
		t.Fatalf("Schema %d/%d, %v", cur, target, err)
	}
	if err := st.MigrateDown(ctx); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := st.Read().ListHosts(ctx); err == nil {
		t.Fatal("nach down sollte die Tabelle hosts fehlen")
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("erneutes up: %v", err)
	}
	if err := st.IntegrityCheck(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestOptimisticLocking(t *testing.T) {
	ctx := context.Background()
	st := testutil.Store(t)
	if err := st.Write(ctx, func(q *dbq.Queries) error { return insertHost(ctx, q, "a.example.com") }); err != nil {
		t.Fatal(err)
	}
	update := func(version int64) int64 {
		var n int64
		err := st.Write(ctx, func(q *dbq.Queries) (err error) {
			n, err = q.UpdateHost(ctx, dbq.UpdateHostParams{UpstreamScheme: "https", UpstreamAddress: "10.0.0.2", UpstreamPort: 443,
				ExternalPort: 443, Status: domain.HostPending, UpdatedAt: store.Now(), Fqdn: "a.example.com", Version: version})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if update(1) != 1 {
		t.Fatal("Update mit aktueller Version sollte greifen")
	}
	if update(1) != 0 {
		t.Fatal("Update mit veralteter Version darf nicht greifen")
	}
	h, _ := st.Read().GetHost(ctx, "a.example.com")
	if h.Version != 2 || h.UpstreamScheme != "https" {
		t.Fatalf("Host nach Update: %+v", h)
	}
}

func TestConstraintsAndRollback(t *testing.T) {
	ctx := context.Background()
	st := testutil.Store(t)
	boom := errors.New("boom")
	err := st.Write(ctx, func(q *dbq.Queries) error {
		if err := insertHost(ctx, q, "rollback.example.com"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("erwartet boom, erhalten %v", err)
	}
	if _, err := st.Read().GetHost(ctx, "rollback.example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Rollback hat nicht gegriffen: %v", err)
	}
	// Fremdschluessel: Host an nicht existierender Site
	missing := "nope"
	err = st.Write(ctx, func(q *dbq.Queries) error {
		now := store.Now()
		return q.InsertHost(ctx, dbq.InsertHostParams{Fqdn: "fk.example.com", UpstreamScheme: "http", UpstreamAddress: "10.0.0.1",
			UpstreamPort: 80, SiteName: &missing, ExternalPort: 443, Status: domain.HostPending, CreatedAt: now, UpdatedAt: now})
	})
	if err == nil {
		t.Fatal("foreign_keys=ON sollte den Insert ablehnen")
	}
	// CHECK-Constraint
	err = st.Write(ctx, func(q *dbq.Queries) error {
		now := store.Now()
		return q.InsertHost(ctx, dbq.InsertHostParams{Fqdn: "chk.example.com", UpstreamScheme: "ftp", UpstreamAddress: "10.0.0.1",
			UpstreamPort: 80, ExternalPort: 443, Status: domain.HostPending, CreatedAt: now, UpdatedAt: now})
	})
	if err == nil {
		t.Fatal("CHECK auf upstream_scheme sollte greifen")
	}
}

// Parallele Schreiber und Leser: die eine Schreibverbindung serialisiert, WAL
// erlaubt Lesen waehrend des Schreibens. Laeuft in CI mit -race.
func TestParallelWriters(t *testing.T) {
	ctx := context.Background()
	st := testutil.Store(t)
	const writers, perWriter = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, writers*2)
	for w := 0; w < writers; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				err := st.Write(ctx, func(q *dbq.Queries) error {
					return store.SaveSetting(ctx, q, domain.KeyClientMaxBodySize, "100M")
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if _, err := store.LoadSettings(ctx, st.Read()); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	row, err := st.Read().GetSetting(ctx, domain.KeyClientMaxBodySize)
	if err != nil || row.Version != writers*perWriter {
		t.Fatalf("Version %d, erwartet %d (%v)", row.Version, writers*perWriter, err)
	}
}

func TestBackupAndLock(t *testing.T) {
	ctx := context.Background()
	st := testutil.Store(t)
	if err := st.Write(ctx, func(q *dbq.Queries) error { return insertHost(ctx, q, "b.example.com") }); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := st.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	if err := st.Backup(ctx, dest); err == nil {
		t.Fatal("vorhandenes Backup darf nicht ueberschrieben werden")
	}
	cp, err := store.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	if _, err := cp.Read().GetHost(ctx, "b.example.com"); err != nil {
		t.Fatalf("Backup enthaelt den Host nicht: %v", err)
	}

	lock := filepath.Join(t.TempDir(), "nrp.lock")
	release, err := store.AcquireLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLock(lock); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("zweite Sperre: erwartet ErrLocked, erhalten %v", err)
	}
	release()
	release2, err := store.AcquireLock(lock)
	if err != nil {
		t.Fatalf("Sperre nach Freigabe: %v", err)
	}
	release2()
}
