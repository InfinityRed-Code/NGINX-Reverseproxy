// Package store kapselt SQLite: eine Schreibverbindung, ein Lese-Pool,
// Migrationen (goose, eingebettet) und die sqlc-generierten Queries.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	ErrNotFound = sql.ErrNoRows
	// ErrLocked: ein anderer Prozess (nrpd oder Offline-CLI) haelt die Sperre.
	ErrLocked = errors.New("Datenbank ist gesperrt: der NRP-Dienst laeuft")
)

const TimeFormat = "2006-01-02T15:04:05.000Z07:00"

// Now liefert den aktuellen Zeitpunkt als RFC-3339-Text (UTC, Millisekunden).
func Now() string { return FormatTime(time.Now()) }

func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

func ParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

type Store struct {
	w    *sql.DB
	r    *sql.DB
	path string
}

func dsn(path string, write bool) string {
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "synchronous(NORMAL)", "foreign_keys(ON)", "busy_timeout(5000)"} {
		q.Add("_pragma", p)
	}
	if write {
		q.Set("_txlock", "immediate")
	}
	return "file:" + filepath.ToSlash(path) + "?" + q.Encode()
}

// Open oeffnet (und erzeugt) die Datenbank. Migrationen laufen separat ueber Migrate.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	w, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	if err := w.Ping(); err != nil {
		w.Close()
		return nil, fmt.Errorf("SQLite %s: %w", path, err)
	}
	r, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(8)
	return &Store{w: w, r: r, path: path}, nil
}

func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

func (s *Store) Path() string { return s.path }

func (s *Store) provider() (*goose.Provider, error) {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectSQLite3, s.w, sub)
}

// Migrate bringt das Schema auf den aktuellen Stand.
func (s *Store) Migrate(ctx context.Context) error {
	p, err := s.provider()
	if err != nil {
		return err
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("Migration fehlgeschlagen: %w", err)
	}
	return nil
}

// MigrateDown rollt alle Migrationen zurueck (nur fuer Tests).
func (s *Store) MigrateDown(ctx context.Context) error {
	p, err := s.provider()
	if err != nil {
		return err
	}
	_, err = p.DownTo(ctx, 0)
	return err
}

// SchemaVersion liefert die aktuelle und die erwartete Schemaversion.
func (s *Store) SchemaVersion(ctx context.Context) (current, target int64, err error) {
	p, err := s.provider()
	if err != nil {
		return 0, 0, err
	}
	return p.GetVersions(ctx)
}

// Read liefert Queries auf dem Lese-Pool.
func (s *Store) Read() *dbq.Queries { return dbq.New(s.r) }

// Write fuehrt fn in einer Schreibtransaktion (BEGIN IMMEDIATE) aus. In fn
// duerfen keine Netzwerkaufrufe stehen.
func (s *Store) Write(ctx context.Context, fn func(q *dbq.Queries) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(dbq.New(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Backup schreibt eine konsistente Kopie per VACUUM INTO.
func (s *Store) Backup(ctx context.Context, dest string) error {
	if strings.ContainsAny(dest, "'\x00") {
		return errors.New("ungueltiger Backup-Pfad")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("Backup-Datei %s existiert bereits", dest)
	}
	_, err := s.r.ExecContext(ctx, "VACUUM INTO '"+filepath.ToSlash(dest)+"'")
	return err
}

// IntegrityCheck fuehrt PRAGMA quick_check aus.
func (s *Store) IntegrityCheck(ctx context.Context) error {
	var res string
	if err := s.r.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("quick_check: %s", res)
	}
	return nil
}

// LoadSettings liest die globalen Defaults; fehlende Schluessel behalten den Standardwert.
func LoadSettings(ctx context.Context, q *dbq.Queries) (domain.Settings, error) {
	st := domain.DefaultSettings()
	rows, err := q.ListSettings(ctx)
	if err != nil {
		return st, err
	}
	for _, r := range rows {
		var dst any
		switch r.Key {
		case domain.KeyClientMaxBodySize:
			dst = &st.ClientMaxBodySize
		case domain.KeyHSTS:
			dst = &st.HSTS
		case domain.KeyWAFMode:
			dst = &st.WAFMode
		case domain.KeyWAFOverrides:
			dst = &st.WAFOverrides
		case domain.KeyACMEEmail:
			dst = &st.ACMEEmail
		default:
			continue
		}
		if err := json.Unmarshal([]byte(r.Value), dst); err != nil {
			return st, fmt.Errorf("settings[%s]: %w", r.Key, err)
		}
	}
	return st, nil
}

// SaveSetting speichert einen Wert als JSON.
func SaveSetting(ctx context.Context, q *dbq.Queries, key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return q.UpsertSetting(ctx, dbq.UpsertSettingParams{Key: key, Value: string(b), UpdatedAt: Now()})
}
