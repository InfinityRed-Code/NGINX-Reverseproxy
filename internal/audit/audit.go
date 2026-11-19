// Package audit schreibt das manipulationserkennbare Audit-Log: jeder Eintrag
// enthaelt den Hash des Vorgaengers (SHA-256(prev_hash || kanonische Zeile)).
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

const (
	Success = "success"
	Denied  = "denied"
	Failed  = "failed"

	ActorSystem = "system"
)

// Output erhaelt jeden Eintrag zusaetzlich als JSON-Zeile (Kopie ausserhalb der DB).
var (
	Output   io.Writer = os.Stdout
	outputMu sync.Mutex
)

type Entry struct {
	RequestID    string
	ActorType    string
	ActorID      string
	Fingerprint  string
	SourceIP     string
	Action       string
	ResourceType string
	ResourceID   string
	Before       any
	After        any
	Result       string
	Error        string
}

// canonical ist die gehashte Darstellung; die Feldreihenfolge ist Teil des Formats.
type canonical struct {
	Ts           string  `json:"ts"`
	RequestID    string  `json:"request_id"`
	ActorType    string  `json:"actor_type"`
	ActorID      string  `json:"actor_id"`
	Fingerprint  *string `json:"actor_fingerprint"`
	SourceIP     *string `json:"source_ip"`
	Action       string  `json:"action"`
	ResourceType string  `json:"resource_type"`
	ResourceID   *string `json:"resource_id"`
	Before       *string `json:"before_json"`
	After        *string `json:"after_json"`
	Result       string  `json:"result"`
	Error        *string `json:"error"`
}

func chainHash(prev []byte, c canonical) []byte {
	b, _ := json.Marshal(c)
	h := sha256.New()
	h.Write(prev)
	h.Write(b)
	return h.Sum(nil)
}

func canonOf(r dbq.AuditLog) canonical {
	return canonical{r.Ts, r.RequestID, r.ActorType, r.ActorID, r.ActorFingerprint, r.SourceIp, r.Action,
		r.ResourceType, r.ResourceID, r.BeforeJson, r.AfterJson, r.Result, r.Error}
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var genesis = make([]byte, sha256.Size)

// Append schreibt einen Eintrag innerhalb der Transaktion von q.
func Append(ctx context.Context, q *dbq.Queries, e Entry) (dbq.AuditLog, error) {
	prev := genesis
	last, err := q.LastAuditEntry(ctx)
	if err == nil {
		prev = last.Hash
	} else if !errors.Is(err, sql.ErrNoRows) {
		return dbq.AuditLog{}, err
	}
	if e.Result == "" {
		e.Result = Success
	}
	row := dbq.AuditLog{
		Ts: store.Now(), RequestID: e.RequestID, ActorType: e.ActorType, ActorID: e.ActorID,
		ActorFingerprint: opt(e.Fingerprint), SourceIp: opt(e.SourceIP), Action: e.Action,
		ResourceType: e.ResourceType, ResourceID: opt(e.ResourceID),
		BeforeJson: Redact(e.Before), AfterJson: Redact(e.After),
		Result: e.Result, Error: opt(e.Error), PrevHash: prev,
	}
	row.Hash = chainHash(prev, canonOf(row))
	row.Seq, err = q.InsertAudit(ctx, dbq.InsertAuditParams{
		Ts: row.Ts, RequestID: row.RequestID, ActorType: row.ActorType, ActorID: row.ActorID,
		ActorFingerprint: row.ActorFingerprint, SourceIp: row.SourceIp, Action: row.Action,
		ResourceType: row.ResourceType, ResourceID: row.ResourceID, BeforeJson: row.BeforeJson,
		AfterJson: row.AfterJson, Result: row.Result, Error: row.Error, PrevHash: row.PrevHash, Hash: row.Hash,
	})
	return row, err
}

// Emit schreibt die Eintraege als JSON-Zeilen nach Output (nach dem Commit aufrufen).
func Emit(rows ...dbq.AuditLog) {
	outputMu.Lock()
	defer outputMu.Unlock()
	for _, r := range rows {
		line := map[string]any{
			"level": "INFO", "msg": "audit", "time": r.Ts, "seq": r.Seq, "request_id": r.RequestID,
			"actor_type": r.ActorType, "actor_id": r.ActorID, "action": r.Action,
			"resource_type": r.ResourceType, "result": r.Result, "hash": hex.EncodeToString(r.Hash),
		}
		for k, v := range map[string]*string{"actor_fingerprint": r.ActorFingerprint, "source_ip": r.SourceIp,
			"resource_id": r.ResourceID, "error": r.Error} {
			if v != nil {
				line[k] = *v
			}
		}
		for k, v := range map[string]*string{"before": r.BeforeJson, "after": r.AfterJson} {
			if v != nil {
				line[k] = json.RawMessage(*v)
			}
		}
		b, _ := json.Marshal(line)
		_, _ = Output.Write(append(b, '\n'))
	}
}

// System schreibt einen Eintrag fuer eine automatische Aktion in eigener Transaktion.
func System(ctx context.Context, st *store.Store, e Entry) {
	e.ActorType, e.ActorID = ActorSystem, "nrpd"
	if e.RequestID == "" {
		e.RequestID = "system"
	}
	var row dbq.AuditLog
	err := st.Write(ctx, func(q *dbq.Queries) (err error) {
		row, err = Append(ctx, q, e)
		return err
	})
	if err == nil {
		Emit(row)
	}
}

// ── Redigierung ─────────────────────────────────────────────────────────────

var sensitiveKeys = []string{"private_key", "key_pem", "psk", "preshared_key", "secret", "password", "token"}

func sensitive(key string) bool {
	k := strings.ToLower(key)
	if strings.HasSuffix(k, "_enc") {
		return true
	}
	for _, s := range sensitiveKeys {
		if k == s || strings.HasSuffix(k, "_"+s) {
			return true
		}
	}
	return false
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sensitive(k) && val != nil && val != "" {
				raw, _ := json.Marshal(val)
				if s, ok := val.(string); ok {
					raw = []byte(s)
				}
				sum := sha256.Sum256(raw)
				t[k] = "[redacted:sha256:" + hex.EncodeToString(sum[:4]) + "]"
			} else {
				t[k] = redactValue(val)
			}
		}
	case []any:
		for i := range t {
			t[i] = redactValue(t[i])
		}
	}
	return v
}

// Redact serialisiert v als JSON und ersetzt Geheimnisse durch einen Kurz-Hash,
// der noch erkennen laesst, ob sich ein Wert geaendert hat.
func Redact(v any) *string {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil
	}
	out, _ := json.Marshal(redactValue(generic))
	s := string(out)
	return &s
}

// ── Verifikation und Aufbewahrung ───────────────────────────────────────────

type VerifyResult struct {
	OK       bool
	Entries  int64
	FirstSeq int64
	LastSeq  int64
	BrokenAt *int64
	Error    string
}

// Verify prueft die Hash-Kette. Beginnt die Kette nicht beim Ursprung, muss ein
// audit.prune-Eintrag den Hash des letzten geloeschten Eintrags als Anker nennen.
func Verify(ctx context.Context, q *dbq.Queries) (VerifyResult, error) {
	res := VerifyResult{OK: true}
	var prev []byte
	var cursor int64
	fail := func(seq int64, msg string) (VerifyResult, error) {
		res.OK, res.BrokenAt, res.Error = false, &seq, msg
		return res, nil
	}
	for {
		rows, err := q.ListAuditAsc(ctx, dbq.ListAuditAscParams{Seq: cursor, Limit: 1000})
		if err != nil {
			return res, err
		}
		if len(rows) == 0 {
			return res, nil
		}
		for _, r := range rows {
			if prev == nil {
				res.FirstSeq = r.Seq
				if !bytes.Equal(r.PrevHash, genesis) {
					anchor := hex.EncodeToString(r.PrevHash)
					n, err := q.FindPruneAnchor(ctx, &anchor)
					if err != nil {
						return res, err
					}
					if n == 0 {
						return fail(r.Seq, "Anfang der Kette fehlt und ist durch keinen audit.prune-Eintrag gedeckt")
					}
				}
			} else if !bytes.Equal(r.PrevHash, prev) {
				return fail(r.Seq, "prev_hash passt nicht zum Vorgaenger (Eintrag geloescht oder eingefuegt)")
			}
			if !bytes.Equal(chainHash(r.PrevHash, canonOf(r)), r.Hash) {
				return fail(r.Seq, "Hash passt nicht zum Inhalt (Eintrag veraendert)")
			}
			prev, cursor = r.Hash, r.Seq
			res.Entries++
			res.LastSeq = r.Seq
		}
	}
}

// Prune loescht Eintraege vor before und protokolliert das selbst, mit dem Hash
// des letzten geloeschten Eintrags als Anker.
func Prune(ctx context.Context, q *dbq.Queries, before time.Time, actor Entry) (deleted int64, anchor string, row dbq.AuditLog, err error) {
	last, err := q.LastAuditBefore(ctx, store.FormatTime(before))
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", row, nil
	}
	if err != nil {
		return 0, "", row, err
	}
	anchor = hex.EncodeToString(last.Hash)
	actor.Action, actor.ResourceType, actor.ResourceID, actor.Result = "audit.prune", "audit", anchor, Success
	actor.After = map[string]any{"before": store.FormatTime(before), "last_deleted_seq": last.Seq, "anchor_hash": anchor}
	// Erst protokollieren (haengt noch an der vollstaendigen Kette), dann loeschen.
	if row, err = Append(ctx, q, actor); err != nil {
		return 0, "", row, err
	}
	deleted, err = q.DeleteAuditUpTo(ctx, last.Seq)
	if err != nil {
		return 0, "", row, fmt.Errorf("audit prune: %w", err)
	}
	return deleted, anchor, row, nil
}
