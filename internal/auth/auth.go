// Package auth beschreibt Identitaeten, Rollen und API-Tokens.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"math/big"
	"strings"
)

type Role string

const (
	Viewer   Role = "viewer"
	Operator Role = "operator"
	Admin    Role = "admin"
)

var rank = map[Role]int{Viewer: 1, Operator: 2, Admin: 3}

func ValidRole(r string) bool { return rank[Role(r)] > 0 }

// Allows prueft, ob die Rolle mindestens min entspricht.
func (r Role) Allows(min Role) bool { return rank[r] > 0 && rank[min] > 0 && rank[r] >= rank[min] }

const (
	TypeMTLS    = "mtls"
	TypeToken   = "token"
	TypeLocal   = "local"
	TypeOffline = "offline"
)

type Identity struct {
	Type        string
	ID          string
	Role        Role
	Fingerprint string
}

// IsLocal: Zugriff ueber den Unix-Socket oder im Offline-Modus (docker exec).
func (i Identity) IsLocal() bool { return i.Type == TypeLocal || i.Type == TypeOffline }

// Actor ist die Darstellung in created_by-Spalten.
func (i Identity) Actor() string { return i.Type + ":" + i.ID }

type ctxKey int

const (
	identityKey ctxKey = iota
	tokenListenerKey
)

func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey).(Identity)
	return id, ok
}

// WithTokenListener markiert Verbindungen des Token-Listeners (TLS ohne Client-Zertifikat).
func WithTokenListener(ctx context.Context) context.Context {
	return context.WithValue(ctx, tokenListenerKey, true)
}

func IsTokenListener(ctx context.Context) bool {
	v, _ := ctx.Value(tokenListenerKey).(bool)
	return v
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func encodeBase62(b []byte) string {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(62)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, base62[mod.Int64()])
	}
	for len(out) < 43 { // 32 Byte ergeben hoechstens 43 Zeichen
		out = append(out, '0')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// NewToken erzeugt ein Token im Format nrp_<id>_<secret>. Gespeichert wird nur
// SHA-256(secret): ein 256-Bit-Zufallswert braucht keinen langsamen Hash.
func NewToken(id string) (full string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret := encodeBase62(raw)
	sum := sha256.Sum256([]byte(secret))
	return "nrp_" + id + "_" + secret, sum[:], nil
}

// ParseToken zerlegt ein Token in ID und Secret.
func ParseToken(s string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(s, "nrp_")
	if !found {
		return "", "", false
	}
	id, secret, ok = strings.Cut(rest, "_")
	return id, secret, ok && id != "" && secret != ""
}

// TokenMatches vergleicht in konstanter Zeit.
func TokenMatches(secret string, hash []byte) bool {
	sum := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(sum[:], hash) == 1
}
