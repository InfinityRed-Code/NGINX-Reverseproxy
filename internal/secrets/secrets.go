// Package secrets verschluesselt Geheimnisse fuer die Ablage in SQLite
// (XChaCha20-Poly1305). Blob-Format: Version(1) | Key-ID(4) | Nonce(24) | Ciphertext.
package secrets

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	blobVersion = 1
	headerLen   = 1 + 4
)

var ErrWrongKey = errors.New("secrets: Blob wurde mit einem anderen Master-Key verschluesselt")

type Box struct {
	aead  cipher.AEAD
	keyID [4]byte
}

// New erzeugt eine Box aus einem 32-Byte-Schluessel.
func New(key []byte) (*Box, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("secrets: Master-Key muss %d Byte lang sein, ist %d", chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("nrp-key-id:"), key...))
	b := &Box{aead: aead}
	copy(b.keyID[:], sum[:4])
	return b, nil
}

// Load liest den Master-Key: 32 rohe Bytes, oder hex/base64-kodiert (mit Zeilenumbruch).
func Load(path string) (*Box, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Master-Key %s nicht lesbar: %w (erzeugen: head -c 32 /dev/urandom > secrets/master.key)", path, err)
	}
	if len(raw) == chacha20poly1305.KeySize {
		return New(raw)
	}
	text := string(bytes.TrimSpace(raw))
	if k, err := hex.DecodeString(text); err == nil && len(k) == chacha20poly1305.KeySize {
		return New(k)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(text); err == nil && len(k) == chacha20poly1305.KeySize {
			return New(k)
		}
	}
	return nil, fmt.Errorf("Master-Key %s: erwartet 32 Byte (roh, hex oder base64), gefunden %d Byte", path, len(raw))
}

func (b *Box) KeyID() string { return hex.EncodeToString(b.keyID[:]) }

func (b *Box) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerLen+len(nonce)+len(plain)+b.aead.Overhead())
	out = append(out, blobVersion)
	out = append(out, b.keyID[:]...)
	out = append(out, nonce...)
	return b.aead.Seal(out, nonce, plain, out[:headerLen]), nil
}

func (b *Box) Open(blob []byte) ([]byte, error) {
	ns := b.aead.NonceSize()
	if len(blob) < headerLen+ns+b.aead.Overhead() || blob[0] != blobVersion {
		return nil, errors.New("secrets: ungueltiges Blob-Format")
	}
	if !bytes.Equal(blob[1:headerLen], b.keyID[:]) {
		return nil, ErrWrongKey
	}
	return b.aead.Open(nil, blob[headerLen:headerLen+ns], blob[headerLen+ns:], blob[:headerLen])
}
