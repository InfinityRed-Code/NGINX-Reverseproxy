package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSealOpen(t *testing.T) {
	box, err := New(key(1))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("wireguard-private-key")
	a, _ := box.Seal(plain)
	b, _ := box.Seal(plain)
	if bytes.Equal(a, b) || bytes.Contains(a, plain) {
		t.Fatal("Nonce muss zufaellig sein und der Klartext darf nicht im Blob stehen")
	}
	got, err := box.Open(a)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	// Manipulation an Header oder Ciphertext wird erkannt.
	for _, i := range []int{0, 6, len(a) - 1} {
		tampered := append([]byte{}, a...)
		tampered[i] ^= 0x01
		if _, err := box.Open(tampered); err == nil {
			t.Errorf("Manipulation an Byte %d nicht erkannt", i)
		}
	}
	other, _ := New(key(2))
	if _, err := other.Open(a); !errors.Is(err, ErrWrongKey) {
		t.Errorf("fremder Schluessel: %v, erwartet ErrWrongKey", err)
	}
	if box.KeyID() == other.KeyID() || len(box.KeyID()) != 8 {
		t.Error("Key-ID muss den Schluessel unterscheiden")
	}
	if _, err := New([]byte("zu kurz")); err == nil {
		t.Error("kurzer Schluessel muss abgelehnt werden")
	}
	if _, err := box.Open([]byte{1, 2, 3}); err == nil {
		t.Error("zu kurzes Blob muss abgelehnt werden")
	}
}

func TestLoadFormats(t *testing.T) {
	dir := t.TempDir()
	k := key(7)
	want, _ := New(k)
	for name, content := range map[string][]byte{
		"raw":    k,
		"hex":    []byte(hex.EncodeToString(k) + "\n"),
		"base64": []byte(base64.StdEncoding.EncodeToString(k) + "\n"),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		box, err := Load(p)
		if err != nil || box.KeyID() != want.KeyID() {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("kein schluessel"), 0o600)
	if _, err := Load(bad); err == nil {
		t.Error("ungueltige Datei muss abgelehnt werden")
	}
	if _, err := Load(filepath.Join(dir, "missing")); err == nil {
		t.Error("fehlende Datei muss ein Fehler sein")
	}
}
