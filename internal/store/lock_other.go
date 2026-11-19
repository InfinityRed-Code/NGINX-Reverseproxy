//go:build !unix

package store

import (
	"os"
	"path/filepath"
)

// AcquireLock: auf Nicht-Unix-Systemen (nur Entwicklung) per exklusiver Lock-Datei.
func AcquireLock(path string) (release func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	held := path + ".held"
	f, err := os.OpenFile(held, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() {
		_ = f.Close()
		_ = os.Remove(held)
	}, nil
}
