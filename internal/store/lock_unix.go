//go:build unix

package store

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// AcquireLock nimmt einen exklusiven, nicht blockierenden flock auf path.
// nrpd haelt ihn dauerhaft, der Offline-Modus der CLI fuer die Dauer des Befehls.
func AcquireLock(path string) (release func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
