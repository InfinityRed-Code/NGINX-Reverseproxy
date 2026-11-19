//go:build linux

package auth

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID liefert die UID der Gegenstelle eines Unix-Sockets (SO_PEERCRED).
func PeerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("keine Unix-Socket-Verbindung")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}
