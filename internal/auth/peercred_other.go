//go:build !linux

package auth

import "net"

// PeerUID: ohne SO_PEERCRED (nur Entwicklungssysteme) schuetzt allein der
// Dateimodus 0600 des Sockets; die Gegenstelle gilt als dessen Eigentuemer.
func PeerUID(net.Conn) (uint32, error) { return 0, nil }
