//go:build !linux

package wireguard

import "errors"

var errUnsupported = errors.New("WireGuard-Steuerung ist nur unter Linux verfuegbar")

type unsupported struct{}

func NewManager() Manager { return unsupported{} }

func (unsupported) Apply(Desired) error                 { return errUnsupported }
func (unsupported) Stats() (map[string]PeerStat, error) { return nil, errUnsupported }
