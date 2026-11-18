//go:build !windows

package main

import "syscall"

const tunSupported = false

func openTunDevice(a *App, mtu int, v6 bool) (tunDevice, error)  { return nil, errTunUnsupported }
func setTunAdapterMTU(dev tunDevice, mtu int, v6 bool) error     { return nil }
func ownerPID(proto string, v6 bool, port uint16) uint32         { return 0 }
func tunProcName(pid uint32) string                              { return "" }
func isElevated() bool                                           { return false }
func relaunchElevated(waitPID int) error                         { return errTunUnsupported }
func waitForPID(pid int)                                         {}
func refreshPhys() error                                         { return errTunUnsupported }
func bindPhys(network, address string, c syscall.RawConn) error  { return nil }

func flushWindowsDNSCache() {}
