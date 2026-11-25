//go:build !windows

package main

const wfpSupported = false

type noopWFPBackend struct{}

func defaultWFPBackend() wfpBackend { return &noopWFPBackend{} }

func (b *noopWFPBackend) Apply(exePath string, strict bool) error { return nil }
func (b *noopWFPBackend) Clear() error                            { return nil }
