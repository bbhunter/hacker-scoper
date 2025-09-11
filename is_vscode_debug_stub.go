//go:build !vscode_debug

package main

// isVSCodeDebug is a stub that always reports “not debugging”.
// It is compiled when the “vscode_debug” tag is NOT present, i.e. for production builds.
func isVSCodeDebug() bool { return false }
