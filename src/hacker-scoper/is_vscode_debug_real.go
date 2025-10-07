//go:build vscode_debug

package main

import "os"

// isVSCodeDebug reports whether the process is running under VS Code’s debugger.
// This file is compiled only when the “vscode_debug” build tag is present.
func isVSCodeDebug() bool {
	// You can also check for any other marker you set in the launch config.
	return os.Getenv("VSCODE_DEBUG") == "true"
}
