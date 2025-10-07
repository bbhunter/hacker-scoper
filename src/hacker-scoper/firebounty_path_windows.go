//go:build windows
package main

import "os"

func getFirebountyJSONPath() string {
    return os.Getenv("APPDATA") + "\\hacker-scoper\\"
}