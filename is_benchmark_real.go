//go:build benchmark

package main

import (
	"os"
	"runtime/pprof"
)

var f *os.File

func StartBenchmark() bool {
	f, err := os.Create("cpu.prof")
	if err != nil {
		crash("could not create CPU profile: ", err)
	}
	err = pprof.StartCPUProfile(f)
	if err != nil {
		crash("could not start CPU profile: ", err)
	}
	return true
}

func StopBenchmark() bool {
	pprof.StopCPUProfile()
	f.Close()
	return true
}
