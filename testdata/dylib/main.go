package main

/*
#include <stdint.h>
*/
import "C"

import (
	"os"
)

const markerPath = "/tmp/beignet_test_marker"

//export StartW
func StartW() {
	_ = os.WriteFile(markerPath, []byte("ok"), 0o600)
}

//export BeignetEntry
func BeignetEntry() {
	StartW()
}

func main() {}
