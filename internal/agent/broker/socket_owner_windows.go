//go:build windows

package broker

import "os"

// adminDirSuffix has no uid concept on Windows: a single fixed private dir
// name; ensurePrivateDir still enforces directory identity before binding.
func adminDirSuffix() string { return "admin" }

// checkSocketOwner has no uid concept on Windows: the private admin dir and
// the owned-socket-type check still apply; ownership is not verifiable here.
func checkSocketOwner(fi os.FileInfo) error { return nil }
